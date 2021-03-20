#include "h2d_main.h"

#define X(lb) extern struct h2d_upstream_loadbalance lb;
H2D_UPSTREAM_LOADBALANCE_X_LIST
#undef X
static struct h2d_upstream_loadbalance *h2d_upstream_loadbalances[H2D_UPSTREAM_LOADBALANCE_MAX] =
{
	#define X(lb) &lb,
	H2D_UPSTREAM_LOADBALANCE_X_LIST
	#undef X
};

static WUY_LIST(h2d_upstream_list);

static int h2d_upstream_loadbalance_number = H2D_UPSTREAM_LOADBALANCE_STATIC_NUMBER;

#define _log(level, fmt, ...) h2d_request_log_at(r, \
		upstream->log, level, "upstream: " fmt, ##__VA_ARGS__)

#define _log_upc(level, fmt, ...) h2d_request_log_at(upc->request, \
		upc->address->upstream->log, level, "upstream: " fmt, ##__VA_ARGS__)

static void h2d_upstream_connection_close(struct h2d_upstream_connection *upc)
{
	loop_stream_close(upc->loop_stream);

	wuy_list_delete(&upc->list_node);

	if (upc->request == NULL) {
		upc->address->idle_num--;
	}

	free(upc->preread_buf);
	free(upc);
}

static void h2d_upstream_on_active(loop_stream_t *s)
{
	/* Explicit handshake is not required here because the following
	 * routine will call SSL_read/SSL_write to do the handshake.
	 * We handshake here just to avoid calling the following
	 * routine during handshake for performence. So we handle
	 * H2D_AGAIN only, but not H2D_ERROR. */
	if (h2d_ssl_stream_handshake(s) == H2D_AGAIN) {
		return;
	}

	struct h2d_upstream_connection *upc = loop_stream_get_app_data(s);
	if (upc->request != NULL) {
		h2d_request_active(upc->request, "upstream ready");
	} else { /* idle */
		h2d_upstream_connection_close(upc);
	}
}
static void h2d_upstream_on_close(loop_stream_t *s, enum loop_stream_close_reason r)
{
	if (r == LOOP_STREAM_TIMEOUT) {
		h2d_upstream_on_active(s);
	}
}
static loop_stream_ops_t h2d_upstream_ops = {
	.on_readable = h2d_upstream_on_active,
	.on_writable = h2d_upstream_on_active,
	.on_close = h2d_upstream_on_close,
	H2D_SSL_LOOP_STREAM_UNDERLYINGS,
};

struct h2d_upstream_connection *
h2d_upstream_get_connection(struct h2d_upstream_conf *upstream, struct h2d_request *r)
{
	/* check if dynamic */
	while (h2d_dynamic_is_enabled(&upstream->dynamic)) {
		h2d_request_log(r, H2D_LOG_DEBUG, "dynamic get");
		upstream = h2d_dynamic_get(&upstream->dynamic, r);
		if (!H2D_PTR_IS_OK(upstream)) {
			return (void *)upstream;
		}
	}

	if (upstream->address_num == 0) { /* only if dynamic upstream */
		if (!wuy_list_node_linked(&r->list_node)) {
			_log(H2D_LOG_DEBUG, "dynamic wait for resolving");
			wuy_list_append(&upstream->wait_head, &r->list_node);
		}
		return H2D_PTR_AGAIN;
	}

	/* pick an address */
	struct h2d_upstream_address *address = upstream->loadbalance->pick(upstream, r);
	if (address == NULL) {
		_log(H2D_LOG_ERROR, "pick fail");
		atomic_fetch_add(&upstream->stats->pick_fail, 1);
		return H2D_PTR_ERROR;
	}

	if (!h2d_upstream_address_is_pickable(address, r)) {
		_log(H2D_LOG_ERROR, "all down");

		struct h2d_upstream_address *iaddr;
		wuy_list_iter_type(&upstream->address_head, iaddr, upstream_node) {
			// XXX iaddr->down_time = 0;
		}
	}

	atomic_fetch_add(&address->stats->pick, 1);

	/* try to reuse an idle one */
	struct h2d_upstream_connection *upc;
	if (wuy_list_pop_type(&address->idle_head, upc, list_node)) {
		_log(H2D_LOG_DEBUG, "reuse %s", address->name);
		wuy_list_append(&address->active_head, &upc->list_node);
		address->idle_num--;
		atomic_fetch_add(&address->stats->reuse, 1);
		upc->request = r;
		return upc;
	}

	_log(H2D_LOG_DEBUG, "connect %s", address->name);

	/* new connection */
	loop_stream_t *s = loop_tcp_connect_sockaddr(h2d_loop, &address->sockaddr.s,
			&h2d_upstream_ops);
	if (s == NULL) {
		return H2D_PTR_ERROR;
	}
	loop_stream_set_timeout(s, upstream->send_timeout * 1000);

	if (upstream->ssl_enable) {
		h2d_ssl_stream_set(s, upstream->ssl_ctx, false);
	}

	upc = calloc(1, sizeof(struct h2d_upstream_connection));
	upc->address = address;
	upc->loop_stream = s;
	wuy_list_append(&address->active_head, &upc->list_node);
	loop_stream_set_app_data(s, upc);
	upc->create_time = wuy_time_ms();

	upc->request = r;
	return upc;
}

/* close @old connection and return a new one */
struct h2d_upstream_connection *
h2d_upstream_retry_connection(struct h2d_upstream_connection *old)
{
	struct h2d_request *r = old->request;
	struct h2d_upstream_address *address = old->address;
	struct h2d_upstream_conf *upstream = address->upstream;

	_log(H2D_LOG_DEBUG, "retry for %s", address->name);

	atomic_fetch_add(&upstream->stats->retry, 1);

	h2d_upstream_release_connection(old);

	/* mark this down temporarily to avoid picked again */
	if (address->healthcheck.down_time == 0) {
		address->healthcheck.down_time = 1;
	}

	/* pick a new connection */
	struct h2d_upstream_connection *newc = h2d_upstream_get_connection(upstream, r);

	/* recover */
	if (address->healthcheck.down_time == 1) {
		address->healthcheck.down_time = 0;
	}

	return newc;
}

void h2d_upstream_release_connection(struct h2d_upstream_connection *upc)
{
	assert(upc->request != NULL);
	assert(upc->loop_stream != NULL);

	struct h2d_request *r = upc->request;
	struct h2d_upstream_address *address = upc->address;
	struct h2d_upstream_conf *upstream = address->upstream;

	_log(H2D_LOG_DEBUG, "release %s%s", address->name, upc->error ? " in error" : "");

	if (!upc->error) {
		address->failure.fails = 0;
		address->failure.passes++;
		if (address->failure.down_time != 0 && address->failure.passes == upstream->failure.passes) {
			_log(H2D_LOG_ERROR, "go up");
			address->failure.down_time = 0;
		}
	} else {
		address->failure.passes = 0;
		address->failure.fails++;
		if (address->failure.down_time == 0 && address->failure.fails == upstream->failure.fails) {
			_log(H2D_LOG_ERROR, "go down");
			atomic_fetch_add(&address->stats->failure_down, 1);
			address->failure.down_time = time(NULL);
		}
	}

	/* close the connection */
	if (upc->error || loop_stream_is_closed(upc->loop_stream) || r->state != H2D_REQUEST_STATE_DONE) {
		_log(H2D_LOG_DEBUG, "just close, state=%d", r->state);
		h2d_upstream_connection_close(upc);
		return;
	}

	/* put the connection into idle pool */
	_log(H2D_LOG_DEBUG, "keeplive, idles=%d", address->idle_num);

	if (address->idle_num > upstream->idle_max) {
		/* close the oldest one if pool is full */
		struct h2d_upstream_connection *idle;
		wuy_list_first_type(&address->idle_head, idle, list_node);
		assert(idle != NULL);
		h2d_upstream_connection_close(idle);
	}

	upc->request = NULL;
	address->idle_num++;
	wuy_list_delete(&upc->list_node);
	wuy_list_append(&address->idle_head, &upc->list_node);

	loop_stream_set_timeout(upc->loop_stream, upstream->idle_timeout * 1000);
}

int h2d_upstream_connection_read(struct h2d_upstream_connection *upc,
		void *buffer, int buf_len)
{
	assert(upc->loop_stream != NULL);
	uint8_t *buf_pos = buffer;

	/* upc->preread_buf was allocated in h2d_upstream_connection_read_notfinish() */
	if (upc->preread_buf != NULL) {
		_log_upc(H2D_LOG_DEBUG, "read preread %d", upc->preread_len);

		if (buf_len < upc->preread_len) {
			memcpy(buffer, upc->preread_buf, buf_len);
			upc->preread_len -= buf_len;
			memmove(upc->preread_buf, upc->preread_buf + buf_len, upc->preread_len);
			return buf_len;
		}

		memcpy(buffer, upc->preread_buf, upc->preread_len);
		buf_pos += upc->preread_len;
		buf_len -= upc->preread_len;
		free(upc->preread_buf);
		upc->preread_buf = NULL;
		upc->preread_len = 0;

		if (buf_len == 0) {
			return buf_pos - (uint8_t *)buffer;
		}
	}

	int read_len = loop_stream_read(upc->loop_stream, buf_pos, buf_len);
	if (read_len < 0) {
		_log_upc(H2D_LOG_ERROR, "read fail %d", read_len);
		return H2D_ERROR;
	}
	if (read_len > 0) { /* update timer */
		loop_stream_set_timeout(upc->loop_stream,
				upc->address->upstream->recv_timeout * 1000);
	}

	int ret_len = buf_pos - (uint8_t *)buffer + read_len;
	_log_upc(H2D_LOG_DEBUG, "read %d", ret_len);

	return ret_len == 0 ? H2D_AGAIN : ret_len;
}
void h2d_upstream_connection_read_notfinish(struct h2d_upstream_connection *upc,
		void *buffer, int buf_len)
{
	if (buf_len == 0) {
		return;
	}
	_log_upc(H2D_LOG_DEBUG, "read not finish %d", buf_len);

	assert(upc->preread_buf == NULL);
	upc->preread_buf = malloc(buf_len);
	memcpy(upc->preread_buf, buffer, buf_len);
	upc->preread_len = buf_len;
}

int h2d_upstream_connection_write(struct h2d_upstream_connection *upc,
		void *data, int data_len)
{
	assert(upc->loop_stream != NULL);

	if (upc->create_time != 0) {
		atomic_fetch_add(&upc->address->stats->connected, 1);
		atomic_fetch_add(&upc->address->stats->connect_acc_ms, wuy_time_ms() - upc->create_time);
		upc->create_time = 0;
	}

	if (loop_stream_is_write_blocked(upc->loop_stream)) {
		return H2D_AGAIN;
	}
	if (upc->prewrite_len > 0) {
		data = (char *)data + upc->prewrite_len;
		data_len -= upc->prewrite_len;
	}

	int write_len = loop_stream_write(upc->loop_stream, data, data_len);
	if (write_len < 0) {
		_log_upc(H2D_LOG_ERROR, "write fail %d", write_len);
		return H2D_ERROR;
	}
	if (write_len != data_len) {
		_log_upc(H2D_LOG_DEBUG, "write blockes %d %d", write_len, data_len);
		upc->prewrite_len = write_len;
		return H2D_AGAIN;
	}

	_log_upc(H2D_LOG_DEBUG, "write %d", write_len);
	upc->prewrite_len = 0;

	/* we assume that the response is expected just after one write */
	loop_stream_set_timeout(upc->loop_stream,
			upc->address->upstream->recv_timeout * 1000);

	return H2D_OK;
}

void h2d_upstream_dynamic_add(struct h2d_upstream_loadbalance *m)
{
	if (h2d_upstream_loadbalance_number >= H2D_UPSTREAM_LOADBALANCE_MAX) {
		fprintf(stderr, "excess dynamic upstream module limit: %d\n",
				H2D_UPSTREAM_LOADBALANCE_MAX);
		exit(H2D_EXIT_DYNAMIC);
	}
	h2d_upstream_loadbalances[h2d_upstream_loadbalance_number++] = m;
}

void h2d_upstream_init(void)
{
	for (int i = 0; i < h2d_upstream_loadbalance_number; i++) {
		struct h2d_upstream_loadbalance *lb = h2d_upstream_loadbalances[i];
		lb->index = i;
		lb->command.offset = offsetof(struct h2d_upstream_conf, lb_confs) + sizeof(void *) * i;
	}
}

bool h2d_upstream_address_is_pickable(struct h2d_upstream_address *address,
		struct h2d_request *r)
{
	struct h2d_upstream_conf *upstream = address->upstream;
	if (address->healthcheck.down_time != 0) {
		return false;
	}
	if (address->failure.down_time == 0) {
		return true;
	}
	if (time(NULL) < address->failure.down_time + upstream->failure.timeout) {
		return false;
	}
	if (!wuy_list_empty(&address->active_head)) {
		/* one connection at most in recovering */
		return false;
	}
	if (wuy_cflua_is_function_set(upstream->failure.filter)) {
		return h2d_lua_call_boolean(r, upstream->failure.filter);
	}
	return true;
}

/* configration */

static const char *h2d_upstream_conf_loadbalance_select(struct h2d_upstream_conf *conf)
{
	for (int i = 1; i < h2d_upstream_loadbalance_number; i++) {
		struct h2d_upstream_loadbalance *lb = h2d_upstream_loadbalances[i];
		if (h2d_module_command_is_set(&lb->command, conf->lb_confs[i])) {
			if (conf->loadbalance != NULL) {
				return "duplicate loadbalance";
			}
			conf->loadbalance = lb;
		}
	}

	/* default is LB:random with index=0 */
	if (conf->loadbalance == NULL) {
		conf->loadbalance = h2d_upstream_loadbalances[0];
	}

	conf->lb_ctx = conf->loadbalance->ctx_new();

	return WUY_CFLUA_OK;
}

static struct wuy_cflua_command *h2d_upstream_next_command(struct wuy_cflua_command *cmd)
{
	int index = 0;
	if (cmd->type != WUY_CFLUA_TYPE_END || cmd->u.next == NULL) {
		struct h2d_upstream_loadbalance *lb = wuy_containerof(cmd,
				struct h2d_upstream_loadbalance, command);
		index = lb->index + 1;
	}

	for (; index < h2d_upstream_loadbalance_number; index++) {
		struct wuy_cflua_command *next = &h2d_upstream_loadbalances[index]->command;
		if (next->type != WUY_CFLUA_TYPE_END) {
			return next;
		}
	}
	return NULL;
}

const char *h2d_upstream_conf_resolve_init(struct h2d_upstream_conf *conf);
static const char *h2d_upstream_conf_post(void *data)
{
	struct h2d_upstream_conf *conf = data;

	const char *lb_err = h2d_upstream_conf_loadbalance_select(conf);
	if (lb_err != WUY_CFLUA_OK) {
		return lb_err;
	}

	conf->stats = wuy_shmpool_alloc(sizeof(struct h2d_upstream_stats));

	/* dynamic */
	if (h2d_dynamic_is_enabled(&conf->dynamic)) {
		if (conf->hostnames_str != NULL) {
			return "hostname is not allowed for dynamic upstream";
		}
		conf->hostnames_str = (void *)1; /* used by h2d_module_command_is_set() */

		h2d_dynamic_set_container(&conf->dynamic, &h2d_upstream_conf_table);

		if (conf->name == NULL) {
			conf->name = "dynamic";
		}

		return WUY_CFLUA_OK;
	}

	if (conf->hostnames_str == NULL) {
		return WUY_CFLUA_OK;
	}

	wuy_list_init(&conf->wait_head);
	wuy_list_init(&conf->address_head);
	wuy_list_init(&conf->deleted_address_defer);

	if (conf->name == NULL) {
		conf->name = conf->hostnames_str[0];
	}

	if (conf->ssl_enable) {
		conf->ssl_ctx = h2d_ssl_ctx_new_client();
	}

	const char *resv_err = h2d_upstream_conf_resolve_init(conf);
	if (resv_err != WUY_CFLUA_OK) {
		return resv_err;
	}

	conf->loadbalance->update(conf);

	if (!h2d_dynamic_is_sub(&conf->dynamic)) {
		wuy_list_append(&h2d_upstream_list, &conf->list_node);
	}

	return WUY_CFLUA_OK;
}

static void h2d_upstream_conf_free(void *data)
{
	struct h2d_upstream_conf *conf = data;
	wuy_list_del_if(&conf->list_node);

	if (conf->resolve_timer != NULL) {
		loop_timer_delete(conf->resolve_timer);
	}
	if (conf->resolve_stream != NULL) {
		loop_stream_close(conf->resolve_stream);
	}

	conf->loadbalance->ctx_free(conf->lb_ctx);
}

static void h2d_upstream_conf_stats(struct h2d_upstream_conf *conf, wuy_json_t *json)
{
	wuy_json_new_object(json);

	wuy_json_object_string(json, "name", conf->name);

	struct h2d_upstream_stats *stats = conf->stats;
	wuy_json_object_int(json, "retry", atomic_load(&stats->retry));
	wuy_json_object_int(json, "pick_fail", atomic_load(&stats->pick_fail));

	wuy_json_object_array(json, "addresses"); /* addresses[] */
	struct h2d_upstream_address *address;
	wuy_list_iter_type(&conf->address_head, address, upstream_node) {
		wuy_json_array_object(json);
		wuy_json_object_string(json, "name", address->name);

		wuy_json_object_object(json, "failure");
		wuy_json_object_int(json, "down_time", address->failure.down_time);
		wuy_json_object_int(json, "fails", address->failure.fails);
		wuy_json_object_int(json, "passes", address->failure.passes);
		wuy_json_object_close(json);

		if (conf->healthcheck.interval != 0) {
			wuy_json_object_object(json, "healthcheck");
			wuy_json_object_int(json, "down_time", address->healthcheck.down_time);
			wuy_json_object_int(json, "fails", address->healthcheck.fails);
			wuy_json_object_int(json, "passes", address->healthcheck.passes);
			wuy_json_object_close(json);
		}

		struct h2d_upstream_address_stats *stats = address->stats;
		wuy_json_object_int(json, "create_time", atomic_load(&stats->create_time));
		wuy_json_object_int(json, "failure_down", atomic_load(&stats->failure_down));
		wuy_json_object_int(json, "healthcheck_down", atomic_load(&stats->healthcheck_down));
		wuy_json_object_int(json, "pick", atomic_load(&stats->pick));
		wuy_json_object_int(json, "reuse", atomic_load(&stats->reuse));
		wuy_json_object_int(json, "connected", atomic_load(&stats->connected));
		wuy_json_object_int(json, "connect_acc_ms", atomic_load(&stats->connect_acc_ms));
		wuy_json_object_close(json);
	}
	wuy_json_array_close(json); /* end of addresses[] */

	wuy_json_object_close(json);
}
void h2d_upstream_stats(wuy_json_t *json)
{
	wuy_json_new_array(json);

	struct h2d_upstream_conf *conf;
	wuy_list_iter_type(&h2d_upstream_list, conf, list_node) {
		h2d_upstream_conf_stats(conf, json);
	}
	wuy_json_array_close(json);
}

static struct wuy_cflua_command h2d_upstream_failure_commands[] = {
	{	.name = "fails",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream_conf, failure.fails),
		.default_value.n = 1,
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "passes",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream_conf, failure.passes),
		.default_value.n = 3,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream_conf, failure.timeout),
		.default_value.n = 60,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "filter",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_upstream_conf, failure.filter),
	},
	{ NULL },
};

static struct wuy_cflua_command h2d_upstream_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.description = "Hostnames list.",
		.offset = offsetof(struct h2d_upstream_conf, hostnames_str),
		.array_number_offset = offsetof(struct h2d_upstream_conf, hostname_num),
	},
	{	.name = "dynamic",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_upstream_conf, dynamic),
		.u.table = &h2d_dynamic_conf_table,
	},
	{	.name = "idle_max",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream_conf, idle_max),
		.default_value.n = 100,
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "max_retries",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream_conf, max_retries),
		.default_value.n = 1,
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "retry_status_codes",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_upstream_conf, retry_status_codes),
		.u.table = WUY_CFLUA_ARRAY_INTEGER_TABLE,
	},
	{	.name = "recv_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream_conf, recv_timeout),
		.default_value.n = 10,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "send_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream_conf, send_timeout),
		.default_value.n = 10,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "idle_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream_conf, idle_timeout),
		.default_value.n = 60,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "default_port",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream_conf, default_port),
		.default_value.n = 80,
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "resolve_interval",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream_conf, resolve_interval),
		.default_value.n = 60,
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "resolved_addresses_max",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream_conf, resolved_addresses_max),
		.default_value.n = 100,
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "ssl_enable",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct h2d_upstream_conf, ssl_enable),
	},
	{	.name = "failure",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) { h2d_upstream_failure_commands },
	},
	{	.name = "healthcheck",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) { h2d_upstream_healthcheck_commands },
	},
	{	.name = "log",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_upstream_conf, log),
		.u.table = &h2d_log_conf_table,
	},
	{	.type = WUY_CFLUA_TYPE_END,
		.u.next = h2d_upstream_next_command,
	},
};

struct wuy_cflua_table h2d_upstream_conf_table = {
	.commands = h2d_upstream_conf_commands,
	.refer_name = "UPSTREAM",
	.size = sizeof(struct h2d_upstream_conf),
	.post = h2d_upstream_conf_post,
	.free = h2d_upstream_conf_free,
};

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

static int h2d_upstream_loadbalance_number;

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

static bool h2d_upstream_is_active_healthcheck(struct h2d_upstream_conf *upstream)
{
	/* If upstream->healthcheck.request/response are set, we do the
	 * healthcheck by sending the request and checking the response
	 * periodly, in upstream->healthcheck.interval. We call it active.
	 *
	 * Otherwise, we have to do the healthcheck by real requests. The
	 * address can be picked if it's down for upstream->healthcheck.interval.
	 * We call it passive. */
	return upstream->healthcheck.req_len != 0;
}

void h2d_upstream_connection_fail(struct h2d_upstream_connection *upc)
{
	struct h2d_request *r = upc->request;
	struct h2d_upstream_address *address = upc->address;
	struct h2d_upstream_conf *upstream = address->upstream;

	_log(H2D_LOG_INFO, "connection fail %s", address->name);

	if (upstream->fails == 0) { /* configure never down */
		return;
	}

	if (address->down_time != 0) { /* down already */
		if (address->healthchecks > 0) { /* fail in passive healthcheck */
			_log(H2D_LOG_DEBUG, "passive healthcheck fail");
			address->healthchecks = 0;
			address->down_time = time(NULL);
		}
		return;
	}

	address->fails++;
	if (address->fails < upstream->fails) {
		return;
	}

	/* go down */
	_log(H2D_LOG_ERROR, "go down");
	address->down_time = time(NULL);
	address->healthchecks = 0;

	atomic_fetch_add(&address->stats->down, 1);

	if (h2d_upstream_is_active_healthcheck(upstream)) {
		wuy_list_del_if(&address->down_node);
		wuy_list_append(&upstream->down_head, &address->down_node);
	}
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
	.timeout_ms = 10*1000, // TODO
	H2D_SSL_LOOP_STREAM_UNDERLYINGS,
};

void h2d_upstream_resolve(struct h2d_upstream_conf *upstream);
void h2d_upstream_healthcheck(struct h2d_upstream_conf *upstream);

struct h2d_upstream_connection *
h2d_upstream_get_connection(struct h2d_upstream_conf *upstream, struct h2d_request *r)
{
	if (h2d_dynamic_is_enabled(&upstream->dynamic)) {
		upstream = h2d_dynamic_get(&upstream->dynamic, r);
		if (upstream == NULL) {
			h2d_request_log(r, H2D_LOG_DEBUG, "dynamic get %d", r->resp.status_code);
			return NULL;
		}
		if (upstream->address_num == 0) { /* wait for hostname resolving */
			_log(H2D_LOG_DEBUG, "dynamic wait for resolving");
			if (wuy_list_node_linked(&r->list_node)) {
				printf("!!!!! where does it linked???\n");
				abort();
			}
			wuy_list_append(&upstream->wait_head, &r->list_node);
			return NULL;
		}
		_log(H2D_LOG_DEBUG, "dynamic get done");
	}

	/* resolve and healthcheck routines */
	h2d_upstream_resolve(upstream);
	h2d_upstream_healthcheck(upstream);

	struct h2d_upstream_address *address = upstream->loadbalance->pick(upstream, r);
	if (address == NULL) {
		_log(H2D_LOG_ERROR, "pick fail");
		atomic_fetch_add(&upstream->stats->pick_fail, 1);
		return NULL;
	}

	if (!h2d_upstream_address_is_pickable(address, r)) {
		_log(H2D_LOG_ERROR, "all down");

		struct h2d_upstream_address *iaddr;
		wuy_list_iter_type(&upstream->address_head, iaddr, upstream_node) {
			iaddr->down_time = 0;
		}
	} else if (address->down_time != 0) {
		_log(H2D_LOG_DEBUG, "passive healthcheck");
		address->healthchecks++;
	}

	atomic_fetch_add(&address->stats->pick, 1);

	/* try to reuse */
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
		return NULL;
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

	h2d_upstream_connection_close(old);

	/* mark this down temporarily to avoid picked again */
	time_t down_time;
	if (address->down_time == 0) {
		down_time = address->down_time;
		address->down_time = 1;
	}

	/* pick a new connection */
	struct h2d_upstream_connection *newc = h2d_upstream_get_connection(upstream, r);

	/* recover if it was not cleared */
	if (address->down_time == 1) {
		address->down_time = down_time;
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

	_log(H2D_LOG_DEBUG, "release %s", address->name);

	/* the connection maybe in passive healthcheck */
	if (address->down_time > 0 && address->healthchecks >= upstream->healthcheck.repeats) {
		_log(H2D_LOG_INFO, "recover from passive healthcheck");
		address->down_time = 0;
	}

	/* close the connection */
	if (loop_stream_is_closed(upc->loop_stream) || r->state != H2D_REQUEST_STATE_DONE) {
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

/* We assume that the writing would not lead to block here.
 * If @data==NULL, we just check if in connecting. */
int h2d_upstream_connection_write(struct h2d_upstream_connection *upc,
		void *data, int data_len)
{
	assert(upc->loop_stream != NULL);

	if (upc->create_time != 0) {
		atomic_fetch_add(&upc->address->stats->connected, 1);
		atomic_fetch_add(&upc->address->stats->connect_acc_ms, wuy_time_ms() - upc->create_time);
		upc->create_time = 0;
	}

	int write_len = loop_stream_write(upc->loop_stream, data, data_len);
	if (write_len < 0) {
		_log_upc(H2D_LOG_ERROR, "write fail %d", write_len);
		return H2D_ERROR;
	}
	if (write_len != data_len) { /* blocking happens */ // TODO
		_log_upc(H2D_LOG_ERROR, "write blockes %d %d", write_len, data_len);
		return H2D_ERROR;
	}

	_log_upc(H2D_LOG_DEBUG, "write %d", write_len);

	/* we assume that the response is expected just after one write */
	loop_stream_set_timeout(upc->loop_stream,
			upc->address->upstream->recv_timeout * 1000);

	return H2D_OK;
}

void h2d_upstream_init(void)
{
	h2d_upstream_loadbalance_number = H2D_UPSTREAM_LOADBALANCE_STATIC_NUMBER;

	// TODO load dynamic loadbalance here

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
	if (address->down_time == 0) {
		return true;
	}
	if (h2d_upstream_is_active_healthcheck(upstream)) {
		return false;
	}
	if (time(NULL) < address->down_time + upstream->healthcheck.interval) {
		return false;
	}
	if (!wuy_list_empty(&address->active_head)) {
		/* at most one connection is allowed in healthcheck */
		return false;
	}
	if (wuy_cflua_is_function_set(upstream->healthcheck.filter)) {
		return h2d_lua_api_call_boolean(r, upstream->healthcheck.filter);
	}
	return true;
}

/* configration */

static bool h2d_upstream_conf_loadbalance_select(struct h2d_upstream_conf *conf)
{
	for (int i = 1; i < h2d_upstream_loadbalance_number; i++) {
		struct h2d_upstream_loadbalance *lb = h2d_upstream_loadbalances[i];
		if (h2d_module_command_is_set(&lb->command, conf->lb_confs[i])) {
			if (conf->loadbalance != NULL) {
				printf("duplicate loadbalance\n");
				return false;
			}
			conf->loadbalance = lb;
		}
	}

	/* default is roundrobing which is the first lb */
	if (conf->loadbalance == NULL) {
		conf->loadbalance = h2d_upstream_loadbalances[0];
	}

	return true;
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

static void h2d_upstream_delete(void *data)
{
}

bool h2d_upstream_conf_resolve_init(struct h2d_upstream_conf *conf);
static bool h2d_upstream_conf_post(void *data)
{
	struct h2d_upstream_conf *conf = data;

	/* some check for both cases, dynamic or not */
	if ((conf->healthcheck.req_len == 0) != (conf->healthcheck.resp_len == 0)) {
		printf("healthcheck request/response must be set both or neigther\n");
		return false;
	}
	if (h2d_upstream_is_active_healthcheck(conf) && wuy_cflua_is_function_set(conf->healthcheck.filter)) {
		printf("request is for active healthcheck while filter is for passive\n");
		return false;
	}

	if (!h2d_upstream_conf_loadbalance_select(conf)) {
		return false;
	}

	conf->stats = wuy_shmem_alloc(sizeof(struct h2d_upstream_stats));

	/* dynamic */
	if (h2d_dynamic_is_enabled(&conf->dynamic)) {
		if (conf->hostnames != NULL) {
			printf("hostname is not allowed for dynamic upstream\n");
			return false;
		}
		conf->hostnames = (void *)1; /* used by h2d_module_command_is_set() */

		h2d_dynamic_set_container(&conf->dynamic, &h2d_upstream_conf_table,
				offsetof(struct h2d_upstream_conf, dynamic),
				h2d_upstream_delete);

		if (conf->name == NULL) {
			conf->name = "dynamic";
		}

		return true;
	}

	/* non-dynamic: static configured or created dynamic-sub */
	if (conf->hostnames == NULL) {
		return true;
	}

	wuy_list_init(&conf->wait_head);
	wuy_list_init(&conf->address_head);
	wuy_list_init(&conf->deleted_address_defer);
	wuy_list_init(&conf->down_head);

	if (conf->name == NULL) {
		conf->name = conf->hostnames[0].name;
	}

	if (conf->ssl_enable) {
		conf->ssl_ctx = h2d_ssl_ctx_new_client();
	}

	if (!h2d_upstream_conf_resolve_init(conf)) {
		return false;
	}

	conf->loadbalance->update(conf);

	if (!h2d_dynamic_is_sub(&conf->dynamic)) {
		wuy_list_append(&h2d_upstream_list, &conf->list_node);
	}

	return true;
}

static void h2d_upstream_conf_stats(struct h2d_upstream_conf *conf, wuy_json_ctx_t *json)
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
		wuy_json_object_int(json, "down_time", address->down_time);

		struct h2d_upstream_address_stats *stats = address->stats;
		wuy_json_object_int(json, "create_time", atomic_load(&stats->create_time));
		wuy_json_object_int(json, "down", atomic_load(&stats->down));
		wuy_json_object_int(json, "pick", atomic_load(&stats->pick));
		wuy_json_object_int(json, "reuse", atomic_load(&stats->reuse));
		wuy_json_object_int(json, "connected", atomic_load(&stats->connected));
		wuy_json_object_int(json, "connect_acc_ms", atomic_load(&stats->connect_acc_ms));
		wuy_json_object_close(json);
	}
	wuy_json_array_close(json); /* end of addresses[] */

	wuy_json_object_close(json);
}
void h2d_upstream_stats(wuy_json_ctx_t *json)
{
	wuy_json_new_array(json);

	struct h2d_upstream_conf *conf;
	wuy_list_iter_type(&h2d_upstream_list, conf, list_node) {
		h2d_upstream_conf_stats(conf, json);
	}
	wuy_json_array_close(json);
}

static struct wuy_cflua_command h2d_upstream_healthcheck_commands[] = {
	{	.name = "interval",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream_conf, healthcheck.interval),
		.default_value.n = 60,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "filter",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_upstream_conf, healthcheck.filter),
	},
	{	.name = "repeats",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream_conf, healthcheck.repeats),
		.default_value.n = 3,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "request",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_upstream_conf, healthcheck.req_str),
		.u.length_offset = offsetof(struct h2d_upstream_conf, healthcheck.req_len),
	},
	{	.name = "response",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_upstream_conf, healthcheck.resp_str),
		.u.length_offset = offsetof(struct h2d_upstream_conf, healthcheck.resp_len),
	},
	{ NULL }
};
static struct wuy_cflua_command h2d_upstream_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_upstream_conf, hostnames),
		.array_member_size = sizeof(struct h2d_upstream_hostname),
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
	{	.name = "fails",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream_conf, fails),
		.default_value.n = 1,
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
	.size = sizeof(struct h2d_upstream_conf),
	.post = h2d_upstream_conf_post,
};

#include "phl_main.h"

#define X(lb) extern struct phl_upstream_loadbalance lb;
PHL_UPSTREAM_LOADBALANCE_X_LIST
#undef X
static struct phl_upstream_loadbalance *phl_upstream_loadbalance_statics[] =
{
	#define X(lb) &lb,
	PHL_UPSTREAM_LOADBALANCE_X_LIST
	#undef X
};

static WUY_LIST(phl_upstream_list);

#define _log(level, fmt, ...) phl_request_log_at(r, \
		upstream->log, level, "upstream: " fmt, ##__VA_ARGS__)

#define _log_upc(level, fmt, ...) phl_request_log_at(upc->request, \
		upc->address->upstream->log, level, "upstream: " fmt, ##__VA_ARGS__)

static void phl_upstream_connection_close(struct phl_upstream_connection *upc)
{
	loop_stream_close(upc->loop_stream);

	wuy_list_delete(&upc->list_node);

	if (upc->request == NULL) {
		upc->address->idle_num--;
	}

	free(upc->preread_buf);
	free(upc);
}

static void phl_upstream_on_active(loop_stream_t *s)
{
	/* Explicit handshake is not required here because the following
	 * routine will call SSL_read/SSL_write to do the handshake.
	 * We handshake here just to avoid calling the following
	 * routine during handshake for performence. So we handle
	 * PHL_AGAIN only, but not PHL_ERROR. */
	if (phl_ssl_stream_handshake(s) == PHL_AGAIN) {
		return;
	}

	struct phl_upstream_connection *upc = loop_stream_get_app_data(s);
	if (upc->request != NULL) {
		phl_request_run(upc->request, "upstream active");
	} else { /* idle */
		phl_upstream_connection_close(upc);
	}
}
static void phl_upstream_on_close(loop_stream_t *s, enum loop_stream_close_reason r)
{
	if (r == LOOP_STREAM_TIMEOUT) {
		phl_upstream_on_active(s);
	}
}
static loop_stream_ops_t phl_upstream_ops = {
	.on_readable = phl_upstream_on_active,
	.on_writable = phl_upstream_on_active,
	.on_close = phl_upstream_on_close,
	PHL_SSL_LOOP_STREAM_UNDERLYINGS,
};

struct phl_upstream_connection *
phl_upstream_get_connection(struct phl_upstream_conf *upstream, struct phl_request *r)
{
	/* check if dynamic */
	while (phl_dynamic_is_enabled(&upstream->dynamic)) {
		phl_request_log(r, PHL_LOG_DEBUG, "dynamic get");
		upstream = phl_dynamic_get(&upstream->dynamic, r);
		if (!PHL_PTR_IS_OK(upstream)) {
			return (void *)upstream;
		}
	}

	if (upstream->address_num == 0) { /* only if dynamic upstream */
		if (!wuy_list_node_linked(&r->list_node)) {
			_log(PHL_LOG_DEBUG, "dynamic wait for resolving");
			wuy_list_append(&upstream->wait_head, &r->list_node);
		}
		return PHL_PTR_AGAIN;
	}

	/* pick an address */
	struct phl_upstream_address *address = upstream->loadbalance->pick(upstream, r);
	if (address == NULL) {
		_log(PHL_LOG_ERROR, "pick fail");
		atomic_fetch_add(&upstream->stats->pick_fail, 1);
		return PHL_PTR_ERROR;
	}

	if (!phl_upstream_address_is_pickable(address, r)) {
		_log(PHL_LOG_ERROR, "all down");

		struct phl_upstream_address *iaddr;
		wuy_list_iter_type(&upstream->address_head, iaddr, upstream_node) {
			// XXX iaddr->down_time = 0;
		}
	}

	atomic_fetch_add(&address->stats->pick, 1);

	/* try to reuse an idle one */
	struct phl_upstream_connection *upc;
	if (wuy_list_pop_type(&address->idle_head, upc, list_node)) {
		_log(PHL_LOG_DEBUG, "reuse %s", address->name);
		wuy_list_append(&address->active_head, &upc->list_node);
		address->idle_num--;
		atomic_fetch_add(&address->stats->reuse, 1);
		upc->request = r;
		return upc;
	}

	_log(PHL_LOG_DEBUG, "connect %s", address->name);

	/* new connection */
	loop_stream_t *s = loop_tcp_connect_sockaddr(phl_loop, &address->sockaddr.s,
			&phl_upstream_ops);
	if (s == NULL) {
		_log(PHL_LOG_ERROR, "connect fail %s", strerror(errno));
		return PHL_PTR_ERROR;
	}
	loop_stream_set_timeout(s, upstream->send_timeout * 1000);

	if (upstream->ssl != NULL) {
		phl_ssl_stream_set(s, upstream->ssl->ctx, false);
	}

	upc = calloc(1, sizeof(struct phl_upstream_connection));
	upc->address = address;
	upc->loop_stream = s;
	wuy_list_append(&address->active_head, &upc->list_node);
	loop_stream_set_app_data(s, upc);
	upc->create_time = wuy_time_ms();

	upc->request = r;
	return upc;
}

/* close @old connection and return a new one */
struct phl_upstream_connection *
phl_upstream_retry_connection(struct phl_upstream_connection *old)
{
	struct phl_request *r = old->request;
	struct phl_upstream_address *address = old->address;
	struct phl_upstream_conf *upstream = address->upstream;

	_log(PHL_LOG_DEBUG, "retry for %s", address->name);

	atomic_fetch_add(&upstream->stats->retry, 1);

	phl_upstream_release_connection(old, false);

	/* mark this down temporarily to avoid picked again */
	if (address->healthcheck.down_time == 0) {
		address->healthcheck.down_time = 1;
	}

	/* pick a new connection */
	struct phl_upstream_connection *newc = phl_upstream_get_connection(upstream, r);

	/* recover */
	if (address->healthcheck.down_time == 1) {
		address->healthcheck.down_time = 0;
	}

	return newc;
}

void phl_upstream_release_connection(struct phl_upstream_connection *upc, bool is_clean)
{
	assert(upc->request != NULL);
	assert(upc->loop_stream != NULL);

	struct phl_request *r = upc->request;
	struct phl_upstream_address *address = upc->address;
	struct phl_upstream_conf *upstream = address->upstream;

	_log(PHL_LOG_DEBUG, "release %s%s", address->name, upc->error ? " in error" : "");

	if (!upc->error) {
		address->failure.fails = 0;
		address->failure.passes++;
		if (address->failure.down_time != 0 && address->failure.passes == upstream->failure.passes) {
			_log(PHL_LOG_ERROR, "go up");
			address->failure.down_time = 0;
		}
	} else {
		address->failure.passes = 0;
		address->failure.fails++;
		if (address->failure.down_time == 0 && address->failure.fails == upstream->failure.fails) {
			_log(PHL_LOG_ERROR, "go down");
			atomic_fetch_add(&address->stats->failure_down, 1);
			address->failure.down_time = time(NULL);
		}
	}

	/* close the connection */
	if (upc->error || !is_clean || loop_stream_is_closed(upc->loop_stream)) {
		_log(PHL_LOG_DEBUG, "just close, state=%d", r->state);
		phl_upstream_connection_close(upc);
		return;
	}

	/* put the connection into idle pool */
	_log(PHL_LOG_DEBUG, "keeplive, idles=%d", address->idle_num);

	if (address->idle_num > upstream->idle_max) {
		/* close the oldest one if pool is full */
		struct phl_upstream_connection *idle;
		wuy_list_first_type(&address->idle_head, idle, list_node);
		assert(idle != NULL);
		phl_upstream_connection_close(idle);
	}

	upc->request = NULL;
	address->idle_num++;
	wuy_list_delete(&upc->list_node);
	wuy_list_append(&address->idle_head, &upc->list_node);

	loop_stream_set_timeout(upc->loop_stream, upstream->idle_timeout * 1000);
}

int phl_upstream_connection_read(struct phl_upstream_connection *upc,
		void *buffer, int buf_len)
{
	assert(upc->loop_stream != NULL);
	uint8_t *buf_pos = buffer;

	/* upc->preread_buf was allocated in phl_upstream_connection_read_notfinish() */
	if (upc->preread_buf != NULL) {
		_log_upc(PHL_LOG_DEBUG, "read preread %d", upc->preread_len);

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
		_log_upc(PHL_LOG_ERROR, "read fail %d", read_len);
		return PHL_ERROR;
	}
	if (read_len > 0) { /* update timer */
		loop_stream_set_timeout(upc->loop_stream,
				upc->address->upstream->recv_timeout * 1000);
	}

	int ret_len = buf_pos - (uint8_t *)buffer + read_len;
	_log_upc(PHL_LOG_DEBUG, "read %d", ret_len);

	return ret_len == 0 ? PHL_AGAIN : ret_len;
}
void phl_upstream_connection_read_notfinish(struct phl_upstream_connection *upc,
		void *buffer, int buf_len)
{
	if (buf_len == 0) {
		return;
	}
	_log_upc(PHL_LOG_DEBUG, "read not finish %d", buf_len);

	assert(upc->preread_buf == NULL);
	upc->preread_buf = malloc(buf_len);
	memcpy(upc->preread_buf, buffer, buf_len);
	upc->preread_len = buf_len;
}

int phl_upstream_connection_write(struct phl_upstream_connection *upc,
		const void *data, int data_len)
{
	assert(upc->loop_stream != NULL);

	if (upc->create_time != 0) {
		atomic_fetch_add(&upc->address->stats->connected, 1);
		atomic_fetch_add(&upc->address->stats->connect_acc_ms, wuy_time_ms() - upc->create_time);
		upc->create_time = 0;
	}

	if (loop_stream_is_write_blocked(upc->loop_stream)) {
		return PHL_AGAIN;
	}
	if (upc->prewrite_len > 0) {
		data = (const char *)data + upc->prewrite_len;
		data_len -= upc->prewrite_len;
	}

	int write_len = loop_stream_write(upc->loop_stream, data, data_len);
	if (write_len < 0) {
		_log_upc(PHL_LOG_ERROR, "write fail %d", write_len);
		return PHL_ERROR;
	}
	if (write_len != data_len) {
		_log_upc(PHL_LOG_DEBUG, "write blockes %d %d", write_len, data_len);
		upc->prewrite_len = write_len;
		return PHL_AGAIN;
	}

	_log_upc(PHL_LOG_DEBUG, "write %d", write_len);
	upc->prewrite_len = 0;

	/* we assume that the response is expected just after one write */
	loop_stream_set_timeout(upc->loop_stream,
			upc->address->upstream->recv_timeout * 1000);

	return PHL_OK;
}

static void phl_upstream_loadbalance_module_fix(struct phl_upstream_loadbalance *lb, int i)
{
	lb->index = i;
	lb->command.offset = offsetof(struct phl_upstream_conf, lb_confs) + sizeof(void *) * i;
}

void phl_upstream_dynamic_module_fix(struct phl_upstream_loadbalance *m, int i)
{
	phl_upstream_loadbalance_module_fix(m, PHL_UPSTREAM_LOADBALANCE_STATIC_NUMBER + i);
}

void phl_upstream_init(void)
{
	/* static modules only here */
	for (int i = 0; i < PHL_UPSTREAM_LOADBALANCE_STATIC_NUMBER; i++) {
		struct phl_upstream_loadbalance *lb = phl_upstream_loadbalance_statics[i];
		phl_upstream_loadbalance_module_fix(lb, i);
	}
}

/* iteration on static and dynamic modules */
struct phl_upstream_loadbalance *phl_upstream_loadbalance_next(struct phl_upstream_loadbalance *lb)
{
	if (lb == NULL) {
		return phl_upstream_loadbalance_statics[0];
	}
	int next = lb->index + 1;
	if (next < PHL_UPSTREAM_LOADBALANCE_STATIC_NUMBER) {
		return phl_upstream_loadbalance_statics[next];
	}
	if (phl_conf_runtime == NULL || phl_conf_runtime->dynamic_upstream_modules == NULL) {
		return NULL;
	}
	return phl_conf_runtime->dynamic_upstream_modules[next - PHL_UPSTREAM_LOADBALANCE_STATIC_NUMBER].sym;
}

bool phl_upstream_address_is_pickable(struct phl_upstream_address *address,
		struct phl_request *r)
{
	struct phl_upstream_conf *upstream = address->upstream;
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
		return phl_lua_call_boolean(r, upstream->failure.filter);
	}
	return true;
}

/* configration */

static const char *phl_upstream_conf_loadbalance_select(struct phl_upstream_conf *conf)
{
	int i = 0;
	struct phl_upstream_loadbalance *random_lb = NULL, *lb = NULL;
	while ((lb = phl_upstream_loadbalance_next(lb)) != NULL) {
		if (phl_module_command_is_set(&lb->command, conf->lb_confs[i++])) {
			if (conf->loadbalance != NULL) {
				return "duplicate loadbalance";
			}
			conf->loadbalance = lb;
		} else if (strcmp(lb->name, "random") == 0) {
			random_lb = lb;
		}
	}

	if (conf->loadbalance == NULL) { /* use random as default */
		conf->loadbalance = random_lb;
	}

	conf->lb_ctx = conf->loadbalance->ctx_new();

	return WUY_CFLUA_OK;
}

static struct wuy_cflua_command *phl_upstream_next_command(struct wuy_cflua_command *cmd)
{
	struct phl_upstream_loadbalance *lb = NULL;
	if (cmd->type != WUY_CFLUA_TYPE_END || cmd->u.next == NULL) {
		lb = wuy_containerof(cmd, struct phl_upstream_loadbalance, command);
	}

	while ((lb = phl_upstream_loadbalance_next(lb)) != NULL) {
		struct wuy_cflua_command *next = &lb->command;
		if (next->type != WUY_CFLUA_TYPE_END) {
			return next;
		}
	}
	return NULL;
}

const char *phl_upstream_conf_resolve_init(struct phl_upstream_conf *conf);
static const char *phl_upstream_conf_post(void *data)
{
	struct phl_upstream_conf *conf = data;

	const char *lb_err = phl_upstream_conf_loadbalance_select(conf);
	if (lb_err != WUY_CFLUA_OK) {
		return lb_err;
	}

	conf->stats = wuy_shmpool_alloc(sizeof(struct phl_upstream_stats));

	/* dynamic */
	if (phl_dynamic_is_enabled(&conf->dynamic)) {
		if (conf->hostnames_str != NULL) {
			return "hostname is not allowed for dynamic upstream";
		}
		conf->hostnames_str = (void *)1; /* used by phl_module_command_is_set() */

		phl_dynamic_set_container(&conf->dynamic, &phl_upstream_conf_table);

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

	const char *resv_err = phl_upstream_conf_resolve_init(conf);
	if (resv_err != WUY_CFLUA_OK) {
		return resv_err;
	}

	conf->loadbalance->update(conf);

	if (!phl_dynamic_is_sub(&conf->dynamic)) {
		wuy_list_append(&phl_upstream_list, &conf->list_node);
	}

	return WUY_CFLUA_OK;
}

static void phl_upstream_conf_free(void *data)
{
	struct phl_upstream_conf *conf = data;
	wuy_list_del_if(&conf->list_node);

	if (conf->resolve_timer != NULL) {
		loop_timer_delete(conf->resolve_timer);
	}
	if (conf->resolve_stream != NULL) {
		loop_stream_close(conf->resolve_stream);
	}

	if (conf->loadbalance != NULL) {
		conf->loadbalance->ctx_free(conf->lb_ctx);
	}
}

static void phl_upstream_conf_stats(struct phl_upstream_conf *conf, wuy_json_t *json)
{
	wuy_json_new_object(json);

	wuy_json_object_string(json, "name", conf->name);

	struct phl_upstream_stats *stats = conf->stats;
	wuy_json_object_int(json, "retry", atomic_load(&stats->retry));
	wuy_json_object_int(json, "pick_fail", atomic_load(&stats->pick_fail));

	wuy_json_object_array(json, "addresses"); /* addresses[] */
	struct phl_upstream_address *address;
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

		struct phl_upstream_address_stats *stats = address->stats;
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
void phl_upstream_stats(wuy_json_t *json)
{
	wuy_json_new_array(json);

	struct phl_upstream_conf *conf;
	wuy_list_iter_type(&phl_upstream_list, conf, list_node) {
		phl_upstream_conf_stats(conf, json);
	}
	wuy_json_array_close(json);
}

static struct wuy_cflua_command phl_upstream_failure_commands[] = {
	{	.name = "fails",
		.description = "Mark an address as failure if it fails this times continuously.",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_upstream_conf, failure.fails),
		.default_value.n = 1,
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "passes",
		.description = "Recover an address if it responses well this times continuously.",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_upstream_conf, failure.passes),
		.default_value.n = 3,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "timeout",
		.description = "Try to use a failure address after this time.",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_upstream_conf, failure.timeout),
		.default_value.n = 60,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "filter",
		.description = "Do not try a failure address on current request if this function returns false.",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct phl_upstream_conf, failure.filter),
	},
	{ NULL },
};

static struct wuy_cflua_command phl_upstream_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.description = "Hostnames list. Delimiter '#' defines weight, e.g. `127.0.0.1:8080#0.2`.",
		.offset = offsetof(struct phl_upstream_conf, hostnames_str),
		.array_number_offset = offsetof(struct phl_upstream_conf, hostname_num),
	},
	{	.name = "dynamic",
		.description = "Do not use the static-defined hostnames; "
			"while dynamicly according to request. See `dynamic` for details.",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct phl_upstream_conf, dynamic),
		.u.table = &phl_dynamic_conf_table,
	},
	{	.name = "idle_max",
		.description = "Max idle connections.",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_upstream_conf, idle_max),
		.default_value.n = 100,
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "max_retries",
		.description = "Max retry count if connecting failure or some status-codes.",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_upstream_conf, max_retries),
		.default_value.n = 1,
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "retry_status_codes",
		.description = "Retry if getting these status-codes.",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct phl_upstream_conf, retry_status_codes),
		.u.table = WUY_CFLUA_ARRAY_INTEGER_TABLE,
	},
	{	.name = "recv_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_upstream_conf, recv_timeout),
		.default_value.n = 10,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "send_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_upstream_conf, send_timeout),
		.default_value.n = 10,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "idle_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_upstream_conf, idle_timeout),
		.default_value.n = 60,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "default_port",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_upstream_conf, default_port),
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "resolve_interval",
		.description = "Interval of resolving hostnames. Set 0 to disable.",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_upstream_conf, resolve_interval),
		.default_value.n = 60,
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "resolved_addresses_max",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_upstream_conf, resolved_addresses_max),
		.default_value.n = 100,
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "ssl",
		.description = "Set to enable HTTPS, even to a empty table `{}`.",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct phl_upstream_conf, ssl),
		.u.table = &phl_ssl_client_conf_table,
	},
	{	.name = "failure",
		.description = "Passive healthcheck",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) { phl_upstream_failure_commands },
	},
	{	.name = "healthcheck",
		.description = "Active healthcheck",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) { phl_upstream_healthcheck_commands },
	},
	{	.name = "log",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct phl_upstream_conf, log),
		.u.table = &phl_log_omit_conf_table,
	},
	{	.type = WUY_CFLUA_TYPE_END,
		.u.next = phl_upstream_next_command,
	},
};

struct wuy_cflua_table phl_upstream_conf_table = {
	.commands = phl_upstream_conf_commands,
	.refer_name = "UPSTREAM",
	.may_omit = true,
	.size = sizeof(struct phl_upstream_conf),
	.post = phl_upstream_conf_post,
	.free = phl_upstream_conf_free,
};

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
	struct h2d_upstream_address *address = upc->address;
	struct h2d_upstream_conf *upstream = address->upstream;

	if (upstream->fails == 0) { /* configure never down */
		return;
	}

	if (address->down_time != 0) { /* down already */
		if (address->healthchecks > 0) { /* fail in passive healthcheck */
			printf("upstream address passive healthcheck fail\n");
			address->healthchecks = 0;
			address->down_time = time(NULL);
		}
		return;
	}

	address->fails++;
	if (address->fails < upstream->fails) {
		printf("upstream address fail %d\n", address->fails);
		return;
	}

	/* go down */
	printf("upstream address go down\n");
	address->down_time = time(NULL);
	address->healthchecks = 0;

	address->stats.down++;

	if (h2d_upstream_is_active_healthcheck(upstream)) {
		wuy_list_del_if(&address->down_node);
		wuy_list_append(&upstream->down_head, &address->down_node);
	}
}

static struct wuy_cflua_table h2d_upstream_sub_conf_table;
static struct h2d_upstream_conf *
h2d_upstream_dynamic_get(struct h2d_upstream_conf *upstream, struct h2d_request *r)
{
	h2d_request_log(r, H2D_LOG_DEBUG, "h2d_upstream_dynamic_get()");
	const char *name = r->dynamic_upstream.name;
	struct h2d_upstream_conf *subups = NULL;

	if (name != NULL) {
		/* we have got name by get_name(), and was got H2D_AGAIN
		 * when calling get_conf(), and it's ready now. */
		subups = wuy_dict_get(upstream->dynamic.dict, name);
		goto state_get_conf;
	}

	/* call get_name() */
	if (upstream->dynamic.is_name_blocking) {
		h2d_request_log(r, H2D_LOG_DEBUG, "dynamic upstream get_name() blocking");
		name = h2d_lua_api_call_lstring(r, upstream->dynamic.get_name, NULL);
		if (name == NULL) {
			goto fail;
		}
		r->dynamic_upstream.name = strdup(name);

	} else {
		h2d_request_log(r, H2D_LOG_DEBUG, "dynamic upstream get_name() non-blocking");

		if (r->dynamic_upstream.L == NULL) {
			r->dynamic_upstream.L = h2d_lua_api_thread_new(upstream->dynamic.get_name);
		}

		int ret = h2d_lua_api_thread_resume(r->dynamic_upstream.L, r);
		if (ret == H2D_ERROR) {
			goto fail;
		}
		if (ret == H2D_AGAIN) {
			return NULL;
		}

		name = lua_tostring(r->dynamic_upstream.L, -1);
		if (name == NULL) {
			goto fail;
		}
		r->dynamic_upstream.name = strdup(name);

		h2d_lua_api_thread_free(r->dynamic_upstream.L);
		r->dynamic_upstream.L = NULL;
	}

	name = r->dynamic_upstream.name;

	/* search cache by name */
	subups = wuy_dict_get(upstream->dynamic.dict, name);
	if (subups != NULL) {
		h2d_request_log(r, H2D_LOG_DEBUG, "upstream hit %s", name);
		return subups;
	}

	/* cache miss, so create new sub-upstream */
	subups = malloc(sizeof(struct h2d_upstream_conf));
	*subups = *upstream; /* inherit confs */
	subups->name = strdup(name);
	subups->address_num = 0;
	subups->dynamic.get_name = 0;
	subups->dynamic.dict = NULL;
	wuy_dict_add(upstream->dynamic.dict, subups);

	/* simple case: single hostname */
	if (name[0] != '@') {
		subups->hostnames = calloc(2, sizeof(struct h2d_upstream_hostname));
		subups->hostnames->name = strdup(name);
		if (!h2d_upstream_sub_conf_table.post(subups)) {
			printf("!!! sub upstream fail\n");
			return NULL;
		}

		goto return_new_sub_upstream;
	}

	/* the other case: get_conf() by name */
	h2d_request_log(r, H2D_LOG_DEBUG, "dynamic upstream get_conf()");
	r->dynamic_upstream.L = h2d_lua_api_thread_new(upstream->dynamic.get_conf);

state_get_conf:;

	int ret = h2d_lua_api_thread_resume(r->dynamic_upstream.L, r);
	if (ret == H2D_ERROR) {
		goto fail;
	}
	if (ret == H2D_AGAIN) {
		return NULL;
	}
	if (lua_gettop(r->dynamic_upstream.L) != 1 || !lua_istable(r->dynamic_upstream.L, -1)) {
		printf("return nil\n");
		goto fail;
	}

	lua_xmove(r->dynamic_upstream.L, h2d_L, 1);
	h2d_lua_api_thread_free(r->dynamic_upstream.L);
	r->dynamic_upstream.L = NULL;

	int err = wuy_cflua_parse(h2d_L, &h2d_upstream_sub_conf_table, subups);
	if (err < 0) {
		printf("parse dynamic upstream error: %s\n", wuy_cflua_strerror(h2d_L, err));
		goto fail;
	}

	if (wuy_cflua_is_function_set(subups->dynamic.get_name)) {
		printf("dynamic_get is not allowed in dynamic upstream\n");
		goto fail;
	}

return_new_sub_upstream:
	h2d_request_log(r, H2D_LOG_DEBUG, "return upstream new %s %d %s",
			name, subups->address_num, subups->hostnames[0].name);
	r->dynamic_upstream.name = NULL;
	wuy_dict_add(upstream->dynamic.dict, subups);
	// TODO non-block hostname resolve
	return subups;

fail:
	if (subups != NULL) {
		wuy_dict_delete(upstream->dynamic.dict, subups);
		free(subups);
	}
	r->resp.status_code = WUY_HTTP_500;
	return NULL;
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
		h2d_request_active(upc->request);
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
	atomic_fetch_add(&upstream->stats->total, 1);

	if (wuy_cflua_is_function_set(upstream->dynamic.get_name)) {
		upstream = h2d_upstream_dynamic_get(upstream, r);
		if (upstream == NULL) {
			return NULL;
		}
	}

	/* resolve and healthcheck routines */
	h2d_upstream_resolve(upstream);
	h2d_upstream_healthcheck(upstream);

	struct h2d_upstream_address *address = upstream->loadbalance->pick(upstream, r);
	if (address == NULL) {
		printf("upstream pick fail\n");
		atomic_fetch_add(&upstream->stats->pick_fail, 1);
		return NULL;
	}

	if (!h2d_upstream_address_is_pickable(address)) {
		printf("upstream all down!\n");
		struct h2d_upstream_address *iaddr;
		wuy_list_iter_type(&upstream->address_head, iaddr, upstream_node) {
			iaddr->down_time = 0;
		}
	} else if (address->down_time != 0) {
		printf("upstream address passive healthcheck\n");
		address->healthchecks++;
	}

	address->stats.pick++;
	char tmpbuf[100];
	wuy_sockaddr_ntop(&address->sockaddr.s, tmpbuf, sizeof(tmpbuf));
	printf("pick %s\n", tmpbuf);

	/* try to reuse */
	struct h2d_upstream_connection *upc;
	if (wuy_list_pop_type(&address->idle_head, upc, list_node)) {
		wuy_list_append(&address->active_head, &upc->list_node);
		address->idle_num--;
		atomic_fetch_add(&upstream->stats->reuse, 1);
		address->stats.reuse++;
		upc->request = r;
		return upc;
	}

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

	struct h2d_upstream_address *address = upc->address;
	struct h2d_upstream_conf *upstream = address->upstream;

	/* the connection maybe in passive healthcheck */
	if (address->down_time > 0 && address->healthchecks >= upstream->healthcheck.repeats) {
		printf("upstream address recover from passive healthcheck\n");
		address->down_time = 0;
	}

	/* close the connection */
	if (loop_stream_is_closed(upc->loop_stream) || upc->request->state != H2D_REQUEST_STATE_DONE) {
		h2d_upstream_connection_close(upc);
		return;
	}

	/* put the connection into idle pool */
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
		printf("upstream read fail %d\n", read_len);
		return H2D_ERROR;
	}
	if (read_len > 0) { /* update timer */
		loop_stream_set_timeout(upc->loop_stream,
				upc->address->upstream->recv_timeout * 1000);
	}

	int ret_len = buf_pos - (uint8_t *)buffer + read_len;
	return ret_len == 0 ? H2D_AGAIN : ret_len;
}
void h2d_upstream_connection_read_notfinish(struct h2d_upstream_connection *upc,
		void *buffer, int buf_len)
{
	if (buf_len == 0) {
		return;
	}
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
		upc->address->stats.connected += 1;
		upc->address->stats.connect_acc_ms += wuy_time_ms() - upc->create_time;
		upc->create_time = 0;
	}

	int write_len = loop_stream_write(upc->loop_stream, data, data_len);
	if (write_len < 0) {
		printf("upstream write fail %d\n", write_len);
		return H2D_ERROR;
	}
	if (write_len != data_len) { /* blocking happens */
		printf(" !!! upstream write block!!! %d %d\n", write_len, data_len);
		return H2D_ERROR;
	}

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

bool h2d_upstream_address_is_pickable(struct h2d_upstream_address *address)
{
	if (address->down_time == 0) {
		return true;
	}
	if (h2d_upstream_is_active_healthcheck(address->upstream)) {
		return false;
	}
	if (time(NULL) < address->down_time + address->upstream->healthcheck.interval) {
		return false;
	}
	/* at most one connection is allowed in healthcheck */
	return wuy_list_empty(&address->active_head);
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

	conf->loadbalance->update(conf);
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

bool h2d_upstream_conf_resolve_init(struct h2d_upstream_conf *conf);
static bool h2d_upstream_conf_post(void *data)
{
	struct h2d_upstream_conf *conf = data;

	if (conf->hostnames == NULL) {
		return true;
	}

	if ((conf->healthcheck.req_len == 0) != (conf->healthcheck.resp_len == 0)) {
		printf("healthcheck request/response must be set both or neigther\n");
		return false;
	}

	conf->stats = wuy_shmem_alloc(sizeof(struct h2d_upstream_stats));

	wuy_list_init(&conf->address_head);
	wuy_list_init(&conf->deleted_address_defer);
	wuy_list_init(&conf->down_head);

	if (wuy_cflua_is_function_set(conf->dynamic.get_name)) {
		conf->dynamic.dict = wuy_dict_new_type(WUY_DICT_KEY_STRING,
				offsetof(struct h2d_upstream_conf, name),
				offsetof(struct h2d_upstream_conf, dynamic.dict_node));
	}

	if (conf->ssl_enable) {
		conf->ssl_ctx = h2d_ssl_ctx_new_client();
	}

	if (!h2d_upstream_conf_resolve_init(conf)) {
		return false;
	}

	if (!h2d_upstream_conf_loadbalance_select(conf)) {
		return false;
	}

	if (conf->name == NULL) {
		conf->name = conf->hostnames[0].name;
	}

	wuy_list_append(&h2d_upstream_list, &conf->list_node);

	return true;
}

static void h2d_upstream_conf_stats(struct h2d_upstream_conf *conf, wuy_json_ctx_t *json)
{
	wuy_json_new_object(json);

	wuy_json_object_string(json, "name", conf->name);

	struct h2d_upstream_stats *stats = conf->stats;
	wuy_json_object_int(json, "total", atomic_load(&stats->total));
	wuy_json_object_int(json, "reuse", atomic_load(&stats->reuse));
	wuy_json_object_int(json, "retry", atomic_load(&stats->retry));
	wuy_json_object_int(json, "pick_fail", atomic_load(&stats->pick_fail));

	wuy_json_object_int(json, "worker_pid", getpid());
	wuy_json_object_array(json, "worker_addresses");
	struct h2d_upstream_address *address;
	wuy_list_iter_type(&conf->address_head, address, upstream_node) {
		wuy_json_array_object(json);
		wuy_json_object_string(json, "name", address->name);
		wuy_json_object_int(json, "down_time", address->down_time);
		wuy_json_object_int(json, "create_time", address->stats.create_time);
		wuy_json_object_int(json, "down", address->stats.down);
		wuy_json_object_int(json, "pick", address->stats.pick);
		wuy_json_object_int(json, "reuse", address->stats.reuse);
		wuy_json_object_int(json, "connected", address->stats.connected);
		wuy_json_object_int(json, "connect_acc_ms", address->stats.connect_acc_ms);
		wuy_json_object_close(json);
	}
	wuy_json_array_close(json); /* end of worker_addresses[] */

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

static struct wuy_cflua_command h2d_upstream_dynamic_commands[] = {
	{	.name = "get_name",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_upstream_conf, dynamic.get_name),
	},
	{	.name = "get_conf",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_upstream_conf, dynamic.get_conf),
	},
	{	.name = "is_name_blocking",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct h2d_upstream_conf, dynamic.is_name_blocking),
	},
	{ NULL },
};
static struct wuy_cflua_command h2d_upstream_healthcheck_commands[] = {
	{	.name = "interval",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream_conf, healthcheck.interval),
		.default_value.n = 60,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
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
		.u.table = &(struct wuy_cflua_table) { h2d_upstream_dynamic_commands },
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
	{	.name = "ssl_enable",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct h2d_upstream_conf, ssl_enable),
	},
	{	.name = "healthcheck",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) { h2d_upstream_healthcheck_commands },
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
static struct wuy_cflua_table h2d_upstream_sub_conf_table = {
	.commands = h2d_upstream_conf_commands,
	.size = 0,
	.post = h2d_upstream_conf_post,
	.no_default_value = true,
};

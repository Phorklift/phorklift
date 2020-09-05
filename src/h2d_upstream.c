#include "h2d_main.h"

static WUY_LIST(h2d_upstream_address_defer_list);

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

static void h2d_upstream_address_defer_free(void *data)
{
	struct h2d_upstream_address *address, *safe;
	wuy_list_iter_safe_type(&h2d_upstream_address_defer_list, address, safe, hostname_node) {
		if (!wuy_list_empty(&address->active_head) || wuy_list_node_linked(&address->down_node)) {
			continue;
		}
		wuy_list_delete(&address->hostname_node);
		free(address);
	}
}
void h2d_upstream_address_delete(struct h2d_upstream_address *address)
{
	wuy_list_delete(&address->hostname_node);
	wuy_list_delete(&address->upstream_node);

	struct h2d_upstream_connection *upc;
	while (wuy_list_pop_type(&address->idle_head, upc, list_node)) {
		h2d_upstream_connection_close(upc);
	}

	wuy_list_append(&h2d_upstream_address_defer_list, &address->hostname_node);
}

void h2d_upstream_address_add(struct h2d_upstream_conf *upstream,
		struct h2d_upstream_hostname *hostname, struct sockaddr *sockaddr,
		struct h2d_upstream_address *before)
{
	struct h2d_upstream_address *address = calloc(1, sizeof(struct h2d_upstream_address));

	switch (sockaddr->sa_family) {
	case AF_INET:
		address->sockaddr.sin = *((struct sockaddr_in *)sockaddr);
		if (hostname->port != 0) {
			address->sockaddr.sin.sin_port = htons(hostname->port);
		}
		break;

	case AF_INET6:
		address->sockaddr.sin6 = *((struct sockaddr_in6 *)sockaddr);
		if (hostname->port != 0) {
			address->sockaddr.sin6.sin6_port = htons(hostname->port);
		}
		break;

	case AF_UNIX:
		address->sockaddr.sun = *((struct sockaddr_un *)sockaddr);
		break;

	default:
		printf("sa_family: %d\n", sockaddr->sa_family);
		abort();
	}

	wuy_list_init(&address->idle_head);
	wuy_list_init(&address->active_head);
	address->upstream = upstream;
	address->weight = hostname->weight;

	if (before != NULL) {
		wuy_list_add_before(&before->upstream_node, &address->upstream_node);
		wuy_list_add_before(&before->hostname_node, &address->hostname_node);
	} else {
		wuy_list_append(&upstream->address_head, &address->upstream_node);
		wuy_list_append(&hostname->address_head, &address->hostname_node);
	}
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

	char tmpbuf[100];
	wuy_sockaddr_ntop(&address->sockaddr.s, tmpbuf, sizeof(tmpbuf));
	printf("pick %s\n", tmpbuf);

	/* try to reuse */
	struct h2d_upstream_connection *upc;
	if (wuy_list_pop_type(&address->idle_head, upc, list_node)) {
		wuy_list_append(&address->active_head, &upc->list_node);
		address->idle_num--;
		atomic_fetch_add(&upstream->stats->reuse, 1);
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

static int h2d_upstream_do_generate_response_headers(struct h2d_request *r,
		struct h2d_upstream_ctx *ctx, parse_f parse)
{
	if (!ctx->has_sent_request) {
		if (h2d_upstream_connection_write_blocked(ctx->upc)) {// remove this check if h2d_upstream_connection_write() can return H2D_AGAIN
			return H2D_AGAIN;
		}
		int ret = h2d_upstream_connection_write(ctx->upc, ctx->req_buf, ctx->req_len);
		if (ret != H2D_OK) {
			return ret;
		}
		ctx->has_sent_request = true;
	}

	char buffer[4096];
	int read_len = h2d_upstream_connection_read(ctx->upc, buffer, sizeof(buffer));
	if (read_len < 0) {
		return read_len;
	}

	bool is_done;
	int proc_len = parse(r, buffer, read_len, &is_done);
	if (proc_len < 0) {
		return H2D_ERROR;
	}
	if (!is_done) {
		// TODO read again
		printf("too long response header\n");
		return H2D_ERROR;
	}

	h2d_upstream_connection_read_notfinish(ctx->upc, buffer + proc_len, read_len - proc_len);
	return H2D_OK;
}

static bool h2d_upstream_status_code_retry(struct h2d_request *r,
		struct h2d_upstream_conf *upstream)
{
	if (upstream->retry_status_codes == NULL) {
		return false;
	}
	for (int *p = upstream->retry_status_codes; *p != 0; p++) {
		if (r->resp.status_code == *p) {
			printf("debug retry_status_codes hit: %d\n", *p);
			return true;
		}
	}
	return false;
}

/* wrapper of generate_response_headers with retry */
int h2d_upstream_generate_response_headers(struct h2d_request *r,
		struct h2d_upstream_ctx *ctx, parse_f parse)
{
	struct h2d_upstream_conf *upstream = ctx->upc->address->upstream;

	while (1) {
		int ret = h2d_upstream_do_generate_response_headers(r, ctx, parse);
		if (ret == H2D_AGAIN) {
			return ret;
		}
		if (ret == H2D_OK && !h2d_upstream_status_code_retry(r, upstream)) {
			free(ctx->req_buf);
			ctx->req_buf = NULL;
			return H2D_OK;
		}

		/* increase connection's address fails */
		h2d_upstream_connection_fail(ctx->upc);

		/* retry */
		printf("retry %d %d\n", ctx->retries, upstream->max_retries);
		if (ctx->retries < 0 || ++ctx->retries >= upstream->max_retries) {
			return ret;
		}

		h2d_request_reset_response(r);

		ctx->upc = h2d_upstream_retry_connection(ctx->upc);
		if (ctx->upc == NULL) {
			return WUY_HTTP_500;
		}
		ctx->has_sent_request = false;
	}
}

void h2d_upstream_ctx_free(struct h2d_upstream_ctx *ctx)
{
	free(ctx->req_buf);
	if (ctx->upc != NULL) {
		h2d_upstream_release_connection(ctx->upc);
	}
}

void h2d_upstream_init(void)
{
	loop_idle_add(h2d_loop, h2d_upstream_address_defer_free, NULL);
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

extern struct h2d_upstream_loadbalance h2d_upstream_loadbalance_hash;
extern struct h2d_upstream_loadbalance h2d_upstream_loadbalance_roundrobin;
static struct h2d_upstream_loadbalance *
h2d_upstream_conf_loadbalance_select(struct h2d_upstream_conf *conf)
{
	/* We have 2 loadbalances now, roundrobin and hash.
	 * Use hash if conf->hash is set, otherwise roundrobin. */
	if (wuy_cflua_is_function_set(conf->hash.key)) {
		return &h2d_upstream_loadbalance_hash;
	} else {
		return &h2d_upstream_loadbalance_roundrobin;
	}
}

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
	wuy_list_init(&conf->down_head);

	if (conf->ssl_enable) {
		conf->ssl_ctx = h2d_ssl_ctx_new_client();
	}

	bool need_resolved = false;
	for (int i = 0; conf->hostnames[i].name != NULL; i++) {
		struct h2d_upstream_hostname *hostname = &conf->hostnames[i];

		wuy_list_init(&hostname->address_head);

		/* parse weight, marked by # */
		char *wstr = strchr(hostname->name, '#');
		if (wstr != NULL) {
			*wstr++ = '\0';
			hostname->weight = atof(wstr);
			if (hostname->weight == 0) {
				printf("invalid weight of %s %s", hostname->name, wstr);
				return false;
			}
		}

		/* it's static address, no need resolve */
		struct sockaddr sockaddr;
		if (wuy_sockaddr_pton(hostname->name, &sockaddr, conf->default_port)) {
			hostname->need_resolved = false;
			hostname->port = 0;
			h2d_upstream_address_add(conf, hostname, &sockaddr, NULL);
			conf->address_num++;
			continue;
		}

		/* it's hostname, resolve it */
		need_resolved = true;
		hostname->need_resolved = true;
		hostname->port = conf->default_port;

		/* parse the port */
		char *pport = strchr(hostname->name, ':');
		if (pport != NULL) {
			hostname->port = atoi(pport + 1);
			if (hostname->port == 0) {
				printf("invalid port %s\n", hostname->name);
				return false;
			}
			*pport = '\0';
		}

		/* resolve the hostname */
		int length;
		uint8_t *buffer = h2d_resolver_hostname(hostname->name, &length);
		if (buffer == NULL) {
			printf("resolve fail %s\n", hostname->name);
			return false;
		}

		uint8_t *p = buffer;
		while (p < buffer + length) {
			struct sockaddr *sa = (struct sockaddr *)p;
			h2d_upstream_address_add(conf, hostname, sa, NULL);
			p += wuy_sockaddr_size(sa);
			conf->address_num++;
		}

		free(buffer);
	}

	if (conf->address_num == 0) {
		printf("no address for upstream\n");
		return false;
	}

	/* resolve stream */
	if (need_resolved && conf->resolve_interval > 0) {
		conf->resolve_last = time(NULL);
	}

	/* loadbalance */
	conf->loadbalance = h2d_upstream_conf_loadbalance_select(conf);
	conf->loadbalance->update(conf);

	return true;
}

int h2d_upstream_conf_stats(void *data, char *buf, int len)
{
	struct h2d_upstream_conf *conf = data;
	struct h2d_upstream_stats *stats = conf->stats;
	if (stats == NULL) {
		return 0;
	}
	return snprintf(buf, len, "upstream: %d %d %d %d\n",
			atomic_load(&stats->total),
			atomic_load(&stats->reuse),
			atomic_load(&stats->retry),
			atomic_load(&stats->pick_fail));
}

static struct wuy_cflua_command h2d_upstream_hash_commands[] = {
	{	.type = WUY_CFLUA_TYPE_FUNCTION,
		.flags = WUY_CFLUA_FLAG_UNIQ_MEMBER,
		.offset = offsetof(struct h2d_upstream_conf, hash.key),
	},
	{	.name = "address_vnodes",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream_conf, hash.address_vnodes),
		.default_value.n = 100,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{ NULL }
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

	/* loadbalances */
	{	.name = "hash",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) { h2d_upstream_hash_commands },
	},
	{ NULL }
};

struct wuy_cflua_table h2d_upstream_conf_table = {
	.commands = h2d_upstream_conf_commands,
	.post = h2d_upstream_conf_post,
};

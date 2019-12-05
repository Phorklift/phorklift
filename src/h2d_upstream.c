#include "h2d_main.h"

struct h2d_upstream {
	/* configrations */
	const char		*address;
	int			recv_buffer_size;
	int			send_buffer_size;
	int			idle_max;
	int			default_port;
	int			read_timeout; // read or recv?
	int			write_timeout;
	int			idle_timeout;
	bool			ssl_enable;

	int			refers;

	/* run time */
	struct sockaddr		sockaddr;
	int			idle_num;
	wuy_list_t		idle_head;
	wuy_list_t		active_head;
};


static wuy_pool_t *h2d_upstream_connection_pool;
static SSL_CTX *h2d_upstream_ssl_ctx;
static WUY_LIST(h2d_upstream_connection_defer_list);


/* loop_stream ops */

static void h2d_upstream_on_readable(loop_stream_t *s)
{
	struct h2d_upstream_connection *upc = loop_stream_get_app_data(s);
	if (upc->request != NULL) {
		h2d_request_active(upc->request);
	}
}

/* XXX different with h2d_connection_write(), which need caller put data into c->send_buffer, and call flush.
 * should make them same?
 * */
int h2d_upstream_connection_write(struct h2d_upstream_connection *upc, void *data, int data_len)
{
	if (upc->send_buffer != NULL) { // TODO
		printf("!!!!!!!!!!!!!! errrrrrrrrrrrrrrrror\n");
		return -1;
		/*
		if (upc->send_buf_len + data_len > upc->upstream->send_buffer_size) {
			printf("!!!!!!!!!!!!!! errrrrrrrrrrrrrrrror\n");
			return -1;
		}

		memcpy(upc->send_buffer + upc->send_buf_len, data, data_len);
		upc->send_buf_len += data_len;
		*/
	}

	int write_len = loop_stream_write(upc->loop_stream, data, data_len);
	if (write_len < 0) {
		return write_len;
	}
	if (write_len < data_len) {
		if (upc->send_buffer == NULL) {
			upc->send_buffer = malloc(upc->upstream->send_buffer_size);
			upc->send_buf_len = 0;
		}
		memcpy(upc->send_buffer, (char *)data + write_len, data_len - write_len);
		upc->send_buf_len = data_len - write_len;
	}
	return data_len;
}

static void h2d_upstream_on_writable(loop_stream_t *s)
{
	struct h2d_upstream_connection *upc = loop_stream_get_app_data(s);
	if (upc->send_buffer == NULL) {
		return;
	}

	int len = loop_stream_write(s, upc->send_buffer, upc->send_buf_len);
	if (len <= 0) {
		return;
	}

	if (len != upc->send_buf_len) { // TODO
		printf("!!!!!!!!!!!!!! errrrrrrrrrrrrrrrror\n");
		return;
	}

	free(upc->send_buffer);
	upc->send_buffer = NULL;
	upc->send_buf_len = 0;
}

static void h2d_upstream_on_close(loop_stream_t *s, const char *reason, int err)
{
	printf("upstream on close: %s\n", reason);

	struct h2d_upstream_connection *upc = loop_stream_get_app_data(s);
	struct h2d_request *r = upc->request;
	if (r != NULL && !h2d_request_is_closed(r)) {
		// TODO tmp code here
		http2_make_frame_body(r->h2s, r->c->send_buf_pos, 0, true);
		r->c->send_buf_pos += HTTP2_FRAME_HEADER_SIZE;
		h2d_connection_flush(r->c);
		h2d_request_close(r);
	}

	// TODO upstream->on_close()
	h2d_upstream_release_connection(upc);
}
static loop_stream_ops_t h2d_upstream_ops = {
	.on_readable = h2d_upstream_on_readable,
	.on_writable = h2d_upstream_on_writable,
	.on_close = h2d_upstream_on_close,
};

struct h2d_upstream_connection *h2d_upstream_get_connection(struct h2d_upstream *upstream)
{
	printf(" === get_conn: %d %p %d\n", wuy_list_empty(&upstream->idle_head), upstream, upstream->idle_num);
	if (!wuy_list_empty(&upstream->idle_head)) {
		wuy_list_node_t *node = wuy_list_first(&upstream->idle_head);
		wuy_list_delete(node);
		wuy_list_append(&upstream->active_head, node);
		upstream->idle_num--;
		return wuy_containerof(node, struct h2d_upstream_connection, list_node);
	}

	int fd = wuy_tcp_connect(&upstream->sockaddr);
	if (fd < 0) {
		return NULL;
	}

	loop_stream_t *s = loop_stream_new(h2d_loop, fd, &h2d_upstream_ops);
	if (s == NULL) {
		return NULL;
	}

	if (upstream->ssl_enable) {
		SSL *ssl = SSL_new(h2d_upstream_ssl_ctx);
		SSL_set_fd(ssl, loop_stream_fd(s));
		SSL_set_connect_state(ssl);
		loop_stream_set_ssl(s, ssl);
	}

	struct h2d_upstream_connection *upc = wuy_pool_alloc(h2d_upstream_connection_pool);
	upc->upstream = upstream;
	upc->loop_stream = s;
	wuy_list_append(&upstream->active_head, &upc->list_node);
	loop_stream_set_app_data(s, upc);

	return upc;
}

void h2d_upstream_release_connection(struct h2d_upstream_connection *upc)
{
	struct h2d_upstream *upstream = upc->upstream;
	loop_stream_t *s = upc->loop_stream;

	if (s == NULL) { /* has been closed */
		return;
	}

	if (upc->send_buffer != NULL) {
		free(upc->send_buffer);
		upc->send_buffer = NULL;
		upc->send_buf_len = 0;
	}

	/* close it */
	if (loop_stream_is_closed(s) || upstream->idle_num >= upstream->idle_max || upc->request == NULL) {
		loop_stream_close(s);
		upc->loop_stream = NULL;
		wuy_list_delete(&upc->list_node);
		wuy_list_append(&h2d_upstream_connection_defer_list, &upc->list_node);
		if (upc->request == NULL) {
			upstream->idle_num--;
		}
		return;
	}

	/* put it to idle pool to reuse */
	upstream->idle_num++;
	upc->request = NULL;
	wuy_list_delete(&upc->list_node);
	wuy_list_append(&upstream->idle_head, &upc->list_node);
}
static void h2d_upstream_connection_defer_free(void *data)
{
	wuy_list_node_t *node, *safe;
	wuy_list_iter_safe(&h2d_upstream_connection_defer_list, node, safe) {
		wuy_list_delete(node);
		wuy_pool_free(wuy_containerof(node, struct h2d_upstream_connection, list_node));
	}
}

void h2d_upstream_init(void)
{
	h2d_upstream_ssl_ctx = SSL_CTX_new(SSLv23_client_method());
	SSL_CTX_set_ecdh_auto(h2d_upstream_ssl_ctx, 1);

	h2d_upstream_connection_pool = wuy_pool_new_type(struct h2d_upstream_connection);

	loop_idle_add(h2d_loop, h2d_upstream_connection_defer_free, NULL);
}


/* configration */

bool h2d_upstream_conf_is_enable(struct h2d_upstream *conf)
{
	return conf && conf->address && conf->address[0] != '\0';
}

static bool h2d_upstream_conf_post(void *data)
{
	struct h2d_upstream *conf = data;

	if (!h2d_upstream_conf_is_enable(conf)) {
		return true;
	}
	if (conf->refers > 0) {
		return true;
	}

	if (!wuy_sockaddr_pton(conf->address, &conf->sockaddr, conf->default_port)) {
		printf("invalid upstream address: %s\n", conf->address);
		return false;
	}

	wuy_list_init(&conf->idle_head);
	wuy_list_init(&conf->active_head);

	conf->refers++;
	return true;
}

static void h2d_upstream_conf_cleanup(void *data)
{
}

static struct wuy_cflua_command h2d_upstream_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_upstream, address),
		.flags = WUY_CFLUA_FLAG_UNIQ_MEMBER,
	},
	{	.name = "idle_max",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream, idle_max),
	},
	{	.name = "recv_buffer_size",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream, recv_buffer_size),
	},
	{	.name = "send_buffer_size",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream, send_buffer_size),
	},
	{	.name = "default_port",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream, default_port),
	},
	{	.name = "ssl_enable",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct h2d_upstream, ssl_enable),
	},
	{ NULL }
};

struct wuy_cflua_table h2d_upstream_conf_table = {
	.commands = h2d_upstream_conf_commands,
	.size = sizeof(struct h2d_upstream),
	.post = h2d_upstream_conf_post,
	.cleanup = h2d_upstream_conf_cleanup,
};

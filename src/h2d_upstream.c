#include <openssl/ssl.h>
#include "h2d_main.h"

static SSL_CTX *h2d_upstream_ssl_ctx;

static wuy_pool_t *h2d_upstream_connection_pool;
static WUY_LIST(h2d_upstream_connection_defer_list);


static void h2d_upstream_on_active(loop_stream_t *s)
{
	struct h2d_upstream_connection *upc = loop_stream_get_app_data(s);
	if (upc->request != NULL) {
		h2d_request_active(upc->request);
	}
}
static void h2d_upstream_on_close(loop_stream_t *s, const char *reason, int err)
{
	printf("upstream on close: %s\n", reason);

	struct h2d_upstream_connection *upc = loop_stream_get_app_data(s);
	if (upc->request != NULL) {
		h2d_request_response_body_finish(upc->request);
	}

	// TODO upstream->on_close()
	h2d_upstream_release_connection(upc);
}
static loop_stream_ops_t h2d_upstream_ops = {
	.on_readable = h2d_upstream_on_active,
	.on_writable = h2d_upstream_on_active,
	.on_close = h2d_upstream_on_close,
};


struct h2d_upstream_connection *
h2d_upstream_get_connection(struct h2d_upstream_conf *upstream)
{
	struct h2d_upstream_address *address = &upstream->rr_addresses[upstream->rr_index++];
	if (upstream->rr_index == wuy_array_count(&upstream->addresses)) {
		upstream->rr_index = 0;
	}

	atomic_fetch_add(&upstream->stats->total, 1);

	if (!wuy_list_empty(&address->idle_head)) {
		wuy_list_node_t *node = wuy_list_first(&address->idle_head);
		wuy_list_delete(node);
		wuy_list_append(&address->active_head, node);
		address->idle_num--;
		atomic_fetch_add(&upstream->stats->reuse, 1);
		return wuy_containerof(node, struct h2d_upstream_connection, list_node);
	}

	errno = 0;
	int fd = wuy_tcp_connect(&address->sockaddr);
	if (fd < 0) {
		return NULL;
	}

	loop_stream_t *s = loop_stream_new(h2d_loop, fd, &h2d_upstream_ops, errno == EINPROGRESS);
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
	upc->address = address;
	upc->loop_stream = s;
	wuy_list_append(&address->active_head, &upc->list_node);
	loop_stream_set_app_data(s, upc);

	return upc;
}

void h2d_upstream_release_connection(struct h2d_upstream_connection *upc)
{
	struct h2d_upstream_address *address = upc->address;
	loop_stream_t *s = upc->loop_stream;

	if (s == NULL) { /* has been closed */
		return;
	}

	wuy_list_t *move_to;
	if (loop_stream_is_closed(s) || upc->request == NULL /* idle */
			|| upc->preread_buf != NULL /* with un-processed data */
			|| address->idle_num >= 10) {
		/* close it */
		loop_stream_close(s);
		upc->loop_stream = NULL;
		free(upc->preread_buf);
		upc->preread_buf = NULL;
		move_to = &h2d_upstream_connection_defer_list;
		if (upc->request == NULL) {
			address->idle_num--;
		}

	} else {
		/* put it to idle pool to reuse */
		address->idle_num++;
		upc->request = NULL;
		move_to = &address->idle_head;
	}

	wuy_list_delete(&upc->list_node);
	wuy_list_append(move_to, &upc->list_node);
}
static void h2d_upstream_connection_defer_free(void *data)
{
	wuy_list_node_t *node, *safe;
	wuy_list_iter_safe(&h2d_upstream_connection_defer_list, node, safe) {
		wuy_list_delete(node);
		wuy_pool_free(wuy_containerof(node, struct h2d_upstream_connection, list_node));
	}
}

int h2d_upstream_connection_read(struct h2d_upstream_connection *upc,
		void *buffer, int buf_len)
{
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
		return H2D_ERROR;
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
	if (loop_stream_is_write_blocked(upc->loop_stream)) {
		return H2D_AGAIN;
	}
	if (data == NULL) {
		return H2D_OK;
	}

	int write_len = loop_stream_write(upc->loop_stream, data, data_len);
	if (write_len < 0) {
		return H2D_ERROR;
	}
	if (write_len != data_len) { /* blocking happens */
		loop_stream_close(upc->loop_stream);
		return H2D_ERROR;
	}
	return H2D_OK;
}

void h2d_upstream_init(void)
{
	h2d_upstream_ssl_ctx = SSL_CTX_new(SSLv23_client_method());
	SSL_CTX_set_ecdh_auto(h2d_upstream_ssl_ctx, 1);

	h2d_upstream_connection_pool = wuy_pool_new_type(struct h2d_upstream_connection);

	loop_idle_add(h2d_loop, h2d_upstream_connection_defer_free, NULL);
}


/* configration */

static bool h2d_upstream_conf_post(void *data)
{
	struct h2d_upstream_conf *conf = data;

	if (!wuy_array_yet_init(&conf->addresses)) {
		return true;
	}

	conf->stats = wuy_shmem_alloc(sizeof(struct h2d_upstream_stats));

	conf->rr_addresses = calloc(wuy_array_count(&conf->addresses),
			sizeof(struct h2d_upstream_address));

	struct h2d_upstream_address *address = conf->rr_addresses;
	const char *addr;
	wuy_array_iter_ppval(&conf->addresses, addr) {

		if (!wuy_sockaddr_pton(addr, &address->sockaddr, conf->default_port)) {
			printf("invalid upstream address: %s\n", addr);
			return false;
		}
		address->idle_num = 0;
		wuy_list_init(&address->idle_head);
		wuy_list_init(&address->active_head);

		address++;
	}
	return true;
}

int h2d_upstream_conf_stats(void *data, char *buf, int len)
{
	struct h2d_upstream_conf *conf = data;
	struct h2d_upstream_stats *stats = conf->stats;
	if (stats == NULL) {
		return 0;
	}
	return snprintf(buf, len, "upstream: %d %d\n", atomic_load(&stats->total), atomic_load(&stats->reuse));
}

static struct wuy_cflua_command h2d_upstream_conf_commands[] = {
	{	.name = "idle_max",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream_conf, idle_max),
	},
	{	.name = "recv_buffer_size",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream_conf, recv_buffer_size),
	},
	{	.name = "send_buffer_size",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream_conf, send_buffer_size),
	},
	{	.name = "default_port",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream_conf, default_port),
	},
	{	.name = "ssl_enable",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct h2d_upstream_conf, ssl_enable),
	},
	{ NULL }
};

struct wuy_cflua_table h2d_upstream_conf_table = {
	.commands = h2d_upstream_conf_commands,
	.post = h2d_upstream_conf_post,
};

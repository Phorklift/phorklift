#include "h2d_main.h"

// TODO each upstream should has one ssl-ctx, for different ssl configs
static SSL_CTX *h2d_upstream_ssl_ctx;

static void h2d_upstream_connection_close(struct h2d_upstream_connection *upc)
{
	loop_stream_close(upc->loop_stream);
	upc->loop_stream = NULL;

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
		h2d_request_active(upc->request);
	} else { /* idle */
		h2d_upstream_connection_close(upc);
	}
}
static loop_stream_ops_t h2d_upstream_ops = {
	.on_readable = h2d_upstream_on_active,
	.on_writable = h2d_upstream_on_active,

	H2D_SSL_LOOP_STREAM_UNDERLYINGS,
};


struct h2d_upstream_connection *
h2d_upstream_get_connection(struct h2d_upstream_conf *upstream)
{
	struct h2d_upstream_address *address = &upstream->rr_addresses[upstream->rr_index++];
	if (upstream->rr_index == wuy_array_count(&upstream->addresses)) {
		upstream->rr_index = 0;
	}

	atomic_fetch_add(&upstream->stats->total, 1);

	struct h2d_upstream_connection *upc;
	if (wuy_list_pop_type(&address->idle_head, upc, list_node)) {
		wuy_list_append(&address->active_head, &upc->list_node);
		address->idle_num--;
		atomic_fetch_add(&upstream->stats->reuse, 1);
		return upc;
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
		h2d_ssl_stream_set(s, h2d_upstream_ssl_ctx, false);
	}

	upc = malloc(sizeof(struct h2d_upstream_connection));
	bzero(upc, sizeof(struct h2d_upstream_connection));
	upc->address = address;
	upc->loop_stream = s;
	wuy_list_append(&address->active_head, &upc->list_node);
	loop_stream_set_app_data(s, upc);

	return upc;
}

void h2d_upstream_release_connection(struct h2d_upstream_connection *upc)
{
	assert(upc->request != NULL);
	assert(upc->loop_stream != NULL);

	/* close the connection */
	if (loop_stream_is_closed(upc->loop_stream) || upc->preread_buf != NULL) {
		h2d_upstream_connection_close(upc);
		return;
	}

	/* put the connection into idle pool */
	struct h2d_upstream_address *address = upc->address;
	if (address->idle_num > 10) {
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

	// TODO loop_stream_set_keepalive()
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
	assert(upc->loop_stream != NULL);

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
		printf(" !!! upstream write block!!! %d %d\n", write_len, data_len);
		h2d_upstream_connection_close(upc);
		return H2D_ERROR;
	}
	return H2D_OK;
}

void h2d_upstream_init(void)
{
	h2d_upstream_ssl_ctx = h2d_ssl_ctx_new_client();
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

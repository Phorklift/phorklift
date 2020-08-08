#include "h2d_main.h"

/* for getaddrinfo() */
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

// TODO each upstream should has one ssl-ctx, for different ssl configs
static SSL_CTX *h2d_upstream_ssl_ctx;

static void h2d_upstream_address_free(struct h2d_upstream_address *address)
{
	if (wuy_list_empty(&address->active_head) && wuy_list_empty(&address->idle_head)) {
		free(address);
	}
}

static void h2d_upstream_connection_close(struct h2d_upstream_connection *upc)
{
	loop_stream_close(upc->loop_stream);
	upc->loop_stream = NULL;

	wuy_list_delete(&upc->list_node);

	struct h2d_upstream_address *address = upc->address;
	if (upc->request == NULL) {
		address->idle_num--;
	}

	free(upc->preread_buf);
	free(upc);

	/* free address if it was deleted */
	if (address->deleted) {
		h2d_upstream_address_free(address);
	}
}

static void h2d_upstream_address_delete(struct h2d_upstream_address *address)
{
	wuy_list_delete(&address->hostname_node);
	wuy_list_delete(&address->upstream_node);
	h2d_upstream_address_free(address);
}

static void h2d_upstream_lb_rr_routine(struct h2d_upstream_conf *upstream)
{
	int num = 0;
	bool any_deleted = false;

	struct h2d_upstream_address *address, *safe;
	wuy_list_iter_safe_type(&upstream->address_head, address, safe, upstream_node) {
		if (address->deleted) {
			any_deleted = true;
			h2d_upstream_address_delete(address);
		} else {
			num++;
		}
	}

	if (num == upstream->rr_total && !any_deleted) { /* no change */
		return;
	}

	upstream->rr_index = 0;
	upstream->rr_total = num;

	upstream->rr_addresses = realloc(upstream->rr_addresses,
			sizeof(struct h2d_upstream_address *) * num);

	int i = 0;
	wuy_list_iter_type(&upstream->address_head, address, upstream_node) {
		upstream->rr_addresses[i++] = address;
	}
}

static void h2d_upstream_do_resolve(struct h2d_upstream_conf *upstream)
{
	/* pick one hostname */
	char *name = NULL;
	while (1) {
		struct h2d_upstream_hostname *hostname = &upstream->hostnames[upstream->resolve_index++];
		if (hostname->name != NULL || hostname->need_resolved) {
			name = hostname->name;
			break;
		}
	}

	/* finish resolve */
	if (name == NULL) {
		upstream->resolve_last = time(NULL);
		upstream->resolve_index = 0;
		h2d_upstream_lb_rr_routine(upstream);
		return;
	}

	/* send resolve query */
	struct h2d_resolver_query query;
	int name_len = strlen(name);
	assert(name_len < sizeof(query.hostname));
	memcpy(query.hostname, name, name_len);
	query.expire_after = upstream->resolve_interval;
	loop_stream_write(upstream->resolve_stream, &query,
			sizeof(query.expire_after) + name_len);
}

static void h2d_upstream_conf_address_add(struct h2d_upstream_conf *upstream,
		struct h2d_upstream_hostname *hostname, struct sockaddr *sockaddr,
		struct h2d_upstream_address *before)
{
	struct h2d_upstream_address *address = malloc(sizeof(struct h2d_upstream_address));

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

	address->deleted = false;
	address->idle_num = 0;
	wuy_list_init(&address->idle_head);
	wuy_list_init(&address->active_head);
	address->upstream = upstream;

	if (before != NULL) {
		wuy_list_add_before(&before->upstream_node, &address->upstream_node);
		wuy_list_add_before(&before->hostname_node, &address->hostname_node);
	} else {
		wuy_list_append(&upstream->address_head, &address->upstream_node);
		wuy_list_append(&hostname->address_head, &address->hostname_node);
	}
}

static void h2d_upstream_address_log(struct h2d_upstream_hostname *hostname,
		struct sockaddr *sa, const char *op)
{
	char addrbuf[100];
	wuy_sockaddr_ntop(sa, addrbuf, sizeof(addrbuf));
	printf(" upstream resolve: %s %s %s\n", hostname->name, op, addrbuf);
}

static int h2d_upstream_resolve_on_read(loop_stream_t *s, void *data, int len)
{
	struct h2d_upstream_conf *upstream = loop_stream_get_app_data(s);
	struct h2d_upstream_hostname *hostname = &upstream->hostnames[upstream->resolve_index-1];

	/* diff */
	uint8_t *p = data;
	uint8_t *end = p + len;
	wuy_list_node_t *node = wuy_list_first(&hostname->address_head);
	while (p < end && node != NULL) {
		struct h2d_upstream_address *address = wuy_containerof(node,
				struct h2d_upstream_address, hostname_node);

		struct sockaddr *newaddr = (struct sockaddr *)p;

		/* compare in the same way with h2d_resolver_addrcmp() */
		int cmp = wuy_sockaddr_addrcmp(newaddr, &address->sockaddr.s);

		if (cmp < 0) { /* new address */
			h2d_upstream_address_log(hostname, newaddr, "new");
			h2d_upstream_conf_address_add(upstream, hostname, newaddr, address);
			p += wuy_sockaddr_size(newaddr);

		} else if (cmp > 0) { /* delete address */
			h2d_upstream_address_log(hostname, &address->sockaddr.s, "delete");
			address->deleted = true;
			node = wuy_list_next(&hostname->address_head, node);

		} else {
			printf("matched\n");
			p += wuy_sockaddr_size(newaddr);
			node = wuy_list_next(&hostname->address_head, node);
		}
	}
	while (node != NULL) {
		struct h2d_upstream_address *address = wuy_containerof(node,
				struct h2d_upstream_address, hostname_node);
		h2d_upstream_address_log(hostname, &address->sockaddr.s, "delete2");
		address->deleted = true;
		node = wuy_list_next(&hostname->address_head, node);
	}
	while (p < end) {
		struct sockaddr *newaddr = (struct sockaddr *)p;
		h2d_upstream_address_log(hostname, newaddr, "new2");
		h2d_upstream_conf_address_add(upstream, hostname, newaddr, NULL);
		p += wuy_sockaddr_size(newaddr);
	}

	/* resolve next hostname */
	h2d_upstream_do_resolve(upstream);

	return len;
}
static loop_stream_ops_t h2d_upstream_resolve_ops = {
	.on_read = h2d_upstream_resolve_on_read,
};

static void h2d_upstream_try_resolve(struct h2d_upstream_conf *upstream)
{
	if (upstream->resolve_last == 0) {
		return;
	}

	if (upstream->resolve_stream == NULL) { /* init at first time */
		int fd = h2d_resolver_connect();
		upstream->resolve_stream = loop_stream_new(h2d_loop, fd, &h2d_upstream_resolve_ops, false);
		loop_stream_set_app_data(upstream->resolve_stream, upstream);
	}

	if (time(NULL) - upstream->resolve_last < upstream->resolve_interval) {
		return;
	}
	if (upstream->resolve_index != 0) { /* in processing already */
		return;
	}

	h2d_upstream_do_resolve(upstream);
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
	atomic_fetch_add(&upstream->stats->total, 1);

	h2d_upstream_try_resolve(upstream);

	struct h2d_upstream_address *address = upstream->rr_addresses[upstream->rr_index++];
	if (upstream->rr_index == upstream->rr_total) {
		upstream->rr_index = 0;
	}

	struct h2d_upstream_connection *upc;
	if (wuy_list_pop_type(&address->idle_head, upc, list_node)) {
		wuy_list_append(&address->active_head, &upc->list_node);
		address->idle_num--;
		atomic_fetch_add(&upstream->stats->reuse, 1);
		return upc;
	}

	errno = 0;
	int fd = wuy_tcp_connect(&address->sockaddr.s);
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

	upc = calloc(1, sizeof(struct h2d_upstream_connection));
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

	struct h2d_upstream_address *address = upc->address;

	/* close the connection */
	if (address->deleted || loop_stream_is_closed(upc->loop_stream) || upc->preread_buf != NULL) {
		h2d_upstream_connection_close(upc);
		return;
	}

	/* put the connection into idle pool */
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

	if (conf->hostnames == NULL) {
		return true;
	}

	conf->stats = wuy_shmem_alloc(sizeof(struct h2d_upstream_stats));

	wuy_list_init(&conf->address_head);

	bool need_resolved = false;
	for (int i = 0; conf->hostnames[i].name != NULL; i++) {
		struct h2d_upstream_hostname *hostname = &conf->hostnames[i];

		wuy_list_init(&hostname->address_head);

		/* it's IP */
		struct sockaddr sockaddr;
		if (wuy_sockaddr_pton(hostname->name, &sockaddr, conf->default_port)) {
			hostname->need_resolved = false;
			hostname->port = 0;
			h2d_upstream_conf_address_add(conf, hostname, &sockaddr, NULL);
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
			h2d_upstream_conf_address_add(conf, hostname, sa, NULL);
			p += wuy_sockaddr_size(sa);
		}

		free(buffer);
	}

	/* resolve stream */
	if (need_resolved && conf->resolve_interval > 0) {
		conf->resolve_last = time(NULL);
	}

	/* LB routine */
	h2d_upstream_lb_rr_routine(conf);

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
	{	.name = "resolve_interval",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream_conf, resolve_interval),
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

#include "h2d_main.h"

static void h2d_upstream_healthcheck_address(struct h2d_upstream_address *address);
static int h2d_upstream_healthcheck_on_read(loop_stream_t *s, void *data, int data_len)
{
	struct h2d_upstream_address *address = loop_stream_get_app_data(s);
	struct h2d_upstream_conf *upstream = address->upstream;

	int resp_len = upstream->healthcheck.resp_len;
	const char *resp_str = upstream->healthcheck.resp_str;

	bool ok;
	switch (resp_str[0]) {
	case '*':
		ok = true;
		break;
	case '=':
		resp_len--;
		resp_str++;
		if (data_len < resp_len) {
			return 0;
		}
		if (data_len > resp_len) {
			ok = false;
			break;
		}
		ok = memcmp(data, resp_str, resp_len) == 0;
		break;
	case '~': // TODO lua string.find()
		// ok = h2d_lua_string_match(data, resp_str+1);
		ok = true;
		break;
	default:
		if (data_len < resp_len) {
			return 0;
		}
		ok = memcmp(data, resp_str, resp_len) == 0;
	}

	if (ok) {
		if (address->healthchecks >= upstream->healthcheck.repeats) {
			printf("upstream address recover from active healthcheck\n");
			address->down_time = 0;
			wuy_list_del_if(&address->down_node);
		} else {
			h2d_upstream_healthcheck_address(address);
		}
	}

	loop_stream_close(s);
	return data_len;
}

static void h2d_upstream_healthcheck_on_writable(loop_stream_t *s)
{
	struct h2d_upstream_address *address = loop_stream_get_app_data(s);
	struct h2d_upstream_conf *upstream = address->upstream;

	int write_len = loop_stream_write(s, upstream->healthcheck.req_str,
			upstream->healthcheck.req_len);

	if (write_len == 0) { /* write blocks */
		loop_stream_set_timeout(s, upstream->send_timeout * 1000);
		return;
	}
	if (write_len == upstream->healthcheck.req_len) { /* write done, wait for response */
		loop_stream_set_timeout(s, upstream->recv_timeout * 1000);
		return;
	}

	/* neighter blocked nor finished */
	loop_stream_close(s);
}

static loop_stream_ops_t h2d_upstream_healthcheck_ops = {
	.on_read = h2d_upstream_healthcheck_on_read,
	.on_writable = h2d_upstream_healthcheck_on_writable,
	H2D_SSL_LOOP_STREAM_UNDERLYINGS,
};

static void h2d_upstream_healthcheck_address(struct h2d_upstream_address *address)
{
	loop_stream_t *s = loop_tcp_connect_sockaddr(h2d_loop, &address->sockaddr.s,
			&h2d_upstream_healthcheck_ops);
	if (s == NULL) {
		return;
	}

	if (address->upstream->ssl_enable) {
		h2d_ssl_stream_set(s, address->upstream->ssl_ctx, false);
	}

	loop_stream_set_app_data(s, address);

	address->healthchecks++; /* active healthcheck */

	h2d_upstream_healthcheck_on_writable(s);
}

void h2d_upstream_healthcheck(struct h2d_upstream_conf *upstream)
{
	time_t now = time(NULL);
	struct h2d_upstream_address *address, *safe;
	wuy_list_iter_safe_type(&upstream->down_head, address, safe, down_node) {
		if (address->deleted || address->down_time == 0) {
			/* deleted, or recovered because of all-down */
			wuy_list_delete(&address->down_node);
			continue;
		}
		if (now < address->down_time + upstream->healthcheck.interval) {
			// TODO make sure upstream->healthcheck.interval > 0
			break;
		}

		address->down_time = now;
		wuy_list_delete(&address->down_node);
		wuy_list_append(&upstream->down_head, &address->down_node);

		h2d_upstream_healthcheck_address(address);
	}
}

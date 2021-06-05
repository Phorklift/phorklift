#include "h2d_main.h"

#define _log(level, fmt, ...) h2d_log_level(upstream->log, level, \
		"upstream healthcheck: %s " fmt, address->name, ##__VA_ARGS__)

static void h2d_upstream_healthcheck_done(struct h2d_upstream_address *address,
		bool pass, const char *reason)
{
	struct h2d_upstream_conf *upstream = address->upstream;

	loop_stream_close(address->healthcheck.stream);
	address->healthcheck.stream = NULL;

	if (pass) {
		address->healthcheck.fails = 0;
		address->healthcheck.passes++;
		if (address->healthcheck.down_time != 0 && address->healthcheck.passes == upstream->healthcheck.passes) {
			_log(H2D_LOG_ERROR, "go up");
			address->healthcheck.down_time = 0;
		}
	} else {
		address->healthcheck.passes = 0;
		address->healthcheck.fails++;
		if (address->healthcheck.down_time == 0 && address->healthcheck.fails == upstream->healthcheck.fails) {
			_log(H2D_LOG_ERROR, "go down for %s", reason);
			atomic_fetch_add(&address->stats->healthcheck_down, 1);
			address->healthcheck.down_time = time(NULL);
		}
	}

	_log(H2D_LOG_DEBUG, "done, %s, %s. fails=%d, passes=%d", pass ? "pass" : "fail",
			reason, address->healthcheck.fails, address->healthcheck.passes);
}

static int h2d_upstream_healthcheck_on_read(loop_stream_t *s, void *data, int data_len)
{
	struct h2d_upstream_address *address = loop_stream_get_app_data(s);
	struct h2d_upstream_conf *upstream = address->upstream;

	int resp_len = upstream->healthcheck.resp_len;
	const char *resp_str = upstream->healthcheck.resp_str;

	bool pass;
	switch (resp_str[0]) {
	case '*':
		pass = true;
		break;
	case '=':
		resp_len--;
		resp_str++;
		if (data_len < resp_len) {
			return 0;
		}
		if (data_len > resp_len) {
			pass = false;
			break;
		}
		pass = memcmp(data, resp_str, resp_len) == 0;
		break;
	case '~':
		pass = wuy_luastr_find2(data, resp_str+1);
		break;
	default:
		if (data_len < resp_len) {
			return 0;
		}
		pass = memcmp(data, resp_str, resp_len) == 0;
	}

	h2d_upstream_healthcheck_done(address, pass, "compare response");

	return -1;
}

static void h2d_upstream_healthcheck_on_writable(loop_stream_t *s)
{
	struct h2d_upstream_address *address = loop_stream_get_app_data(s);
	struct h2d_upstream_conf *upstream = address->upstream;

	if (upstream->healthcheck.req_str == NULL) {
		h2d_upstream_healthcheck_done(address, true, NULL);
		return;
	}

	int write_len = loop_stream_write(s, upstream->healthcheck.req_str,
			upstream->healthcheck.req_len);

	if (write_len == 0) { /* write blocks */
		loop_stream_set_timeout(s, upstream->send_timeout * 1000);
		return;
	}
	if (write_len != upstream->healthcheck.req_len) {
		h2d_upstream_healthcheck_done(address, false, "send request");
		return;
	}

	/* write done, wait for response */
	loop_stream_set_timeout(s, upstream->recv_timeout * 1000);
}

static void h2d_upstream_healthcheck_on_close(loop_stream_t *s, enum loop_stream_close_reason reason)
{
	struct h2d_upstream_address *address = loop_stream_get_app_data(s);
	h2d_upstream_healthcheck_done(address, false, loop_stream_close_string(reason));
}

static loop_stream_ops_t h2d_upstream_healthcheck_ops = {
	.on_read = h2d_upstream_healthcheck_on_read,
	.on_writable = h2d_upstream_healthcheck_on_writable,
	.on_close = h2d_upstream_healthcheck_on_close,
	H2D_SSL_LOOP_STREAM_UNDERLYINGS,
};

static int64_t h2d_upstream_healthcheck_address_handler(int64_t at, void *data)
{
	struct h2d_upstream_address *address = data;
	struct h2d_upstream_conf *upstream = address->upstream;

	if (address->healthcheck.stream != NULL) {
		_log(H2D_LOG_INFO, "last not finish");
		goto out;
	}

	_log(H2D_LOG_DEBUG, "begin");

	loop_stream_t *s = loop_tcp_connect_sockaddr(h2d_loop,
			&address->sockaddr.s, &h2d_upstream_healthcheck_ops);
	if (s == NULL) {
		h2d_upstream_healthcheck_done(address, false, "connect");
		goto out;
	}

	if (address->upstream->ssl_enable) {
		h2d_ssl_stream_set(s, upstream->ssl_ctx, false);
	}

	address->healthcheck.stream = s;

	loop_stream_set_app_data(s, address);

	h2d_upstream_healthcheck_on_writable(s);
out:
	return address->upstream->healthcheck.interval * 1000;
}

void h2d_upstream_healthcheck_start(struct h2d_upstream_address *address)
{
	address->healthcheck.timer = loop_timer_new(h2d_loop,
			h2d_upstream_healthcheck_address_handler, address);

	loop_timer_set_after(address->healthcheck.timer, random() % 1000);
}

void h2d_upstream_healthcheck_stop(struct h2d_upstream_address *address)
{
	if (address->healthcheck.timer != NULL) {
		loop_timer_delete(address->healthcheck.timer);
	}
	if (address->healthcheck.stream != NULL) {
		loop_stream_close(address->healthcheck.stream);
	}
}

struct wuy_cflua_command h2d_upstream_healthcheck_commands[] = {
	{	.name = "interval",
		.description = "Set 0 to disable healthcheck.",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream_conf, healthcheck.interval),
		.default_value.n = 0,
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "fails",
		.description = "Mark an address as failure if it fails this times continuously.",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream_conf, healthcheck.fails),
		.default_value.n = 1,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "passes",
		.description = "Recover an address if it responses well this times continuously.",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream_conf, healthcheck.passes),
		.default_value.n = 3,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "request",
		.description = "Request string. If not set, connected is considered as success.",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_upstream_conf, healthcheck.req_str),
		.u.length_offset = offsetof(struct h2d_upstream_conf, healthcheck.req_len),
	},
	{	.name = "response",
		.description = "Response string used for comparison check. "
			"String `*` means accepting any response; "
			"leading `=` means exactly comparison; "
			"leading `~` means regex comparison in Lua's rule; "
			"otherwise, means prefix comparison.",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_upstream_conf, healthcheck.resp_str),
		.u.length_offset = offsetof(struct h2d_upstream_conf, healthcheck.resp_len),
	},
	{ NULL }
};

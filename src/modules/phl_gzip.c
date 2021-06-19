#include "phl_main.h"

#include <zlib.h>

struct phl_gzip_conf {
	int		level;
	int		window_bits;
	int		mem_level;
	int		min_length;

	wuy_cflua_function_t	filter;
};

struct phl_module phl_gzip_module;

static int phl_gzip_filter_response_headers(struct phl_request *r)
{
	struct phl_gzip_conf *conf = r->conf_path->module_confs[phl_gzip_module.index];
	if (conf->level == 0) {
		return H2D_OK;
	}
	if (r->resp.status_code != WUY_HTTP_200) {
		return H2D_OK;
	}
	if (r->resp.content_length <= conf->min_length) {
		return H2D_OK;
	}

	struct phl_header *h;
	phl_header_iter(&r->resp.headers, h) {
		if (strcasecmp(h->str, "Content-Encoding") == 0) {
			return H2D_OK;
		}
	}

	if (wuy_cflua_is_function_set(conf->filter) && phl_lua_call_boolean(r, conf->filter) != 1) {
		return H2D_OK;
	}

	/* enable gzip */

	r->resp.content_length = H2D_CONTENT_LENGTH_INIT,
	phl_header_add(&r->resp.headers, "Content-Encoding", 16, "gzip", 4, r->pool);

	z_streamp zs = wuy_pool_alloc(r->pool, sizeof(*zs));
	deflateInit2(zs, conf->level, Z_DEFLATED, conf->window_bits + 16,
			conf->mem_level, Z_DEFAULT_STRATEGY);

	r->module_ctxs[phl_gzip_module.index] = zs;
	return H2D_OK;
}

static int phl_gzip_filter_response_body(struct phl_request *r, uint8_t *data,
		int data_len, int buf_len, bool *p_is_last)
{
	z_streamp zs = r->module_ctxs[phl_gzip_module.index];
	if (zs == NULL) {
		return data_len;
	}

	zs->next_in = data;
	zs->avail_in = data_len;

	uint8_t out_buf[buf_len];
	zs->next_out = out_buf;
	zs->avail_out = buf_len;

	int ret = deflate(zs, *p_is_last ? Z_FINISH : Z_NO_FLUSH);
	if (ret != Z_STREAM_END) {
		phl_request_log(r, H2D_LOG_ERROR, "gzip: defalte() %d: "
				"in=%d out=%d, avail_in=%d avail_out=%d",
				ret, data_len, buf_len, zs->avail_in, zs->avail_out);
		return H2D_ERROR;
	}

	int out_len = buf_len - zs->avail_out;
	memcpy(data, out_buf, out_len);

	return out_len;
}

static void phl_gzip_ctx_free(struct phl_request *r)
{
	z_streamp zs = r->module_ctxs[phl_gzip_module.index];
	deflateEnd(zs);
}

/* configuration */

static struct wuy_cflua_command phl_gzip_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_INTEGER,
		.description = "Compress level. 0 is disable, 1 is fastest, and 9 is best compression.",
		.is_single_array = true,
		.offset = offsetof(struct phl_gzip_conf, level),
		.limits.n = WUY_CFLUA_LIMITS(0, 9),
	},
	{	.name = "window_bits",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_gzip_conf, window_bits),
		.limits.n = WUY_CFLUA_LIMITS(8, 15),
		.default_value.n = 15,
	},
	{	.name = "mem_level",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_gzip_conf, mem_level),
		.limits.n = WUY_CFLUA_LIMITS(1, 9),
		.default_value.n = 8,
	},
	{	.name = "min_length",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_gzip_conf, min_length),
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
		.default_value.n = 100,
	},
	{	.name = "filter",
		.description = "Return a boolean to indicate whether to compress.",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct phl_gzip_conf, filter),
	},
	{ NULL }
};

struct phl_module phl_gzip_module = {
	.name = "gzip",
	.command_path = {
		.name = "gzip",
		.description = "Gzip filter module.",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) {
			.commands = phl_gzip_conf_commands,
			.size = sizeof(struct phl_gzip_conf),
		}
	},

	.filters = {
		.response_headers = phl_gzip_filter_response_headers,
		.response_body = phl_gzip_filter_response_body,
	},
	.ctx_free = phl_gzip_ctx_free,
};

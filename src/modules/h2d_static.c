#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "h2d_main.h"

struct h2d_static_conf {
	const char	*dir_name;
	int		dirfd;

	const char	*index;

	struct h2d_log	*log;
};

struct h2d_static_ctx {
	int		fd;
	size_t		range;
};

struct h2d_module h2d_static_module;


/* content handlers */
static int h2d_static_generate_response_headers(struct h2d_request *r)
{
	struct h2d_static_conf *conf = r->conf_path->module_confs[h2d_static_module.index];

	time_t if_modified_since = 0;
	struct h2d_header *h;
	h2d_header_iter(&r->req.headers, h) {
		const char *name = h->str;
		const char *value = h2d_header_value(h);
		if (strcasecmp(name, "If-Modified-Since") == 0) {
			if_modified_since = wuy_http_date_parse(value);
		}
	}

	const char *filename = r->req.uri.path + 1;
	if (filename[0] == '\0') {
		// TODO /index.html
	}

	h2d_request_log_at(r, conf->log, H2D_LOG_DEBUG, "open file %s", filename);

	int fd = openat(conf->dirfd, filename, O_RDONLY);
	if (fd < 0) {
		h2d_request_log_at(r, conf->log, H2D_LOG_INFO, "error to open file %s %s",
				filename, strerror(errno));
		return WUY_HTTP_404;
	}

	struct stat st_buf;
	fstat(fd, &st_buf);

	h2d_header_add(&r->resp.headers, "Last-Modified", 13,
			wuy_http_date_make(st_buf.st_mtime),
			WUY_HTTP_DATE_LENGTH);

	h2d_request_log_at(r, conf->log, H2D_LOG_DEBUG, "check if-modified-since %ld %ld",
			if_modified_since, st_buf.st_mtime);
	if (if_modified_since == st_buf.st_mtime) {
		close(fd);
		return WUY_HTTP_304;
	}

	r->resp.status_code = WUY_HTTP_200;
	r->resp.content_length = st_buf.st_size;

	struct h2d_static_ctx *ctx = malloc(sizeof(struct h2d_static_ctx));
	ctx->fd = fd;
	r->module_ctxs[h2d_static_module.index] = ctx;

	return H2D_OK;
}
static int h2d_static_generate_response_body(struct h2d_request *r, uint8_t *buf, int len)
{
	struct h2d_static_conf *conf = r->conf_path->module_confs[h2d_static_module.index];
	struct h2d_static_ctx *ctx = r->module_ctxs[h2d_static_module.index];

	int ret = read(ctx->fd, buf, len);
	if (ret < 0) {
		h2d_request_log_at(r, conf->log, H2D_LOG_ERROR, "read fail %s", strerror(errno));
		return -1;
	}
	h2d_request_log_at(r, conf->log, H2D_LOG_DEBUG, "read file %ld", ret);
	return ret;
}

static void h2d_static_ctx_free(struct h2d_request *r)
{
	struct h2d_static_ctx *ctx = r->module_ctxs[h2d_static_module.index];
	close(ctx->fd);
	free(ctx);
}


/* configuration */

static bool h2d_static_conf_post(void *data)
{
	struct h2d_static_conf *conf = data;

	if (conf->dir_name == NULL) {
		return true;
	}

	conf->dirfd = open(conf->dir_name, O_RDONLY, O_DIRECTORY);
	if (conf->dirfd < 0) {
		printf("static: fail to open dir: %s\n", conf->dir_name);
		return false;
	}
	// printf("debug: open %s\n", conf->dir_name);

	return true;
}

static struct wuy_cflua_command h2d_static_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_static_conf, dir_name),
		.flags = WUY_CFLUA_FLAG_UNIQ_MEMBER,
	},
	{	.name = "index",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_static_conf, index),
		.default_value.s = "/index.html",
	},
	{	.name = "log",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_static_conf, log),
		.u.table = &h2d_log_conf_table,
	},
	{ NULL }
};

struct h2d_module h2d_static_module = {
	.name = "static",
	.command_path = {
		.name = "static",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = 0, /* reset later */
		.u.table = &(struct wuy_cflua_table) {
			.commands = h2d_static_conf_commands,
			.size = sizeof(struct h2d_static_conf),
			.post = h2d_static_conf_post,
		}
	},

	.content = {
		.response_headers = h2d_static_generate_response_headers,
		.response_body = h2d_static_generate_response_body,
	},

	.ctx_free = h2d_static_ctx_free,

};

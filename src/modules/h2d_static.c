#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include "h2d_main.h"

struct h2d_static_conf {
	const char	*dir_name;
	const char	*index;
	struct h2d_log	*log;
	bool		list_dir;

	int		dirfd;
};

struct h2d_static_ctx {
	int		fd;
	off_t		left;
	char		*list_dir_buf;
	int		list_dir_len;
};

struct h2d_module h2d_static_module;

static const char *h2d_static_mime_type(const char *filename)
{
	return "hello";
}

static int h2d_static_process_request_headers(struct h2d_request *r)
{
	if (r->req.method != WUY_HTTP_GET && r->req.method != WUY_HTTP_HEAD) {
		return WUY_HTTP_405;
	}
	return H2D_OK;
}

static int h2d_static_dir_headers(struct h2d_request *r, struct stat *st_buf)
{
	struct h2d_static_ctx *ctx = r->module_ctxs[h2d_static_module.index];

	ctx->list_dir_buf = malloc(4096);

	char *p = ctx->list_dir_buf;
	DIR *dir = fdopendir(ctx->fd);
	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL){
		const char *name = entry->d_name;
		if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
			continue;
		}
		p += sprintf(p, "%s\n", name);
	}
	ctx->list_dir_len = p - ctx->list_dir_buf;

	h2d_header_add_lite(&r->resp.headers, "Content-Type",
			"application/text", 16);

	r->resp.status_code = WUY_HTTP_200;
	r->resp.content_length = ctx->list_dir_len;
	return H2D_OK;
}

static int h2d_static_range_headers(struct h2d_request *r, struct h2d_header *h,
		struct stat *st_buf)
{
	struct h2d_static_conf *conf = r->conf_path->module_confs[h2d_static_module.index];
	struct h2d_static_ctx *ctx = r->module_ctxs[h2d_static_module.index];

	struct wuy_http_range ranges[10];
	int range_num = wuy_http_range_parse(h2d_header_value(h), h->value_len,
			st_buf->st_size, ranges, 10);
	if (range_num < 0) {
		return WUY_HTTP_416;
	}
	if (range_num == 0) {
		return WUY_HTTP_200;
	}
	if (range_num > 1) {
		/* multiple ranges are not suppored */
		return WUY_HTTP_200;
	}

	/* check If-Range */
	h = h2d_header_get(&r->req.headers, "If-Range");
	if (h != NULL) {
		time_t if_range = wuy_http_date_parse(h2d_header_value(h));
		h2d_request_log_at(r, conf->log, H2D_LOG_DEBUG, "check If-Range %ld %ld",
				if_range, st_buf->st_mtime);
		if (if_range != st_buf->st_mtime) {
			return WUY_HTTP_200;
		}
	}

	struct wuy_http_range *range = ranges;
	lseek(ctx->fd, range->first, SEEK_SET);
	ctx->left = range->last - range->first + 1;

	/* response status code and headers */
	r->resp.status_code = WUY_HTTP_206;
	r->resp.content_length = ctx->left;

	char buf[100];
	int len = sprintf(buf, "bytes %ld-%ld/%ld", range->first,
			range->last, st_buf->st_size);
	h2d_header_add_lite(&r->resp.headers, "Content-Range", buf, len);

	return H2D_OK;
}

static int h2d_static_generate_response_headers(struct h2d_request *r)
{
	struct h2d_static_conf *conf = r->conf_path->module_confs[h2d_static_module.index];

	h2d_header_add_lite(&r->resp.headers, "Server", "h2tpd", 5);

	/* ctx */
	struct h2d_static_ctx *ctx = calloc(1, sizeof(struct h2d_static_ctx));
	r->module_ctxs[h2d_static_module.index] = ctx;

	const char *filename = r->req.uri.path + 1;
	if (filename[0] == '\0') {
		if (conf->index != NULL) {
			filename = conf->index;
		} else if (conf->list_dir) {
			filename = ".";
			ctx->fd = conf->dirfd;
			goto skip_open;
		} else {
			return WUY_HTTP_404;
		}
	}

	h2d_request_log_at(r, conf->log, H2D_LOG_DEBUG, "open file %s", filename);

	ctx->fd = openat(conf->dirfd, filename, O_RDONLY);
	if (ctx->fd < 0) {
		h2d_request_log_at(r, conf->log, H2D_LOG_INFO, "error to open file %s %s",
				filename, strerror(errno));
		return WUY_HTTP_404;
	}
skip_open:;

	struct stat st_buf;
	fstat(ctx->fd, &st_buf);

	/* check If-Modified-Since */
	struct h2d_header *h = h2d_header_get(&r->req.headers, "If-Modified-Since");
	if (h != NULL) {
		time_t if_modified_since = wuy_http_date_parse(h2d_header_value(h));
		h2d_request_log_at(r, conf->log, H2D_LOG_DEBUG, "check If-Modified-Since %ld %ld",
				if_modified_since, st_buf.st_mtime);
		if (if_modified_since == st_buf.st_mtime) {
			return WUY_HTTP_304;
		}
	}

	switch (st_buf.st_mode & S_IFMT) {
	case S_IFREG:
		break;
	case S_IFDIR:
		if (!conf->list_dir) {
			printf(" conf %s %s %d\n", conf->dir_name, conf->index, conf->list_dir);
			return WUY_HTTP_403;
		}
		return h2d_static_dir_headers(r, &st_buf);
	default:
		return WUY_HTTP_403;
	}

	h2d_header_add_lite(&r->resp.headers, "Last-Modified",
			wuy_http_date_make(st_buf.st_mtime),
			WUY_HTTP_DATE_LENGTH);

	const char *content_type = h2d_static_mime_type(filename);
	h2d_header_add_lite(&r->resp.headers, "Content-Type",
			content_type, strlen(content_type));

	/* check Range */
	if (r->req.method == WUY_HTTP_GET) {
		h = h2d_header_get(&r->req.headers, "Range");
		if (h != NULL) {
			int ret = h2d_static_range_headers(r, h, &st_buf);
			if (ret != WUY_HTTP_200) {
				return ret;
			}
		}
	}

	r->resp.status_code = WUY_HTTP_200;
	r->resp.content_length = st_buf.st_size;
	ctx->left = st_buf.st_size;

	return H2D_OK;
}

static int h2d_static_generate_response_body(struct h2d_request *r, uint8_t *buf, int size)
{
	struct h2d_static_conf *conf = r->conf_path->module_confs[h2d_static_module.index];
	struct h2d_static_ctx *ctx = r->module_ctxs[h2d_static_module.index];

	if (ctx->list_dir_buf != NULL) {
		memcpy(buf, ctx->list_dir_buf, ctx->list_dir_len);
		return ctx->list_dir_len;
	}

	if (size > ctx->left) {
		size = ctx->left;
	}

	int ret = read(ctx->fd, buf, size);
	if (ret < 0) {
		h2d_request_log_at(r, conf->log, H2D_LOG_ERROR, "read fail %s", strerror(errno));
		return -1;
	}
	if (ret < size) {
		// TODO
		h2d_request_log_at(r, conf->log, H2D_LOG_ERROR, "read not complete");
	}
	ctx->left -= ret;
	h2d_request_log_at(r, conf->log, H2D_LOG_DEBUG, "read file %ld", ret);
	return ret;
}

static void h2d_static_ctx_free(struct h2d_request *r)
{
	struct h2d_static_conf *conf = r->conf_path->module_confs[h2d_static_module.index];
	struct h2d_static_ctx *ctx = r->module_ctxs[h2d_static_module.index];

	if (ctx->fd != conf->dirfd) {
		close(ctx->fd);
	}
	free(ctx->list_dir_buf);
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
		.default_value.s = "index.html",
	},
	{	.name = "list_dir",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct h2d_static_conf, list_dir),
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
		.process_headers = h2d_static_process_request_headers,
		.response_headers = h2d_static_generate_response_headers,
		.response_body = h2d_static_generate_response_body,
	},

	.ctx_free = h2d_static_ctx_free,
};

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


struct h2d_module h2d_static_module;

static const char *h2d_static_mime_type(const char *filename)
{
	return "TODO";
}

static int h2d_static_process_request_headers(struct h2d_request *r)
{
	if (r->req.method != WUY_HTTP_GET && r->req.method != WUY_HTTP_HEAD) {
		return WUY_HTTP_405;
	}
	return H2D_OK;
}

static int h2d_static_dir_headers(struct h2d_request *r, int fd)
{
	char buffer[4096 * 10];
	char *p = buffer, *end = buffer + sizeof(buffer);
	DIR *dir = fdopendir(fd);
	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL){
		const char *name = entry->d_name;
		if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
			continue;
		}
		p += snprintf(p, end - p, "%s\n", name);
	}

	closedir(dir);

	h2d_header_add_lite(&r->resp.headers, "Content-Type",
			"application/text", 16, r->pool);

	r->resp.easy_str_len = p - buffer;
	r->resp.easy_string = wuy_pool_strndup(r->pool, buffer, r->resp.easy_str_len);

	r->resp.status_code = WUY_HTTP_200;
	r->resp.content_length = r->resp.easy_str_len;
	return H2D_OK;
}

static int h2d_static_range_headers(struct h2d_request *r, struct h2d_header *h,
		struct stat *st_buf, int fd)
{
	struct h2d_static_conf *conf = r->conf_path->module_confs[h2d_static_module.index];

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
	lseek(fd, range->first, SEEK_SET);

	/* response status code and headers */
	r->resp.status_code = WUY_HTTP_206;
	r->resp.content_length = range->last - range->first + 1;

	char buf[100];
	int len = sprintf(buf, "bytes %ld-%ld/%ld", range->first,
			range->last, st_buf->st_size);
	h2d_header_add_lite(&r->resp.headers, "Content-Range", buf, len, r->pool);

	return H2D_OK;
}

static int h2d_static_generate_response_headers(struct h2d_request *r)
{
	struct h2d_static_conf *conf = r->conf_path->module_confs[h2d_static_module.index];

	h2d_header_add_lite(&r->resp.headers, "Server", "h2tpd", 5, r->pool);

	const char *filename = r->req.uri.path + 1;
	if (filename[0] == '\0') { /* "/" */
		filename = ".";
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

	/* if directory */
	mode_t ftype = st_buf.st_mode & S_IFMT;
	if (ftype == S_IFDIR) {
		if (conf->list_dir) {
			return h2d_static_dir_headers(r, fd);
		}
		if (conf->index == NULL) {
			h2d_request_log_at(r, conf->log, H2D_LOG_INFO, "request directory");
			return WUY_HTTP_404;
		}

		int index_fd = openat(fd, conf->index, O_RDONLY);
		close(fd);
		fd = index_fd;
		if (fd < 0) {
			h2d_request_log_at(r, conf->log, H2D_LOG_INFO,
					"error to open index %s", strerror(errno));
			return WUY_HTTP_404;
		}

		fstat(fd, &st_buf);
		ftype = st_buf.st_mode & S_IFMT;
	}

	r->module_ctxs[h2d_static_module.index] = (void *)(intptr_t)fd;

	if (ftype != S_IFREG && ftype != S_IFLNK) {
		h2d_request_log_at(r, conf->log, H2D_LOG_INFO, "invalid file type");
		return WUY_HTTP_404;
	}

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

	/* OK, response the file */
	r->resp.easy_fd = fd;

	h2d_header_add_lite(&r->resp.headers, "Last-Modified",
			wuy_http_date_make(st_buf.st_mtime),
			WUY_HTTP_DATE_LENGTH, r->pool);

	const char *content_type = h2d_static_mime_type(filename);
	h2d_header_add_lite(&r->resp.headers, "Content-Type",
			content_type, strlen(content_type), r->pool);

	/* check Range */
	if (r->req.method == WUY_HTTP_GET) {
		h = h2d_header_get(&r->req.headers, "Range");
		if (h != NULL) {
			int ret = h2d_static_range_headers(r, h, &st_buf, fd);
			if (ret != WUY_HTTP_200) {
				return ret;
			}
		}
	}

	r->resp.status_code = WUY_HTTP_200;
	r->resp.content_length = st_buf.st_size;
	return H2D_OK;
}

static void h2d_static_ctx_free(struct h2d_request *r)
{
	int fd = (intptr_t)r->module_ctxs[h2d_static_module.index];
	if (fd != 0) {
		close(fd);
	}
}


/* configuration */

static const char *h2d_static_conf_post(void *data)
{
	struct h2d_static_conf *conf = data;

	if (conf->dir_name == NULL) {
		return WUY_CFLUA_OK;
	}

	conf->dirfd = open(conf->dir_name, O_RDONLY|O_DIRECTORY);
	if (conf->dirfd < 0) {
		wuy_cflua_post_arg = conf->dir_name;
		return "fail to open dir";
	}

	return WUY_CFLUA_OK;
}

static struct wuy_cflua_command h2d_static_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.description = "The directory.",
		.is_single_array = true,
		.offset = offsetof(struct h2d_static_conf, dir_name),
	},
	{	.name = "list_dir",
		.description = "List the directory if set.",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct h2d_static_conf, list_dir),
	},
	{	.name = "index",
		.description = "Set the index file if directory is queried. Only if list_dir not set.",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_static_conf, index),
	},
	{	.name = "log",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_static_conf, log),
		.u.table = &h2d_log_omit_conf_table,
	},
	{ NULL }
};

struct h2d_module h2d_static_module = {
	.name = "static",
	.command_path = {
		.name = "static",
		.description = "Static file content module.",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = 0, /* reset later */
		.u.table = &(struct wuy_cflua_table) {
			.commands = h2d_static_conf_commands,
			.size = sizeof(struct h2d_static_conf),
			.post = h2d_static_conf_post,
			.may_omit = true,
		}
	},

	.content = {
		.process_headers = h2d_static_process_request_headers,
		.response_headers = h2d_static_generate_response_headers,
	},

	.ctx_free = h2d_static_ctx_free,
};

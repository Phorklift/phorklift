#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include "phl_main.h"

struct phl_static_conf {
	const char	*dir_name;
	const char	*index;
	struct phl_log	*log;
	bool		enable_list_dir;
	bool		enable_upload;

	int		dirfd;
};


struct phl_module phl_static_module;

static const char *phl_static_mime_type(const char *filename)
{
	return "TODO";
}

static int phl_static_generate_response_headers_post(struct phl_request *r)
{
	struct phl_static_conf *conf = r->conf_path->module_confs[phl_static_module.index];

	if (!conf->enable_upload) {
		return WUY_HTTP_405;
	}

	const char *filename = r->req.uri.path + 1;
	if (filename[strlen(filename)-1] == '/') {
		return WUY_HTTP_405;
	}

	phl_request_log_at(r, conf->log, PHL_LOG_DEBUG, "open/w file %s", filename);

	int fd = openat(conf->dirfd, filename, O_WRONLY | O_TRUNC | O_CREAT, 0644);
	if (fd < 0) {
		phl_request_log_at(r, conf->log, PHL_LOG_INFO, "error to open/w file %s %s",
				filename, strerror(errno));
		return errno == EACCES ? WUY_HTTP_403 : WUY_HTTP_404;
	}

	if (write(fd, r->req.body_buf, r->req.body_len) < 0) {
		phl_request_log_at(r, conf->log, PHL_LOG_INFO, "error to write file %s %s",
				filename, strerror(errno));
		return WUY_HTTP_500;
	}
	close(fd);

	r->resp.content_length = 0;
	return WUY_HTTP_201;
}

static int phl_static_dir_headers(struct phl_request *r, int fd)
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

	phl_header_add_lite(&r->resp.headers, "Content-Type",
			"application/text", 16, r->pool);

	r->resp.content_length = p - buffer;
	r->resp.easy_string = wuy_pool_strndup(r->pool, buffer, r->resp.content_length);

	r->resp.status_code = WUY_HTTP_200;
	return PHL_OK;
}

static int phl_static_range_headers(struct phl_request *r, struct phl_header *h,
		struct stat *st_buf, int fd)
{
	struct phl_static_conf *conf = r->conf_path->module_confs[phl_static_module.index];

	struct wuy_http_range ranges[10];
	int range_num = wuy_http_range_parse(phl_header_value(h), h->value_len,
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
	h = phl_header_get(&r->req.headers, "If-Range");
	if (h != NULL) {
		time_t if_range = wuy_http_date_parse(phl_header_value(h));
		phl_request_log_at(r, conf->log, PHL_LOG_DEBUG, "check If-Range %ld %ld",
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
	phl_header_add_lite(&r->resp.headers, "Content-Range", buf, len, r->pool);

	return PHL_OK;
}

static int phl_static_generate_response_headers(struct phl_request *r)
{
	if (r->req.method == WUY_HTTP_POST || r->req.method == WUY_HTTP_PUT) {
		return phl_static_generate_response_headers_post(r);
	}

	struct phl_static_conf *conf = r->conf_path->module_confs[phl_static_module.index];

	const char *filename = r->req.uri.path + 1;
	if (filename[0] == '\0') { /* "/" */
		filename = ".";
	}

	phl_request_log_at(r, conf->log, PHL_LOG_DEBUG, "open file %s", filename);

	int fd = openat(conf->dirfd, filename, O_RDONLY);
	if (fd < 0) {
		phl_request_log_at(r, conf->log, PHL_LOG_INFO, "error to open file %s %s",
				filename, strerror(errno));
		return WUY_HTTP_404;
	}

	struct stat st_buf;
	fstat(fd, &st_buf);

	/* if directory */
	mode_t ftype = st_buf.st_mode & S_IFMT;
	if (ftype == S_IFDIR) {
		if (conf->enable_list_dir) {
			return phl_static_dir_headers(r, fd);
		}

		int index_fd = openat(fd, conf->index, O_RDONLY);
		close(fd);
		fd = index_fd;
		if (fd < 0) {
			phl_request_log_at(r, conf->log, PHL_LOG_INFO,
					"error to open index %s", strerror(errno));
			return WUY_HTTP_404;
		}

		fstat(fd, &st_buf);
		ftype = st_buf.st_mode & S_IFMT;
	}

	r->module_ctxs[phl_static_module.index] = (void *)(intptr_t)fd;

	if (ftype != S_IFREG && ftype != S_IFLNK) {
		phl_request_log_at(r, conf->log, PHL_LOG_INFO, "invalid file type");
		return WUY_HTTP_404;
	}

	/* check If-Modified-Since */
	struct phl_header *h = phl_header_get(&r->req.headers, "If-Modified-Since");
	if (h != NULL) {
		time_t if_modified_since = wuy_http_date_parse(phl_header_value(h));
		phl_request_log_at(r, conf->log, PHL_LOG_DEBUG, "check If-Modified-Since %ld %ld",
				if_modified_since, st_buf.st_mtime);
		if (if_modified_since == st_buf.st_mtime) {
			return WUY_HTTP_304;
		}
	}

	/* OK, response the file */
	r->resp.easy_fd = fd;

	phl_header_add_lite(&r->resp.headers, "Last-Modified",
			wuy_http_date_make(st_buf.st_mtime),
			WUY_HTTP_DATE_LENGTH, r->pool);

	const char *content_type = phl_static_mime_type(filename);
	phl_header_add_lite(&r->resp.headers, "Content-Type",
			content_type, strlen(content_type), r->pool);

	/* check Range */
	if (r->req.method == WUY_HTTP_GET) {
		h = phl_header_get(&r->req.headers, "Range");
		if (h != NULL) {
			int ret = phl_static_range_headers(r, h, &st_buf, fd);
			if (ret != WUY_HTTP_200) {
				return ret;
			}
		}
	}

	r->resp.status_code = WUY_HTTP_200;
	r->resp.content_length = st_buf.st_size;
	return PHL_OK;
}

static void phl_static_ctx_free(struct phl_request *r)
{
	int fd = (intptr_t)r->module_ctxs[phl_static_module.index];
	if (fd != 0) {
		close(fd);
	}
}


/* configuration */

static const char *phl_static_conf_post(void *data)
{
	struct phl_static_conf *conf = data;

	if (conf->dir_name == NULL) {
		return WUY_CFLUA_OK;
	}

	if (conf->enable_upload && wuy_cflua_fenv != 0) {
		/* wuy_cflua_fenv was set in phl_dynamic.c before parsing */
		return "can not enable_upload in sandbox of dynamic configuration";
	}

	conf->dirfd = open(conf->dir_name, O_RDONLY|O_DIRECTORY);
	if (conf->dirfd < 0) {
		wuy_cflua_post_arg = conf->dir_name;
		return "fail to open dir";
	}

	return WUY_CFLUA_OK;
}

static struct wuy_cflua_command phl_static_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.description = "The directory.",
		.is_single_array = true,
		.offset = offsetof(struct phl_static_conf, dir_name),
	},
	{	.name = "index",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct phl_static_conf, index),
		.default_value.s = "index.html",
		.description = "Set the index file if directory is queried. Only if enable_list_dir not set.",
	},
	{	.name = "enable_list_dir",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct phl_static_conf, enable_list_dir),
		.description = "List the directory if set.",
	},
	{	.name = "enable_upload",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct phl_static_conf, enable_upload),
	},
	{	.name = "log",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct phl_static_conf, log),
		.u.table = &phl_log_omit_conf_table,
	},
	{ NULL }
};

struct phl_module phl_static_module = {
	.name = "static",
	.command_path = {
		.name = "static",
		.description = "Static file content module.",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = 0, /* reset later */
		.u.table = &(struct wuy_cflua_table) {
			.commands = phl_static_conf_commands,
			.size = sizeof(struct phl_static_conf),
			.post = phl_static_conf_post,
			.may_omit = true,
		}
	},

	.content = {
		.response_headers = phl_static_generate_response_headers,
	},

	.ctx_free = phl_static_ctx_free,
};

#include "h2d_main.h"

struct h2d_file_cache_stats {
	atomic_long		total;
	atomic_long		hit_current;
	atomic_long		hit_last;
	atomic_long		miss;
	atomic_long		not_finished;
	atomic_long		ignore;
	atomic_long		create;
	atomic_long		remove;
};

struct h2d_file_cache_conf {
	const char		*dir_name;
	wuy_cflua_function_t	key;
	int			inactive;
	int			max_length;
	int			default_expire;
	int			dir_level;
	const char		**include_headers;
	const char		**exclude_headers;
	struct h2d_log		*log;

	int			dirfd;
	int			current_dirfd;
	int			last_dirfd;

	struct h2d_file_cache_stats	*stats;
};

struct h2d_file_cache_item {
	enum wuy_http_status_code	status_code;
	time_t				expire_at;
	size_t				content_length;
	int				header_num;
	int				header_total_length;
	struct h2d_header		headers[0];
};

struct h2d_file_cache_ctx {
	int				fd;
	const char			*filename;
	struct h2d_file_cache_item	item;
};

#define _log(level, fmt, ...) h2d_request_log_at(r, \
		conf->log, level, "file_cache: " fmt, ##__VA_ARGS__)

struct h2d_module h2d_file_cache_module;

static void h2d_file_cache_ctx_free(struct h2d_request *r)
{
	struct h2d_file_cache_ctx *ctx = r->module_ctxs[h2d_file_cache_module.index];
	if (ctx->fd > 0) {
		close(ctx->fd);
	}
	free((char *)ctx->filename);
	free(ctx);
}

static void h2d_file_cache_abort(struct h2d_request *r)
{
	h2d_file_cache_ctx_free(r);
	r->module_ctxs[h2d_file_cache_module.index] = NULL;
}

static int h2d_file_cache_filter_process_headers(struct h2d_request *r)
{
	struct h2d_file_cache_conf *conf = r->conf_path->module_confs[h2d_file_cache_module.index];
	if (conf->dir_name == NULL) {
		return H2D_OK;
	}
	if (r->req.method != WUY_HTTP_GET && r->req.method != WUY_HTTP_HEAD) {
		return H2D_OK;
	}

	/* get key and calculate hash */
	int len;
	const char *key = r->req.uri.raw;
	if (wuy_cflua_is_function_set(conf->key)) {
		key = h2d_lua_api_call_lstring(r, conf->key, &len);
		if (key == NULL) {
			_log(H2D_LOG_DEBUG, "none key");
			return H2D_OK;
		}
	} else {
		len = strlen(key);
	}

	uint64_t hash[2];
	wuy_murmurhash(key, len, hash);

	atomic_fetch_add(&conf->stats->total, 1);

	/* build filename */
	char filename[100], *p = filename;
	uint64_t tmpdirhash = hash[0];
	for (int i = 0; i < conf->dir_level; i++) {
		p += sprintf(p, "%02lx/", tmpdirhash & 0xFF);
		tmpdirhash >>= 8;
	}
	sprintf(p, "%016lx%016lx", hash[0], hash[1]);

	_log(H2D_LOG_DEBUG, "key: %*s, filename: %s", len, key, filename);

	struct h2d_file_cache_ctx *ctx = calloc(1, sizeof(struct h2d_file_cache_ctx));
	r->module_ctxs[h2d_file_cache_module.index] = ctx;

	/* try to open file */
	ctx->fd = openat(conf->current_dirfd, filename, O_RDONLY);
	if (ctx->fd < 0) {
		ctx->fd = openat(conf->last_dirfd, filename, O_RDONLY);
		if (ctx->fd < 0) {
			/* cache miss, so save the filename to store */
			_log(H2D_LOG_DEBUG, "miss");
			atomic_fetch_add(&conf->stats->miss, 1);
			ctx->filename = strdup(filename);
			return H2D_OK;
		}

		atomic_fetch_add(&conf->stats->hit_last, 1);

		/* cache hit in last period directory, so move it to current directory */
		// TODO dir_level
		_log(H2D_LOG_DEBUG, "move to current directory");
		renameat(conf->last_dirfd, filename, conf->current_dirfd, filename);

	} else {
		atomic_fetch_add(&conf->stats->hit_current, 1);
	}

	/* cache hit! */
	_log(H2D_LOG_DEBUG, "hit");

	int ret = read(ctx->fd, &ctx->item, sizeof(struct h2d_file_cache_item));
	if (ret < 0) {
		_log(H2D_LOG_ERROR, "error to read cache file %s %s", filename, strerror(errno));
		return H2D_ERROR;
	}
	if (ctx->item.status_code == 0) {
		_log(H2D_LOG_DEBUG, "not finished");
		atomic_fetch_add(&conf->stats->not_finished, 1);
		h2d_file_cache_abort(r);
		return H2D_OK;
	}

	return ctx->item.status_code;
}

static int h2d_file_cache_dump_header_length(struct h2d_header *h)
{
	int len = 4 + h->name_len + h->value_len + 2;
	if ((len % 2) != 0) {
		len++;
	}
	return len;
}

static int h2d_file_cache_filter_response_headers(struct h2d_request *r)
{
	struct h2d_file_cache_conf *conf = r->conf_path->module_confs[h2d_file_cache_module.index];
	struct h2d_file_cache_ctx *ctx = r->module_ctxs[h2d_file_cache_module.index];
	if (ctx == NULL || ctx->filename == NULL) {
		return H2D_OK;
	}
	if (r->resp.status_code != WUY_HTTP_200) { // TODO cache more status_code
		atomic_fetch_add(&conf->stats->ignore, 1);
		h2d_file_cache_abort(r);
		return H2D_OK;
	}

	ctx->fd = openat(conf->current_dirfd, ctx->filename, O_CREAT | O_EXCL | O_WRONLY, 0644);
	if (ctx->fd < 0) {
		_log(H2D_LOG_DEBUG, "create fail %s %s\n", ctx->filename, strerror(errno));
		h2d_file_cache_abort(r);
		return H2D_OK;
	}

	/* count response headers first */
	int header_total_length = 0;
	int header_num = 0;
	struct h2d_header *store_headers[100], *h;
	h2d_header_iter(&r->resp.headers, h) {
		if (0) {
			continue;
		}
		store_headers[header_num++] = h;
		header_total_length += h2d_file_cache_dump_header_length(h);
	}

	/* dump the item and headers infomation into buffer */
	char buffer[sizeof(struct h2d_file_cache_item) + header_total_length];

	struct h2d_file_cache_item *item = (struct h2d_file_cache_item *)buffer;
	item->status_code = r->resp.status_code;
	item->expire_at = 0; // TODO
	item->content_length = r->resp.content_length;
	item->header_num = header_num;
	item->header_total_length = header_total_length;

	char *header_pos = (char *)(item + 1);
	for (int i = 0; i < header_num; i++) {
		h = store_headers[i];
		int len = h2d_file_cache_dump_header_length(h);
		memcpy(header_pos, &h->name_len, len);
		header_pos += len;
	}

	int ret = write(ctx->fd, buffer, sizeof(buffer));
	if (ret < 0) {
		_log(H2D_LOG_ERROR, "write headers fail %s %s", ctx->filename, strerror(errno));
		unlinkat(conf->current_dirfd, ctx->filename, 0);
		h2d_file_cache_abort(r);
		return H2D_OK;
	}

	return H2D_OK;
}

static int h2d_file_cache_filter_response_body(struct h2d_request *r,
		uint8_t *data, int data_len, int buf_len)
{
	struct h2d_file_cache_conf *conf = r->conf_path->module_confs[h2d_file_cache_module.index];
	struct h2d_file_cache_ctx *ctx = r->module_ctxs[h2d_file_cache_module.index];

	if (ctx != NULL && ctx->filename != NULL) {
		int ret = write(ctx->fd, data, data_len);
		if (ret < 0) {
			_log(H2D_LOG_ERROR, "write body fail %s %s",
					ctx->filename, strerror(errno));
			unlinkat(conf->current_dirfd, ctx->filename, 0);
			h2d_file_cache_abort(r);
		}
		// TODO set version
	}

	return data_len;
}

static int h2d_file_cache_generate_response_headers(struct h2d_request *r)
{
	struct h2d_file_cache_conf *conf = r->conf_path->module_confs[h2d_file_cache_module.index];
	struct h2d_file_cache_ctx *ctx = r->module_ctxs[h2d_file_cache_module.index];

	char buffer[ctx->item.header_total_length], *buf_pos = buffer;
	int ret = read(ctx->fd, buffer, sizeof(buffer));
	if (ret < 0) {
		_log(H2D_LOG_ERROR, "read headers %s", strerror(errno));
		return H2D_ERROR;
	}

	for (int i = 0; i < ctx->item.header_num; i++) {
		struct h2d_header *h = (struct h2d_header *)(buf_pos - sizeof(wuy_slist_node_t));
		h2d_header_add(&r->resp.headers, h->str, h->name_len,
				h2d_header_value(h), h->value_len);
		buf_pos += h2d_file_cache_dump_header_length(h);
	}

	r->resp.content_length = ctx->item.content_length;
	return H2D_OK;
}

static int h2d_file_cache_generate_response_body(struct h2d_request *r, uint8_t *buf, int size)
{
	struct h2d_file_cache_conf *conf = r->conf_path->module_confs[h2d_file_cache_module.index];
	struct h2d_file_cache_ctx *ctx = r->module_ctxs[h2d_file_cache_module.index];

	int ret = read(ctx->fd, buf, size);
	if (ret < 0) {
		_log(H2D_LOG_ERROR, "read body %s", strerror(errno));
		return H2D_ERROR;
	}
	return ret;
}

static void h2d_file_cache_stats_path(void *data, wuy_json_ctx_t *json)
{
	struct h2d_file_cache_conf *conf = data;
	struct h2d_file_cache_stats *stats = conf->stats;
	if (stats == NULL) {
		return;
	}

	wuy_json_object_object(json, "file_cache");
	wuy_json_object_int(json, "total", atomic_load(&stats->total));
	wuy_json_object_int(json, "hit_current", atomic_load(&stats->hit_current));
	wuy_json_object_int(json, "hit_last", atomic_load(&stats->hit_last));
	wuy_json_object_int(json, "miss", atomic_load(&stats->miss));
	wuy_json_object_int(json, "not_finished", atomic_load(&stats->not_finished));
	wuy_json_object_int(json, "ignore", atomic_load(&stats->ignore));
	wuy_json_object_int(json, "create", atomic_load(&stats->create));
	wuy_json_object_int(json, "remove", atomic_load(&stats->remove));
	wuy_json_object_close(json);
}

/* configuration */

static const char *h2d_file_cache_conf_post(void *data)
{
	struct h2d_file_cache_conf *conf = data;
	if (conf->dir_name == NULL) {
		return WUY_CFLUA_OK;
	}

	conf->dirfd = open(conf->dir_name, O_RDONLY, O_DIRECTORY);
	if (conf->dirfd < 0) {
		wuy_cflua_post_arg = conf->dir_name;
		return "fail to open dir";
	}

	conf->current_dirfd = conf->dirfd;
	conf->last_dirfd = conf->dirfd;

	conf->stats = wuy_shmpool_alloc(sizeof(struct h2d_file_cache_stats));

	return WUY_CFLUA_OK;
}

static bool h2d_file_cache_content_is_enabled(void *data)
{
	return false;
}

static struct wuy_cflua_command h2d_file_cache_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.is_single_array = true,
		.offset = offsetof(struct h2d_file_cache_conf, dir_name),
	},
	{	.name = "key",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_file_cache_conf, key),
	},
	{	.name = "inactive",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_file_cache_conf, inactive),
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
		.default_value.n = 3 * 3600,
	},
	{	.name = "dir_level",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_file_cache_conf, dir_level),
		.limits.n = WUY_CFLUA_LIMITS(0, 3),
	},
	{	.name = "max_length",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_file_cache_conf, max_length),
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "default_expire",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_file_cache_conf, default_expire),
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "include_headers",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_file_cache_conf, include_headers),
		.u.table = WUY_CFLUA_ARRAY_STRING_TABLE,
	},
	{	.name = "exclude_headers",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_file_cache_conf, exclude_headers),
		.u.table = WUY_CFLUA_ARRAY_STRING_TABLE,
	},
	{	.name = "log",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_file_cache_conf, log),
		.u.table = &h2d_log_conf_table,
	},
	{ NULL }
};

struct h2d_module h2d_file_cache_module = {
	.name = "file_cache",
	.command_path = {
		.name = "file_cache",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) {
			.commands = h2d_file_cache_conf_commands,
			.size = sizeof(struct h2d_file_cache_conf),
			.post = h2d_file_cache_conf_post,
		}
	},

	.filters = {
		.process_headers = h2d_file_cache_filter_process_headers,
		.response_headers = h2d_file_cache_filter_response_headers,
		.response_body = h2d_file_cache_filter_response_body,
	},

	.content = {
		.is_enabled = h2d_file_cache_content_is_enabled,
		.response_headers = h2d_file_cache_generate_response_headers,
		.response_body = h2d_file_cache_generate_response_body,
	},

	.ctx_free = h2d_file_cache_ctx_free,
	.stats_path = h2d_file_cache_stats_path,
};

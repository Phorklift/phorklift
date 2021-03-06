#include <dirent.h>
#include "h2d_main.h"

struct h2d_file_cache_stats {
	atomic_long		total;
	atomic_long		hit_current;
	atomic_long		hit_last;
	atomic_long		miss;
	atomic_long		not_finished;
	atomic_long		expired;
	atomic_long		ignore_status;
	atomic_long		ignore_expire;
	atomic_long		store_ok;
	atomic_long		store_fail;
	atomic_long		create;
	atomic_long		remove;
};

struct h2d_file_cache_conf {
	const char		*dir_name;
	wuy_cflua_function_t	key;
	wuy_cflua_function_t	expire_time;
	int			default_expire;
	int			inactive;
	int			max_length;
	int			dir_level;
	int			*status_codes;
	const char		**include_headers;
	const char		**exclude_headers;
	struct h2d_log		*log;

	int			dirfd;
	int			current_dirfd;
	int			last_dirfd;
	const char		*current_dirname;
	const char		*last_dirname;

	struct h2d_file_cache_stats	*stats;
};

struct h2d_file_cache_item {
	size_t				content_length;
	time_t				expire_at;
	enum wuy_http_status_code	status_code;
	int				header_num;
	int				header_total_length;
	struct h2d_header		headers[0];
};

struct h2d_file_cache_ctx {
	int				fd;
	const char			*new_filename;
	size_t				new_length;
	struct h2d_file_cache_item	item;
};

#define _log(level, fmt, ...) h2d_request_log_at(r, \
		conf->log, level, "file_cache: " fmt, ##__VA_ARGS__)

#define _log_conf(level, fmt, ...) h2d_log_level(conf->log, \
		level, "file_cache: " fmt, ##__VA_ARGS__)

struct h2d_module h2d_file_cache_module;

/* === directory oprations */

static void h2d_file_cache_delete_last_dir(struct h2d_file_cache_conf *conf)
{
	if (conf->last_dirfd == 0) {
		return;
	}

	close(conf->last_dirfd);

	// TODO
	printf("delete dir: %s/%s\n", conf->dir_name, conf->last_dirname);
	free((char *)conf->last_dirname);
}

static bool h2d_file_cache_mkdir(int dirfd, const char *pathname)
{
	return mkdirat(dirfd, pathname, 0700) == 0 || errno == EEXIST;
}

static bool h2d_file_cache_new_dir(struct h2d_file_cache_conf *conf, time_t now)
{
	char dirname[100];
	sprintf(dirname, "P_%ld", time(NULL));
	if (!h2d_file_cache_mkdir(conf->dirfd, dirname)) {
		_log_conf(H2D_LOG_ERROR, "new directory %s", strerror(errno));
		return false;
	}

	int new_dirfd = openat(conf->dirfd, dirname, O_RDONLY|O_DIRECTORY);
	if (new_dirfd < 0) {
		_log_conf(H2D_LOG_ERROR, "fail in new dir: %s", strerror(errno));
		return false;
	}

	h2d_file_cache_delete_last_dir(conf);

	conf->last_dirfd = conf->current_dirfd;
	conf->current_dirfd = new_dirfd;
	conf->last_dirname = conf->current_dirname;
	conf->current_dirname = strdup(dirname);

	return true;
}

static bool h2d_file_cache_do_prepare_prefix(int dirfd, const char *filename, int level)
{
	assert(level > 0);

	char pathname[100];
	memcpy(pathname, filename, level*3);
	pathname[level*3] = '\0';

	/* mkdir */
	if (h2d_file_cache_mkdir(dirfd, pathname)) {
		return true;
	}
	if (errno != ENOENT) {
		return false;
	}

	/* make parent directory */
	if (!h2d_file_cache_do_prepare_prefix(dirfd, filename, level - 1)) {
		return false;
	}

	/* try again */
	return h2d_file_cache_mkdir(dirfd, pathname);
}

static void h2d_file_cache_prepare_prefix(struct h2d_file_cache_conf *conf,
		const char *filename)
{
	if (conf->dir_level == 0) {
		return;
	}

	if (!h2d_file_cache_do_prepare_prefix(conf->current_dirfd,
				filename, conf->dir_level)) {
		_log_conf(H2D_LOG_ERROR, "prepare prefix for %s: %s",
				filename, strerror(errno));
	}
}

static bool h2d_file_cache_rename_file(struct h2d_file_cache_conf *conf,
		const char *filename)
{
	_log_conf(H2D_LOG_DEBUG, "move to current directory %s", filename);

	if (renameat(conf->last_dirfd, filename, conf->current_dirfd, filename) == 0) {
		return true;
	}
	if (errno != ENOENT) {
		_log_conf(H2D_LOG_ERROR, "fail to move %s", strerror(errno));
		return false;
	}

	h2d_file_cache_prepare_prefix(conf, filename);

	if (renameat(conf->last_dirfd, filename, conf->current_dirfd, filename) < 0) {
		_log_conf(H2D_LOG_ERROR, "fail to move again: %s", strerror(errno));
		return false;
	}
	return true;
}

static int h2d_file_cache_create_file(struct h2d_file_cache_conf *conf,
		const char *filename)
{
	_log_conf(H2D_LOG_DEBUG, "create new file %s", filename);

	int fd = openat(conf->current_dirfd, filename, O_CREAT | O_EXCL | O_WRONLY, 0644);
	if (fd >= 0) {
		return fd;
	}
	if (errno != ENOENT) {
		_log_conf(H2D_LOG_ERROR, "fail to create %s", strerror(errno));
		return fd;
	}

	h2d_file_cache_prepare_prefix(conf, filename);

	fd = openat(conf->current_dirfd, filename, O_CREAT | O_EXCL | O_WRONLY, 0644);
	if (fd < 0) {
		_log_conf(H2D_LOG_ERROR, "fail to create again: %s", strerror(errno));
		return fd;
	}
	return fd;
}

/* === module handlers */

static void h2d_file_cache_ctx_free(struct h2d_request *r)
{
	struct h2d_file_cache_conf *conf = r->conf_path->module_confs[h2d_file_cache_module.index];
	struct h2d_file_cache_ctx *ctx = r->module_ctxs[h2d_file_cache_module.index];

	if (ctx->fd > 0) {
		close(ctx->fd);
	}
	if (ctx->new_filename != NULL) {
		/* created a new item but not finished */
		if (ctx->new_length > 0) {
			atomic_fetch_add(&conf->stats->store_fail, 1);
		}
		unlinkat(conf->current_dirfd, ctx->new_filename, 0);
	}
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
		key = h2d_lua_call_lstring(r, conf->key, &len);
		if (key == NULL) {
			_log(H2D_LOG_DEBUG, "none key");
			return H2D_OK;
		}
	} else {
		len = strlen(key);
	}

	uint64_t hash[2];
	wuy_vhash128(key, len, hash);

	atomic_fetch_add(&conf->stats->total, 1);

	/* build filename */
	char filename[100], *p = filename;
	uint64_t tmpdirhash = hash[1];
	for (int i = 0; i < conf->dir_level; i++) {
		p += sprintf(p, "%02lx/", tmpdirhash & 0xFF);
		tmpdirhash >>= 8;
	}
	sprintf(p, "%016lx%016lx", hash[0], hash[1]);

	_log(H2D_LOG_DEBUG, "key: %*s, filename: %s", len, key, filename);

	struct h2d_file_cache_ctx *ctx = wuy_pool_alloc(r->pool, sizeof(struct h2d_file_cache_ctx));
	r->module_ctxs[h2d_file_cache_module.index] = ctx;

	/* try to open file */
	ctx->fd = openat(conf->current_dirfd, filename, O_RDONLY);
	if (ctx->fd > 0) {
		atomic_fetch_add(&conf->stats->hit_current, 1);

	} else if (conf->last_dirfd > 0) {
		ctx->fd = openat(conf->last_dirfd, filename, O_RDONLY);
		if (ctx->fd < 0) {
			goto cache_miss;
		}

		atomic_fetch_add(&conf->stats->hit_last, 1);
		h2d_file_cache_rename_file(conf, filename);

	} else {
cache_miss:
		/* save the filename and store response into it in filters later */
		_log(H2D_LOG_DEBUG, "miss");
		atomic_fetch_add(&conf->stats->miss, 1);
		ctx->new_filename = wuy_pool_strdup(r->pool, filename);
		return H2D_OK;
	}

	/* cache hit! */
	_log(H2D_LOG_DEBUG, "hit");

	int ret = read(ctx->fd, &ctx->item, sizeof(struct h2d_file_cache_item));
	if (ret < 0) {
		_log(H2D_LOG_ERROR, "error to read cache file %s %s", filename, strerror(errno));
		return H2D_ERROR;
	}
	if (ret < sizeof(struct h2d_file_cache_item) || ctx->item.content_length == H2D_CONTENT_LENGTH_INIT) {
		_log(H2D_LOG_DEBUG, "not finished");
		atomic_fetch_add(&conf->stats->not_finished, 1);
		h2d_file_cache_abort(r);
		return H2D_OK;
	}
	if (ctx->item.expire_at < time(NULL)) {
		_log(H2D_LOG_DEBUG, "expired");
		atomic_fetch_add(&conf->stats->expired, 1);

		close(ctx->fd);
		unlinkat(conf->current_dirfd, filename, 0);
		ctx->fd = -1;
		ctx->new_filename = wuy_pool_strdup(r->pool, filename);
		return H2D_OK;
	}

	return ctx->item.status_code;
}

static int h2d_file_cache_filter_response_headers(struct h2d_request *r)
{
	struct h2d_file_cache_conf *conf = r->conf_path->module_confs[h2d_file_cache_module.index];
	struct h2d_file_cache_ctx *ctx = r->module_ctxs[h2d_file_cache_module.index];
	if (ctx == NULL || ctx->new_filename == NULL) {
		return H2D_OK;
	}
	if (r->resp.status_code != WUY_HTTP_200) { // TODO cache more status_code
		atomic_fetch_add(&conf->stats->ignore_status, 1);
		h2d_file_cache_abort(r);
		return H2D_OK;
	}

	time_t expire_after = -1;
	ctx->item.header_num = 0;
	ctx->item.header_total_length = 0;

	/* count response headers first */
	struct h2d_header *store_headers[100], *h;
	h2d_header_iter(&r->resp.headers, h) {
		const char *value = h2d_header_value(h);
		if (strcasecmp(h->str, "Cache-Control") == 0) {
			if (memcmp(value, "max-age=", 8) != 0) {
				atomic_fetch_add(&conf->stats->ignore_expire, 1);
				h2d_file_cache_abort(r);
				return H2D_OK;
			}
			expire_after = atoi(value+8);
		} else if (strcasecmp(h->str, "Expires") == 0) {
			expire_after = wuy_http_date_parse(h2d_header_value(h)) - time(NULL);
		}

		store_headers[ctx->item.header_num++] = h;
		ctx->item.header_total_length += h2d_header_dump_length(h);
	}

	if (expire_after == -1) {
		expire_after = conf->default_expire;
	}
	if (expire_after <= 0) {
		atomic_fetch_add(&conf->stats->ignore_expire, 1);
		h2d_file_cache_abort(r);
		return H2D_OK;
	}

	/* create item */
	ctx->fd = h2d_file_cache_create_file(conf, ctx->new_filename);
	if (ctx->fd < 0) {
		h2d_file_cache_abort(r);
		return H2D_OK;
	}

	/* dump the item and headers infomation into buffer */
	char buffer[sizeof(struct h2d_file_cache_item) + ctx->item.header_total_length];

	struct h2d_file_cache_item *item = (struct h2d_file_cache_item *)buffer;
	item->content_length = H2D_CONTENT_LENGTH_INIT; /* mark as not-finished */
	item->expire_at = expire_after + time(NULL);
	item->status_code = r->resp.status_code;
	item->header_num = ctx->item.header_num;
	item->header_total_length = ctx->item.header_total_length;

	char *header_pos = (char *)(item + 1);
	for (int i = 0; i < item->header_num; i++) {
		h = store_headers[i];
		int len = h2d_header_dump_length(h);
		memcpy(header_pos, h2d_header_dump_pos(h), len);
		header_pos += len;
	}

	int ret = write(ctx->fd, buffer, sizeof(buffer));
	if (ret < 0) {
		_log(H2D_LOG_ERROR, "write headers fail %s %s", ctx->new_filename, strerror(errno));
		h2d_file_cache_abort(r);
		return H2D_OK;
	}

	return H2D_OK;
}

static int h2d_file_cache_filter_response_body(struct h2d_request *r,
		uint8_t *data, int data_len, int buf_len, bool *p_is_last)
{
	struct h2d_file_cache_conf *conf = r->conf_path->module_confs[h2d_file_cache_module.index];
	struct h2d_file_cache_ctx *ctx = r->module_ctxs[h2d_file_cache_module.index];

	if (ctx == NULL || ctx->new_filename == NULL) {
		return data_len;
	}

	if (write(ctx->fd, data, data_len) != data_len) {
		_log(H2D_LOG_ERROR, "write body fail %s %s",
				ctx->new_filename, strerror(errno));
		h2d_file_cache_abort(r);
	}

	ctx->new_length += data_len;

	if (*p_is_last) {
		atomic_fetch_add(&conf->stats->store_ok, 1);

		lseek(ctx->fd, 0, SEEK_SET);
		if (write(ctx->fd, &ctx->new_length, sizeof(size_t)) < 0) {
			_log(H2D_LOG_ERROR, "write fail");
		}

		/* mark finished */
		ctx->new_filename = NULL;
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
		struct h2d_header *h = h2d_header_load_from(buf_pos);
		h2d_header_add(&r->resp.headers, h->str, h->name_len,
				h2d_header_value(h), h->value_len, r->pool);
		buf_pos += h2d_header_dump_length(h);
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
	wuy_json_object_int(json, "expired", atomic_load(&stats->expired));
	wuy_json_object_int(json, "ignore_status", atomic_load(&stats->ignore_status));
	wuy_json_object_int(json, "ignore_expire", atomic_load(&stats->ignore_expire));
	wuy_json_object_int(json, "store_ok", atomic_load(&stats->store_ok));
	wuy_json_object_int(json, "store_fail", atomic_load(&stats->store_fail));
	wuy_json_object_int(json, "create", atomic_load(&stats->create));
	wuy_json_object_int(json, "remove", atomic_load(&stats->remove));
	wuy_json_object_close(json);
}


/* === configuration */

static int64_t h2d_file_cache_renew_period(int64_t at, void *data)
{
	struct h2d_file_cache_conf *conf = data;

	h2d_file_cache_new_dir(conf, at / 1000);
	return conf->inactive * 1000;
}

static const char *h2d_file_cache_conf_post(void *data)
{
	struct h2d_file_cache_conf *conf = data;
	if (conf->dir_name == NULL) {
		return WUY_CFLUA_OK;
	}

	conf->dirfd = open(conf->dir_name, O_RDONLY|O_DIRECTORY);
	if (conf->dirfd < 0) {
		wuy_cflua_post_arg = conf->dir_name;
		return "fail to open dir";
	}

	/* get current_dirfd and last_dirfd */
	time_t last_ts = 0, current_ts = 0;
	DIR *dir = opendir(conf->dir_name);
	struct dirent *e;
	while ((e = readdir(dir)) != NULL) {
		if ((e->d_type & DT_DIR) == 0) {
			continue;
		}
		time_t ts;
		if (sscanf(e->d_name, "P_%ld", &ts) != 1) {
			continue;
		}
		if (ts > current_ts) {
			h2d_file_cache_delete_last_dir(conf);

			last_ts = current_ts;
			current_ts = ts;
			conf->last_dirname = conf->current_dirname;
			conf->current_dirname = strdup(e->d_name);

			conf->last_dirfd = conf->current_dirfd;
			conf->current_dirfd = openat(conf->dirfd, e->d_name, O_RDONLY|O_DIRECTORY);
			if (conf->current_dirfd < 0) {
				wuy_cflua_post_arg = e->d_name;
				return "fail to open sub dir";
			}

		} else if (ts > last_ts) {
			h2d_file_cache_delete_last_dir(conf);

			last_ts = ts;
			conf->last_dirname = strdup(e->d_name);

			conf->last_dirfd = openat(conf->dirfd, e->d_name, O_RDONLY|O_DIRECTORY);
			if (conf->last_dirfd < 0) {
				wuy_cflua_post_arg = e->d_name;
				return "fail to open sub dir";
			}
		}
	}
	closedir(dir);

	/* create current_dirfd if not found */
	if (conf->current_dirfd == 0) {
		time_t now = time(NULL);
		if (conf->inactive > 0) {
			now = now / conf->inactive * conf->inactive;
		}
		if (!h2d_file_cache_new_dir(conf, now)) {
			return "fail to create sub dir";
		}
	}

	if (conf->inactive > 0) {
		loop_timer_t *timer = loop_timer_new(h2d_loop, h2d_file_cache_renew_period, conf);
		loop_timer_set_at(timer, (time(NULL) / conf->inactive + 1) * conf->inactive * 1000);
	}

	conf->stats = wuy_shmpool_alloc(sizeof(struct h2d_file_cache_stats));

	return WUY_CFLUA_OK;
}

static struct wuy_cflua_command h2d_file_cache_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.description = "Directory to store the cache content.",
		.is_single_array = true,
		.offset = offsetof(struct h2d_file_cache_conf, dir_name),
	},
	{	.name = "key",
		.description = "Return a string as cache key. The raw URL is used if not set.",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_file_cache_conf, key),
	},
	{	.name = "expire_time",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_file_cache_conf, expire_time),
	},
	{	.name = "default_expire",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_file_cache_conf, default_expire),
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "inactive",
		.description = "Cache items will be deleted if inactive such long time.",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_file_cache_conf, inactive),
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
		.default_value.n = 3 * 3600,
	},
	{	.name = "dir_level",
		.description = "This should be set as `floor(log[256]N) - 1` where N is the estimated number of cache items.",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_file_cache_conf, dir_level),
		.limits.n = WUY_CFLUA_LIMITS(0, 3),
		.default_value.n = 1,
	},
	{	.name = "max_length",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_file_cache_conf, max_length),
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "status_codes",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_file_cache_conf, status_codes),
		.u.table = WUY_CFLUA_ARRAY_INTEGER_TABLE,
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
		.description = "File cache filter module. " \
				"There is no total size limit of occupation. " \
				"We just clear items that inactive for a long time.",
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

		.content_headers = h2d_file_cache_generate_response_headers,
		.content_body = h2d_file_cache_generate_response_body,
	},

	.ctx_free = h2d_file_cache_ctx_free,
	.stats_path = h2d_file_cache_stats_path,
};

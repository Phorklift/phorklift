#include "h2d_main.h"

#define _log(level, fmt, ...) h2d_request_log_at(r, dynamic->log, level, "dynamic: " fmt, ##__VA_ARGS__)

#define _log_conf(level, fmt, ...) h2d_log_level(dynamic->log, level, "dynamic: " fmt, ##__VA_ARGS__)


static atomic_int *h2d_dynamic_id;

/* Call dynamic->get_name() which returns a name.
 * Return H2D_AGAIN, H2D_ERROR or H2D_OK. */
static int h2d_dynamic_get_name(struct h2d_dynamic_conf *dynamic,
		struct h2d_request *r, const char **p_name)
{
	struct h2d_dynamic_ctx *ctx = r->dynamic_ctx;

	_log(H2D_LOG_DEBUG, "get_name");

	const char *name;
	if (dynamic->is_name_blocking) {
		name = h2d_lua_api_call_lstring(r, dynamic->get_name, NULL);

	} else {
		if (ctx->lth == NULL) {
			ctx->lth = h2d_lua_api_thread_new(dynamic->get_name, r);
		}

		int ret = h2d_lua_api_thread_resume(ctx->lth);
		if (ret != H2D_OK) {
			_log(H2D_LOG_DEBUG, "get_name lua_api %d", ret);
			return ret;
		}

		name = lua_tostring(ctx->lth->L, -1);

		h2d_lua_api_thread_free(ctx->lth);
		ctx->lth = NULL;
	}

	if (name == NULL) {
		_log(H2D_LOG_ERROR, "get_name fail");
		return H2D_ERROR;
	}

	_log(H2D_LOG_DEBUG, "get_name: %s", name);

	*p_name = name;
	return H2D_OK;
}

static void *h2d_dynamic_to_container(struct h2d_dynamic_conf *sub_dyn)
{
	struct h2d_dynamic_conf *dynamic = sub_dyn->father ? sub_dyn->father : sub_dyn;
	return ((char *)sub_dyn) - dynamic->container_offset;
}
static struct h2d_dynamic_conf *h2d_dynamic_from_container(void *container,
		struct h2d_dynamic_conf *dynamic)
{
	return (void *)(((char *)container) + dynamic->container_offset);
}

static void h2d_dynamic_delete(struct h2d_dynamic_conf *sub_dyn)
{
	struct h2d_dynamic_conf *dynamic = sub_dyn->father;

	_log_conf(H2D_LOG_DEBUG, "delete %s", sub_dyn->name);

	if (sub_dyn->is_just_holder) {
		if (sub_dyn->error_ret == 0) {
			sub_dyn->error_ret = WUY_HTTP_500;
		}
		h2d_request_active_list(&sub_dyn->holder_wait_head, "dynamic holder");
	}

	loop_timer_delete(sub_dyn->timer);
	wuy_dict_delete(dynamic->sub_dict, sub_dyn);

	if (sub_dyn->shmpool != NULL) {
		wuy_shmpool_release(sub_dyn->shmpool);
	}
	if (sub_dyn->pool != NULL) {
		wuy_pool_release(sub_dyn->pool);
	}
}

static int64_t h2d_dynamic_timeout_handler(int64_t at, void *data)
{
	h2d_dynamic_delete(data);
	return 0;
}
static void h2d_dynamic_timer_new(struct h2d_dynamic_conf *sub_dyn)
{
	sub_dyn->timer = loop_timer_new(h2d_loop, h2d_dynamic_timeout_handler, sub_dyn);
}
static void h2d_dynamic_timer_update(struct h2d_dynamic_conf *sub_dyn)
{
	if (sub_dyn->timer != NULL) {
		loop_timer_set_after(sub_dyn->timer, sub_dyn->idle_timeout * 1000);
	}
}

/* Call dynamic->get_conf(), which accepts 2 arguments (name, last_modify_time),
 * and returns WUY_HTTP_200 (with conf-table), WUY_HTTP_304, WUY_HTTP_404,
 * or WUY_HTTP_500. */
static int h2d_dynamic_get_conf(struct h2d_dynamic_conf *dynamic,
		struct h2d_request *r)
{
	struct h2d_dynamic_ctx *ctx = r->dynamic_ctx;
	struct h2d_dynamic_conf *sub_dyn = ctx->sub_dyn;
	const char *name = sub_dyn->name;

	_log(H2D_LOG_DEBUG, "get_conf of %s", name);

	if (ctx->lth == NULL) {
		ctx->lth = h2d_lua_api_thread_new(dynamic->get_conf, r);
		lua_pushstring(ctx->lth->L, name);
		lua_pushinteger(ctx->lth->L, sub_dyn->modify_time);
		h2d_lua_api_thread_set_argn(ctx->lth, 2);
	}

	int ret = h2d_lua_api_thread_resume(ctx->lth);
	if (ret != H2D_OK) {
		_log(H2D_LOG_DEBUG, "get_conf %s lua_api %d", name, ret);
		return ret;
	}

	/* not conf-table, but WUY_HTTP_200/304/404/500 */
	if (lua_isnumber(ctx->lth->L, -1)) {
		switch (lua_tointeger(ctx->lth->L, -1)) {
		case WUY_HTTP_200:
			lua_pop(ctx->lth->L, 1);
			break;
		case WUY_HTTP_304:
			if (sub_dyn->is_just_holder) {
				_log(H2D_LOG_ERROR, "holder %s get 304", name);
				return H2D_ERROR;
			}
			return H2D_OK;
		case WUY_HTTP_404:
			h2d_dynamic_delete(sub_dyn);
			ctx->sub_dyn = NULL;
			return WUY_HTTP_404;
		default:
			_log(H2D_LOG_ERROR, "sub %s return %d", name,
					lua_tointeger(ctx->lth->L, -1));
			return WUY_HTTP_500;
		}
	}

	/* conf-table */
	if (!lua_istable(ctx->lth->L, -1)) {
		_log(H2D_LOG_ERROR, "%s invalid table", name);
		return H2D_ERROR;
	}

	lua_xmove(ctx->lth->L, h2d_L, 1);
	h2d_lua_api_thread_free(ctx->lth);
	ctx->lth = NULL;

	/* prepare shared-memory pool */
	char pool_name[1000];
	snprintf(pool_name, sizeof(pool_name), "/h2tpd.pid.%d.%s",
			atomic_load(dynamic->shared_id), name);
	wuy_shmpool_t *shmpool = wuy_shmpool_new(pool_name, 40*1024, 40*1024, 10);
	if (shmpool == NULL) {
		_log(H2D_LOG_ERROR, "fail in wuy_shmpool_new");
		return H2D_ERROR;
	}

	/* parse */
	wuy_pool_t *pool = wuy_pool_new(1024);
	void *container = NULL;
	const char *err = wuy_cflua_parse(h2d_L, dynamic->sub_table, &container, pool);
	if (err != WUY_CFLUA_OK) {
		_log(H2D_LOG_ERROR, "parse sub %s error: %s", name, err);
		return H2D_ERROR;
	}

	wuy_shmpool_finish(shmpool);

	/* replace */
	_log(H2D_LOG_INFO, "%s sub %s", sub_dyn->is_just_holder ? "new" : "update", name);

	struct h2d_dynamic_conf *new_sub = h2d_dynamic_from_container(container, dynamic);
	new_sub->name = wuy_pool_strdup(pool, name);
	new_sub->create_time = sub_dyn->create_time;

	new_sub->father = dynamic;
	new_sub->modify_time = time(NULL);
	new_sub->check_time = new_sub->modify_time;
	new_sub->shmpool = shmpool;
	new_sub->pool = pool;
	wuy_dict_add(dynamic->sub_dict, new_sub);
	if (new_sub->idle_timeout > 0) {
		h2d_dynamic_timer_new(new_sub);
		h2d_dynamic_timer_update(new_sub);
	}

	h2d_dynamic_delete(sub_dyn);
	ctx->sub_dyn = new_sub;

	return H2D_OK;
}

static bool h2d_dynamic_need_check_conf(struct h2d_dynamic_conf *sub_dyn,
		struct h2d_request *r)
{
	if (sub_dyn->is_just_holder) {
		return false;
	}
	if (sub_dyn->check_interval == 0) {
		return false;
	}
	time_t now = time(NULL);
	if (now - sub_dyn->check_time < sub_dyn->check_interval) {
		return false;
	}
	if (wuy_cflua_is_function_set(sub_dyn->check_filter)) {
		if (h2d_lua_api_call_boolean(r, sub_dyn->check_filter) != 1) {
			return false;
		}
	}
	sub_dyn->check_time = now;
	return true;
}

void *h2d_dynamic_get(struct h2d_dynamic_conf *dynamic, struct h2d_request *r)
{
	_log(H2D_LOG_DEBUG, "h2d_dynamic_get()");

	const char *name = NULL;

	struct h2d_dynamic_ctx *ctx = r->dynamic_ctx;
	if (ctx == NULL) {
		ctx = wuy_pool_alloc(r->pool, sizeof(struct h2d_dynamic_ctx));
		r->dynamic_ctx = ctx;
	}

	if (ctx->sub_dyn != NULL) { /* in processing already*/
		_log(H2D_LOG_DEBUG, "continue");
		goto state_get_conf;
	}

	/* get name to ctx->name */
	int ret = h2d_dynamic_get_name(dynamic, r, &name);
	if (ret != H2D_OK) {
		goto not_ok;
	}
	if (strlen(name) > 100) {
		_log(H2D_LOG_ERROR, "too long name");
		ret = H2D_ERROR;
		goto not_ok;
	}

	/* search cache by name */
	ctx->sub_dyn = wuy_dict_get(dynamic->sub_dict, name);

	if (ctx->sub_dyn == NULL) {
		if (wuy_dict_count(dynamic->sub_dict) >= dynamic->sub_max) {
			_log(H2D_LOG_ERROR, "fail to create new because of limited");
			ret = H2D_ERROR;
			goto not_ok;
		}

		_log(H2D_LOG_DEBUG, "new holder %s", name);

		/* No container, just hold this name. So the following requests
		 * will be pending here on its holder_wait_head, before get_conf()
		 * returning. */
		wuy_pool_t *pool = wuy_pool_new(256);
		struct h2d_dynamic_conf *new_sub = wuy_pool_alloc(pool, sizeof(struct h2d_dynamic_conf));
		new_sub->pool = pool;
		new_sub->father = dynamic;
		new_sub->name = wuy_pool_strdup(pool, name);
		new_sub->create_time = time(NULL);
		new_sub->is_just_holder = true;
		wuy_list_init(&new_sub->holder_wait_head);
		wuy_dict_add(dynamic->sub_dict, new_sub);

		ctx->sub_dyn = new_sub;

	} else if (ctx->sub_dyn->is_just_holder) {
		_log(H2D_LOG_DEBUG, "just_holder hit %s %d", name, ctx->sub_dyn->error_ret);

		/* this name was error in get_conf() */
		ret = ctx->sub_dyn->error_ret;
		if (ret != H2D_OK) {
			goto not_ok;
		}

		/* this name is in get_conf() processing */
		wuy_list_append(&ctx->sub_dyn->holder_wait_head, &r->list_node);
		ctx->sub_dyn = NULL;
		return NULL;

	} else {
		_log(H2D_LOG_DEBUG, "sub hit %s", name);

		h2d_dynamic_timer_update(ctx->sub_dyn);

		if (!h2d_dynamic_need_check_conf(ctx->sub_dyn, r)) {
			/* here is the most passed way to end this function! */
			goto done;
		}

		/* also get_conf() to check */
		_log(H2D_LOG_DEBUG, "check %s", name);
	}

state_get_conf:

	ret = h2d_dynamic_get_conf(dynamic, r);
	if (ret != H2D_OK) {
		goto not_ok;
	}

done:;
	void *container = h2d_dynamic_to_container(ctx->sub_dyn);
	h2d_dynamic_ctx_free(r);
	return container;

not_ok:
	if (ret == H2D_AGAIN) {
		return NULL;
	}

	_log(H2D_LOG_ERROR, "get fail %s %d", name, ret);

	if (ctx->sub_dyn == NULL) {
		goto out;
	}
	if (ctx->sub_dyn->is_just_holder) {
		/* cache error */
		ctx->sub_dyn->error_ret = ret;

		h2d_dynamic_timer_new(ctx->sub_dyn);
		loop_timer_set_after(ctx->sub_dyn->timer,
				ctx->sub_dyn->father->error_expire * 1000);

		h2d_request_active_list(&ctx->sub_dyn->holder_wait_head, "dynamic holder");
	} else {
		/* ignore error */
		return h2d_dynamic_to_container(ctx->sub_dyn);
	}
out:
	r->resp.status_code = (ret == H2D_ERROR) ? WUY_HTTP_500 : ret;
	return NULL;
}

void h2d_dynamic_ctx_free(struct h2d_request *r)
{
	struct h2d_dynamic_ctx *ctx = r->dynamic_ctx;
	if (ctx == NULL) {
		return;
	}

	if (ctx->lth != NULL) {
		h2d_lua_api_thread_free(ctx->lth);
	}
	if (ctx->sub_dyn != NULL && ctx->sub_dyn->is_just_holder
			&& ctx->sub_dyn->timer == NULL) {
		h2d_dynamic_delete(ctx->sub_dyn);
	}
	r->dynamic_ctx = NULL;
}

void h2d_dynamic_init(void)
{
	h2d_dynamic_id = wuy_shmpool_alloc(sizeof(atomic_int));
	atomic_store(h2d_dynamic_id, 1);

	atexit(wuy_shmpool_cleanup);
}

static struct wuy_cflua_command *h2d_dynamic_get_cmd(struct wuy_cflua_table *table)
{
	for (struct wuy_cflua_command *cmd = table->commands; cmd->type != WUY_CFLUA_TYPE_END; cmd++) {
		if (cmd->name != NULL && strcmp(cmd->name, "dynamic") == 0) {
			return cmd;
		}
	}
	return NULL;
}
void h2d_dynamic_set_container(struct h2d_dynamic_conf *dynamic,
		struct wuy_cflua_table *conf_table)
{
	/* get the offset */
	struct wuy_cflua_command *cmd = h2d_dynamic_get_cmd(conf_table);
	dynamic->container_offset = cmd->offset;

	/* duplicate a wuy_cflua_table from @conf_table, and copy default
	 * values from the container */
	dynamic->sub_table = wuy_cflua_copy_table_default(conf_table,
			h2d_dynamic_to_container(dynamic));

	/* find and clear dynamic->get_name */
	cmd = h2d_dynamic_get_cmd(dynamic->sub_table);
	cmd->u.table->commands[0].default_value.f = 0;
}

static const char *h2d_dynamic_conf_post(void *data)
{
	struct h2d_dynamic_conf *dynamic = data;

	if (!wuy_cflua_is_function_set(dynamic->get_name)) {
		return WUY_CFLUA_OK;
	}
	if (!wuy_cflua_is_function_set(dynamic->get_conf)) {
		return "dynamic get_conf must be set too";
	}
	dynamic->sub_dict = wuy_dict_new_type(WUY_DICT_KEY_STRING,
			offsetof(struct h2d_dynamic_conf, name),
			offsetof(struct h2d_dynamic_conf, dict_node));

	int expected = 0;
	int desired = atomic_fetch_add(h2d_dynamic_id, 1);
	dynamic->shared_id = wuy_shmpool_alloc(sizeof(atomic_int));
	atomic_compare_exchange_strong(dynamic->shared_id, &expected, desired);

	return WUY_CFLUA_OK;
}

static void h2d_dynamic_conf_free(void *data)
{
	struct h2d_dynamic_conf *dynamic = data;

	// TODO any sub-sub-dyn?

	if (dynamic->sub_dict != NULL) {
		wuy_dict_destroy(dynamic->sub_dict);
	}
}

static struct wuy_cflua_command h2d_dynamic_conf_commands[] = {
	/* father only */
	{	.name = "get_name",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_dynamic_conf, get_name),
		.meta_level_offset = offsetof(struct h2d_dynamic_conf, get_name_meta_level),
	},
	{	.name = "get_conf",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_dynamic_conf, get_conf),
	},
	{	.name = "is_name_blocking",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct h2d_dynamic_conf, is_name_blocking),
	},
	{	.name = "sub_max",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_dynamic_conf, sub_max),
		.default_value.n = 1000,
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "error_expire",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_dynamic_conf, error_expire),
		.default_value.n = 3,
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "log",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_dynamic_conf, log),
		.u.table = &h2d_log_conf_table,
	},

	/* sub */
	{	.name = "check_interval",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_dynamic_conf, check_interval),
		.default_value.n = 0,
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "check_filter",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_dynamic_conf, check_filter),
	},
	{	.name = "idle_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_dynamic_conf, idle_timeout),
		.default_value.n = 3600,
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{ NULL },
};

struct wuy_cflua_table h2d_dynamic_conf_table = {
	.commands = h2d_dynamic_conf_commands,
	.refer_name = "DYNAMIC",
	.post = h2d_dynamic_conf_post,
	.free = h2d_dynamic_conf_free,
};

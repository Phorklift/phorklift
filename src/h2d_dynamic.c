#include "h2d_main.h"

#define _log(level, fmt, ...) h2d_request_log_at(r, dynamic->log, level, "dynamic: " fmt, ##__VA_ARGS__)

#define _log_conf(level, fmt, ...) h2d_log_level(dynamic->log, level, "dynamic: " fmt, ##__VA_ARGS__)


static atomic_int *h2d_dynamic_id;

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

	if (sub_dyn->shmpool != NULL) {
		wuy_shmpool_release(sub_dyn->shmpool);
	}
	loop_timer_delete(sub_dyn->timer);
	wuy_dict_delete(dynamic->sub_dict, sub_dyn);
	wuy_pool_release(sub_dyn->pool);
}

static int64_t h2d_dynamic_timeout_handler(int64_t at, void *data)
{
	h2d_dynamic_delete(data);
	return 0;
}

static bool h2d_dynamic_need_get_conf(struct h2d_dynamic_conf *sub_dyn,
		struct h2d_request *r)
{
	if (sub_dyn->is_just_holder) {
		return true;
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

static struct h2d_dynamic_conf *h2d_dynamic_get_sub_dyn(struct h2d_dynamic_conf *dynamic,
		const char *name, struct h2d_request *r)
{
	struct h2d_dynamic_conf *sub_dyn = wuy_dict_get(dynamic->sub_dict, name);

	if (sub_dyn == NULL) {
		if (wuy_dict_count(dynamic->sub_dict) >= dynamic->sub_max) {
			_log(H2D_LOG_ERROR, "fail to create new because of limited");
			return H2D_PTR_ERROR;
		}

		/* create a bare sub_dyn without container, to hold the following requests */
		wuy_pool_t *pool = wuy_pool_new(1024);
		sub_dyn = wuy_pool_alloc(pool, sizeof(struct h2d_dynamic_conf));
		sub_dyn->pool = pool;
		sub_dyn->father = dynamic;
		sub_dyn->name = wuy_pool_strdup(pool, name);
		wuy_list_init(&sub_dyn->holder_wait_head);
		wuy_dict_add(dynamic->sub_dict, sub_dyn);
		sub_dyn->is_just_holder = true;
		sub_dyn->timer = loop_timer_new(h2d_loop, h2d_dynamic_timeout_handler, sub_dyn);
		loop_timer_set_after(sub_dyn->timer, 60 * 1000);
		return sub_dyn;
	}

	if (sub_dyn->error_ret != H2D_OK) {
		r->resp.status_code = sub_dyn->error_ret;
		return H2D_PTR_ERROR;
	}

	if (h2d_lua_api_thread_in_running(r)) {
		return sub_dyn;
	}

	if (sub_dyn->is_just_holder) {
		wuy_list_append(&sub_dyn->holder_wait_head, &r->list_node);
		return H2D_PTR_AGAIN;
	}

	loop_timer_set_after(sub_dyn->timer, sub_dyn->idle_timeout * 1000);
	return sub_dyn;
}

static struct h2d_dynamic_conf *h2d_dynamic_parse_sub_dyn(lua_State *L,
		struct h2d_dynamic_conf *dynamic,
		const char *name, struct h2d_request *r)
{
	if (!lua_istable(L, -1)) {
		_log(H2D_LOG_ERROR, "%s invalid table", name);
		return H2D_PTR_ERROR;
	}

	lua_xmove(L, h2d_L, 1);

	/* prepare shared-memory pool */
	char pool_name[1000];
	snprintf(pool_name, sizeof(pool_name), "/h2tpd.pid.%d.%s",
			atomic_load(dynamic->shared_id), name);
	wuy_shmpool_t *shmpool = wuy_shmpool_new(pool_name, 40*1024, 40*1024, 10);
	if (shmpool == NULL) {
		_log(H2D_LOG_ERROR, "fail in wuy_shmpool_new");
		return H2D_PTR_ERROR;
	}

	/* parse */
	wuy_pool_t *pool = wuy_pool_new(1024);
	void *container = NULL;
	const char *err = wuy_cflua_parse(h2d_L, dynamic->sub_table, &container, pool);
	if (err != WUY_CFLUA_OK) {
		_log(H2D_LOG_ERROR, "parse sub %s error: %s", name, err);
		return H2D_PTR_ERROR;
	}

	wuy_shmpool_finish(shmpool);

	_log(H2D_LOG_INFO, "sub %s get_conf() done", name);

	/* init the sub-dyn */
	struct h2d_dynamic_conf *sub_dyn = h2d_dynamic_from_container(container, dynamic);
	sub_dyn->name = wuy_pool_strdup(pool, name);
	sub_dyn->father = dynamic;
	sub_dyn->modify_time = time(NULL);
	sub_dyn->check_time = sub_dyn->modify_time;
	sub_dyn->shmpool = shmpool;
	sub_dyn->pool = pool;
	wuy_dict_add(dynamic->sub_dict, sub_dyn);

	sub_dyn->timer = loop_timer_new(h2d_loop, h2d_dynamic_timeout_handler, sub_dyn);
	loop_timer_set_after(sub_dyn->timer, sub_dyn->idle_timeout * 1000);

	return sub_dyn;
}

void *h2d_dynamic_get(struct h2d_dynamic_conf *dynamic, struct h2d_request *r)
{
	/* call get_name() */
	int name_len;
	const char *name = h2d_lua_api_call_lstring(r, dynamic->get_name, &name_len);
	if (name_len > 100) {
		_log(H2D_LOG_ERROR, "too long name");
		return H2D_PTR_ERROR;
	}
	_log(H2D_LOG_DEBUG, "get_name: %s", name);

	/* search cache by name */
	struct h2d_dynamic_conf *sub_dyn = h2d_dynamic_get_sub_dyn(dynamic, name, r);
	if (sub_dyn == H2D_PTR_ERROR || sub_dyn == H2D_PTR_AGAIN) {
		return sub_dyn;
	}

	if (!h2d_dynamic_need_get_conf(sub_dyn, r)) { /* HIT! */
		return h2d_dynamic_to_container(sub_dyn);
	}

	/* call get_conf() */
	lua_State *L = h2d_lua_api_thread_run(r, dynamic->get_conf, "sl",
			name, sub_dyn->modify_time);
	if (L == H2D_PTR_ERROR || L == H2D_PTR_AGAIN) {
		return L;
	}

	/* return value: optional status-code */
	if (lua_isnumber(L, -1)) {
		switch (lua_tointeger(L, -1)) {
		case WUY_HTTP_200:
			lua_pop(L, 1);
			break;

		case WUY_HTTP_304:
			if (sub_dyn->is_just_holder) {
				_log(H2D_LOG_ERROR, "holder %s get 304", name);
				return H2D_PTR_ERROR;
			}
			return h2d_dynamic_to_container(sub_dyn);

		case WUY_HTTP_404:
			_log(H2D_LOG_ERROR, "sub %s removed", name);
			sub_dyn->error_ret = WUY_HTTP_404;
			r->resp.status_code = WUY_HTTP_404;
			return H2D_PTR_ERROR;

		default:
			_log(H2D_LOG_ERROR, "sub %s returns %d", name, lua_tointeger(L, -1));
			goto fail;
		}
	}

	/* return value: conf-table is at L:stack[-1] now */
	struct h2d_dynamic_conf *new_sub = h2d_dynamic_parse_sub_dyn(L, dynamic, name, r);
	if (new_sub == H2D_PTR_ERROR) {
		goto fail;
	}

	h2d_dynamic_delete(sub_dyn);

	return h2d_dynamic_to_container(new_sub);

fail:
	if (sub_dyn->is_just_holder) {
		return H2D_PTR_ERROR;
	}
	return h2d_dynamic_to_container(sub_dyn); /* use stale */
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
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{ NULL },
};

struct wuy_cflua_table h2d_dynamic_conf_table = {
	.commands = h2d_dynamic_conf_commands,
	.refer_name = "DYNAMIC",
	.post = h2d_dynamic_conf_post,
	.free = h2d_dynamic_conf_free,
};

/* This file is for dynamic configration, but not dynamic module. */

#include "h2d_main.h"

#define _log(level, fmt, ...) h2d_request_log_at(r, dynamic->log, level, "dynamic: " fmt, ##__VA_ARGS__)

#define _log_conf(level, fmt, ...) h2d_conf_log_at(dynamic->log, level, "dynamic: " fmt, ##__VA_ARGS__)


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

	_log_conf(H2D_LOG_INFO, "delete %s", sub_dyn->name);

	if (sub_dyn->is_just_holder) {
		if (sub_dyn->error_ret == 0) {
			sub_dyn->error_ret = WUY_HTTP_500;
		}

		struct h2d_request *r;
		while (wuy_list_pop_type(&sub_dyn->holder_wait_head, r, list_node)) {
			h2d_request_run(r, "dynamic holder");
		}
	}

	if (sub_dyn->sub_dict != NULL && wuy_dict_count(sub_dyn->sub_dict) != 0) {
		_log_conf(H2D_LOG_INFO, "%s holds subs, so wait a minute", sub_dyn->name);
		loop_timer_set_after(sub_dyn->timer, 60 * 1000);
		return;
	}

	if (sub_dyn->shmpool != NULL) {
		wuy_shmpool_destroy(sub_dyn->shmpool);
	}
	loop_timer_delete(sub_dyn->timer);
	wuy_dict_delete(dynamic->sub_dict, sub_dyn);
	wuy_pool_destroy(sub_dyn->pool); /* this frees the container too */
}

static int64_t h2d_dynamic_timeout_handler(int64_t at, void *data)
{
	h2d_dynamic_delete(data);
	return 0;
}

static bool h2d_dynamic_need_get_conf(struct h2d_dynamic_conf *sub_dyn,
		struct h2d_request *r)
{
	if (sub_dyn->check_interval == 0) {
		return false;
	}
	time_t now = time(NULL);
	if (now - sub_dyn->check_time < sub_dyn->check_interval) {
		return false;
	}
	if (wuy_cflua_is_function_set(sub_dyn->check_filter)) {
		if (h2d_lua_call_boolean(r, sub_dyn->check_filter) != 1) {
			return false;
		}
	}
	sub_dyn->check_time = now;
	return true;
}

#include <lua5.1/lauxlib.h>
static bool h2d_dynamic_load_str_conf(lua_State *L)
{
	size_t len;
	const char *s = lua_tolstring(L, -1, &len);

	char buffer[8 + len];
	memcpy(buffer, "return ", 7);
	memcpy(buffer + 7, s, len + 1);
	if (luaL_dostring(L, buffer) != 0) {
		return false;
	}

	return true;
}

static struct h2d_dynamic_conf *h2d_dynamic_parse_sub_dyn(lua_State *L,
		struct h2d_dynamic_conf *dynamic,
		const char *name, struct h2d_request *r)
{
	if (lua_isstring(L, -1) && !h2d_dynamic_load_str_conf(L)) {
		_log(H2D_LOG_ERROR, "fail to load string: %s", lua_tostring(L, -1));
		return H2D_PTR_ERROR;
	}
	if (!lua_istable(L, -1)) {
		_log(H2D_LOG_ERROR, "%s: conf is not table but %s", name,
				lua_typename(L, lua_type(L, -1)));
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
	const void *father_container = h2d_dynamic_to_container(dynamic);
	wuy_cflua_function_t tmp_get_name = dynamic->get_name;
	dynamic->get_name = 0; /* clear father_container->dynamic.get_name temporarily to avoid inherited */
	const char *err = wuy_cflua_parse(h2d_L, dynamic->sub_table, &container,
			pool, &father_container);
	dynamic->get_name = tmp_get_name; /* recover */
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
	sub_dyn->check_time = time(NULL);
	sub_dyn->shmpool = shmpool;
	sub_dyn->pool = pool;
	wuy_dict_add(dynamic->sub_dict, sub_dyn);

	sub_dyn->timer = loop_timer_new(h2d_loop, h2d_dynamic_timeout_handler, sub_dyn);
	loop_timer_set_after(sub_dyn->timer, sub_dyn->idle_timeout * 1000);

	return sub_dyn;
}

static struct h2d_dynamic_conf *h2d_dynamic_new_holder(struct h2d_dynamic_conf *dynamic,
		const char *name)
{
	/* create a bare sub_dyn without container, to hold the following requests */
	wuy_pool_t *pool = wuy_pool_new(1024);
	struct h2d_dynamic_conf *sub_dyn = wuy_pool_alloc(pool, sizeof(struct h2d_dynamic_conf));
	sub_dyn->pool = pool;
	sub_dyn->father = dynamic;
	sub_dyn->name = wuy_pool_strdup(pool, name);
	wuy_list_init(&sub_dyn->holder_wait_head);
	wuy_dict_add(dynamic->sub_dict, sub_dyn);
	sub_dyn->is_just_holder = true;
	sub_dyn->error_timeout = dynamic->error_timeout;
	sub_dyn->timer = loop_timer_new(h2d_loop, h2d_dynamic_timeout_handler, sub_dyn);
	loop_timer_set_after(sub_dyn->timer, 60 * 1000);
	return sub_dyn;
}

void *h2d_dynamic_get(struct h2d_dynamic_conf *dynamic, struct h2d_request *r)
{
	/* call get_name() */
	int name_len;
	const char *name = h2d_lua_call_lstring(r, dynamic->get_name, &name_len);
	if (name == NULL) {
		_log(H2D_LOG_ERROR, "fail to call get_name");
		return H2D_PTR_ERROR;
	}
	if (name_len > 100) {
		_log(H2D_LOG_ERROR, "too long name");
		return H2D_PTR_ERROR;
	}
	_log(H2D_LOG_DEBUG, "get_name: %s", name);

	/* search cache by name */
	struct h2d_dynamic_conf *sub_dyn = wuy_dict_get(dynamic->sub_dict, name);

	if (sub_dyn == NULL) {
		if (wuy_dict_count(dynamic->sub_dict) >= dynamic->sub_max) {
			_log(H2D_LOG_ERROR, "fail to create new because of limited");
			return H2D_PTR_ERROR;
		}
		sub_dyn = h2d_dynamic_new_holder(dynamic, name);
		goto get_conf;
	}

	/* cache hit */
	if (h2d_lua_thread_in_running(r, dynamic->get_conf)) {
		goto get_conf;
	}
	if (sub_dyn->error_ret != 0) {
		r->resp.status_code = sub_dyn->error_ret;
		return H2D_PTR_ERROR;
	}
	if (sub_dyn->is_just_holder) {
		wuy_list_append(&sub_dyn->holder_wait_head, &r->list_node);
		return H2D_PTR_AGAIN;
	}

	loop_timer_set_after(sub_dyn->timer, sub_dyn->idle_timeout * 1000);

	if (!h2d_dynamic_need_get_conf(sub_dyn, r)) {
		return h2d_dynamic_to_container(sub_dyn); /* in most cases */
	}

	/* call get_conf() */
get_conf:
	_log(H2D_LOG_DEBUG, "get_conf");

	lua_State *L = h2d_lua_thread_run(r, dynamic->get_conf, "s", name);
	if (L == H2D_PTR_ERROR || L == H2D_PTR_AGAIN) {
		return L;
	}

	/* return value: optional status-code */
	if (lua_isnumber(L, 1)) {
		_log(H2D_LOG_DEBUG, "status-code: %ld", lua_tointeger(L, 1));

		switch (lua_tointeger(L, 1)) {
		case WUY_HTTP_200:
			break;

		case WUY_HTTP_304:
			if (sub_dyn->is_just_holder) {
				_log(H2D_LOG_ERROR, "holder %s get 304", name);
				return H2D_PTR_ERROR;
			}
			return h2d_dynamic_to_container(sub_dyn);

		case WUY_HTTP_404:
			_log(H2D_LOG_ERROR, "sub %s not exist or removed", name);
			sub_dyn->error_ret = WUY_HTTP_404;
			r->resp.status_code = WUY_HTTP_404;
			loop_timer_set_after(sub_dyn->timer, sub_dyn->error_timeout * 1000);
			return H2D_PTR_ERROR;

		default:
			_log(H2D_LOG_ERROR, "sub %s returns %d", name, lua_tointeger(L, -1));
			goto fail;
		}
	}

	/* return value: conf-table is at L:stack[-1] */
	uint64_t tag = 0;
	if (dynamic->check_interval != 0) {
		if (lua_isstring(L, -1)) {
			size_t len;
			const char *s = lua_tolstring(L, -1, &len);
			tag = wuy_vhash64(s, len);
		} else if (lua_istable(L, -1)) {
			// TODO
			_log(H2D_LOG_ERROR, "NOT SUPPORT YET: get_conf() returns table with check_interval!=0");
			return H2D_PTR_ERROR;
		} else {
			_log(H2D_LOG_ERROR, "expect string or table, but got %s",
					lua_typename(L, lua_type(L, -1)));
			return H2D_PTR_ERROR;
		}

		if (tag == sub_dyn->tag) {
			_log(H2D_LOG_INFO, "no change");
			return h2d_dynamic_to_container(sub_dyn);
		}
	}

	struct h2d_dynamic_conf *new_sub = h2d_dynamic_parse_sub_dyn(L, dynamic, name, r);
	if (new_sub == H2D_PTR_ERROR) {
		goto fail;
	}

	new_sub->tag = tag;

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

void h2d_dynamic_set_container(struct h2d_dynamic_conf *dynamic,
		struct wuy_cflua_table *conf_table)
{
	struct wuy_cflua_command *cmd;
	for (cmd = conf_table->commands; cmd->type != WUY_CFLUA_TYPE_END; cmd++) {
		if (cmd->name != NULL && strcmp(cmd->name, "dynamic") == 0) {
			break;
		}
	}
	dynamic->container_offset = cmd->offset;

	dynamic->sub_table = conf_table;
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

	if (dynamic->sub_dict != NULL) {
		assert(wuy_dict_count(dynamic->sub_dict) == 0);
		wuy_dict_destroy(dynamic->sub_dict);
	}
}

static struct wuy_cflua_command h2d_dynamic_conf_commands[] = {
	/* father only */
	{	.name = "get_name",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_dynamic_conf, get_name),
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
	{	.name = "log",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_dynamic_conf, log),
		.u.table = &h2d_log_omit_conf_table,
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
	{	.name = "error_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_dynamic_conf, error_timeout),
		.default_value.n = 1,
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

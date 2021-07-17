/* This file is for dynamic configration, but not dynamic module.
 *
 * Some configuration components can be created/updated/deleted by this.
 * By now, built-in Upstream and Path support dynamic configuration.
 * You can make any components in you module to support dynamic easily
 * if necessary.
 *
 * All actions are triggered by user-requests. They are passive.
 * You must have a clear rule (e.g. ../example/modules/forward_proxy.lua)
 * or an admin-center (e.g. Redis in ../example/modules/service_discovery.lua).
 * You can not create/update/delete the configration actively.
 * There are 2 reasons:
 *
 * 1. For example, you could write a content module and manipulate this
 *    by admin-requests actively. However the configration is not shared
 *    amount worker processes, so you can manipulate the current work
 *    process only. Share the configration is too complex. Besides, there
 *    maybe multiple machines deployed.
 *
 * 2. Assume you can manipulate this actively. But after reloading
 *    configration or restarting the process, all changes lose. You still
 *    need some place to save the rules.
 */

#include "phl_main.h"

#define _log(level, fmt, ...) phl_request_log_at(r, dynamic->log, level, "dynamic: " fmt, ##__VA_ARGS__)

#define _log_conf(level, fmt, ...) phl_conf_log_at(dynamic->log, level, "dynamic: " fmt, ##__VA_ARGS__)


static atomic_int *phl_dynamic_id;

static void *phl_dynamic_to_container(struct phl_dynamic_conf *sub_dyn)
{
	struct phl_dynamic_conf *dynamic = sub_dyn->father ? sub_dyn->father : sub_dyn;
	return ((char *)sub_dyn) - dynamic->container_offset;
}
static struct phl_dynamic_conf *phl_dynamic_from_container(void *container,
		struct phl_dynamic_conf *dynamic)
{
	return (void *)(((char *)container) + dynamic->container_offset);
}

static void phl_dynamic_delete(struct phl_dynamic_conf *sub_dyn)
{
	struct phl_dynamic_conf *dynamic = sub_dyn->father;

	_log_conf(PHL_LOG_INFO, "delete %s", sub_dyn->name);

	if (sub_dyn->is_just_holder) {
		if (sub_dyn->error_ret == 0) {
			sub_dyn->error_ret = WUY_HTTP_500;
		}

		struct phl_request *r;
		while (wuy_list_pop_type(&sub_dyn->holder_wait_head, r, list_node)) {
			phl_request_run(r, "dynamic holder");
		}
	}

	if (sub_dyn->sub_dict != NULL && wuy_dict_count(sub_dyn->sub_dict) != 0) {
		_log_conf(PHL_LOG_INFO, "%s holds subs, so wait a minute", sub_dyn->name);
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

static int64_t phl_dynamic_timeout_handler(int64_t at, void *data)
{
	phl_dynamic_delete(data);
	return 0;
}

static bool phl_dynamic_need_get_conf(struct phl_dynamic_conf *sub_dyn,
		struct phl_request *r)
{
	if (sub_dyn->check_interval == 0) {
		return false;
	}
	time_t now = time(NULL);
	if (now - sub_dyn->check_time < sub_dyn->check_interval) {
		return false;
	}
	if (wuy_cflua_is_function_set(sub_dyn->check_filter)) {
		if (phl_lua_call_boolean(r, sub_dyn->check_filter) != 1) {
			return false;
		}
	}
	sub_dyn->check_time = now;
	return true;
}

#include <lua5.1/lauxlib.h>
static bool phl_dynamic_load_str_conf(lua_State *L)
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

static struct phl_dynamic_conf *phl_dynamic_parse_sub_dyn(lua_State *L,
		struct phl_dynamic_conf *dynamic,
		const char *name, struct phl_request *r)
{
	if (lua_isstring(L, -1) && !phl_dynamic_load_str_conf(L)) {
		_log(PHL_LOG_ERROR, "fail to load string: %s", lua_tostring(L, -1));
		return PHL_PTR_ERROR;
	}
	if (!lua_istable(L, -1)) {
		_log(PHL_LOG_ERROR, "%s: conf is not table but %s", name,
				lua_typename(L, lua_type(L, -1)));
		return PHL_PTR_ERROR;
	}

	/* prepare shared-memory pool */
	char pool_name[1000];
	snprintf(pool_name, sizeof(pool_name), "/phorklift.pid.%d.%s",
			atomic_load(dynamic->shared_id), name);
	wuy_shmpool_t *shmpool = wuy_shmpool_new(pool_name, 40*1024, 40*1024, 10);
	if (shmpool == NULL) {
		_log(PHL_LOG_ERROR, "fail in wuy_shmpool_new");
		return PHL_PTR_ERROR;
	}

	/* prepare the sandbox, which would be GCed automatically */
	int sandbox_env = 0;
	if (dynamic->enable_sandbox) {
		sandbox_env = wuy_safelua_new(L);
		wuy_safelua_add_package(L, "phl");
		lua_insert(L, -2);
		sandbox_env--;
	}
	wuy_cflua_fenv = sandbox_env;

	/* parse */
	wuy_pool_t *pool = wuy_pool_new(1024);
	void *container = NULL;
	const void *father_container = phl_dynamic_to_container(dynamic);
	wuy_cflua_function_t tmp_get_name = dynamic->get_name;
	dynamic->get_name = 0; /* clear father_container->dynamic.get_name temporarily to avoid inherited */
	const char *err = wuy_cflua_parse(L, dynamic->sub_table, &container,
			pool, &father_container);
	dynamic->get_name = tmp_get_name; /* recover */
	if (err != WUY_CFLUA_OK) {
		_log(PHL_LOG_ERROR, "parse sub %s error: %s", name, err);
		wuy_shmpool_destroy(shmpool);
		wuy_pool_destroy(pool);
		return PHL_PTR_ERROR;
	}

	wuy_shmpool_finish(shmpool);

	_log(PHL_LOG_INFO, "sub %s get_conf() done", name);

	/* check and init the sub-dyn */
	struct phl_dynamic_conf *sub_dyn = phl_dynamic_from_container(container, dynamic);
	if (dynamic->enable_sandbox && !sub_dyn->enable_sandbox) {
		_log(PHL_LOG_ERROR, "can not disable sandbox");
		wuy_shmpool_destroy(shmpool);
		wuy_pool_destroy(pool);
		return PHL_PTR_ERROR;
	}

	sub_dyn->name = wuy_pool_strdup(pool, name);
	sub_dyn->father = dynamic;
	sub_dyn->check_time = time(NULL);
	sub_dyn->shmpool = shmpool;
	sub_dyn->pool = pool;
	wuy_dict_add(dynamic->sub_dict, sub_dyn);

	sub_dyn->timer = loop_timer_new(phl_loop, phl_dynamic_timeout_handler, sub_dyn);
	loop_timer_set_after(sub_dyn->timer, sub_dyn->idle_timeout * 1000);

	return sub_dyn;
}

static struct phl_dynamic_conf *phl_dynamic_new_holder(struct phl_dynamic_conf *dynamic,
		const char *name)
{
	/* create a bare sub_dyn without container, to hold the following requests */
	wuy_pool_t *pool = wuy_pool_new(1024);
	struct phl_dynamic_conf *sub_dyn = wuy_pool_alloc(pool, sizeof(struct phl_dynamic_conf));
	sub_dyn->pool = pool;
	sub_dyn->father = dynamic;
	sub_dyn->name = wuy_pool_strdup(pool, name);
	wuy_list_init(&sub_dyn->holder_wait_head);
	wuy_dict_add(dynamic->sub_dict, sub_dyn);
	sub_dyn->is_just_holder = true;
	sub_dyn->error_timeout = dynamic->error_timeout;
	sub_dyn->timer = loop_timer_new(phl_loop, phl_dynamic_timeout_handler, sub_dyn);
	loop_timer_set_after(sub_dyn->timer, 60 * 1000);
	return sub_dyn;
}

void *phl_dynamic_get(struct phl_dynamic_conf *dynamic, struct phl_request *r)
{
	/* call get_name() */
	int name_len;
	const char *name = phl_lua_call_lstring(r, dynamic->get_name, &name_len);
	if (name == NULL) {
		_log(PHL_LOG_ERROR, "fail to call get_name");
		return PHL_PTR_ERROR;
	}
	if (name_len > 100) {
		_log(PHL_LOG_ERROR, "too long name");
		return PHL_PTR_ERROR;
	}
	_log(PHL_LOG_DEBUG, "get_name: %s", name);

	/* search cache by name */
	struct phl_dynamic_conf *sub_dyn = wuy_dict_get(dynamic->sub_dict, name);

	if (sub_dyn == NULL) {
		if (wuy_dict_count(dynamic->sub_dict) >= dynamic->sub_max) {
			_log(PHL_LOG_ERROR, "fail to create new because of limited");
			return PHL_PTR_ERROR;
		}
		sub_dyn = phl_dynamic_new_holder(dynamic, name);
		goto get_conf;
	}

	/* cache hit */
	if (phl_lua_thread_in_running(r, dynamic->get_conf)) {
		goto get_conf;
	}
	if (sub_dyn->error_ret != 0) {
		r->resp.status_code = sub_dyn->error_ret;
		return PHL_PTR_ERROR;
	}
	if (sub_dyn->is_just_holder) {
		wuy_list_append(&sub_dyn->holder_wait_head, &r->list_node);
		return PHL_PTR_AGAIN;
	}

	loop_timer_set_after(sub_dyn->timer, sub_dyn->idle_timeout * 1000);

	if (!phl_dynamic_need_get_conf(sub_dyn, r)) {
		return phl_dynamic_to_container(sub_dyn); /* in most cases */
	}

	/* call get_conf() */
get_conf:
	_log(PHL_LOG_DEBUG, "get_conf");

	lua_State *L = phl_lua_thread_run(r, dynamic->get_conf, "s", name);
	if (L == PHL_PTR_ERROR || L == PHL_PTR_AGAIN) {
		return L;
	}

	/* return value: optional status-code */
	if (lua_isnumber(L, 1)) {
		_log(PHL_LOG_DEBUG, "status-code: %ld", lua_tointeger(L, 1));

		switch (lua_tointeger(L, 1)) {
		case WUY_HTTP_200:
			break;

		case WUY_HTTP_304:
			if (sub_dyn->is_just_holder) {
				_log(PHL_LOG_ERROR, "holder %s get 304", name);
				return PHL_PTR_ERROR;
			}
			return phl_dynamic_to_container(sub_dyn);

		case WUY_HTTP_404:
			_log(PHL_LOG_ERROR, "sub %s not exist or removed", name);
			sub_dyn->error_ret = WUY_HTTP_404;
			r->resp.status_code = WUY_HTTP_404;
			loop_timer_set_after(sub_dyn->timer, sub_dyn->error_timeout * 1000);
			return PHL_PTR_ERROR;

		default:
			_log(PHL_LOG_ERROR, "sub %s returns %d", name, lua_tointeger(L, -1));
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
			_log(PHL_LOG_ERROR, "NOT SUPPORT YET: get_conf() returns table with check_interval!=0");
			return PHL_PTR_ERROR;
		} else {
			_log(PHL_LOG_ERROR, "expect string or table, but got %s",
					lua_typename(L, lua_type(L, -1)));
			return PHL_PTR_ERROR;
		}

		if (tag == sub_dyn->tag) {
			_log(PHL_LOG_INFO, "no change");
			return phl_dynamic_to_container(sub_dyn);
		}
	}

	struct phl_dynamic_conf *new_sub = phl_dynamic_parse_sub_dyn(L, dynamic, name, r);
	if (new_sub == PHL_PTR_ERROR) {
		goto fail;
	}

	new_sub->tag = tag;

	phl_dynamic_delete(sub_dyn);

	return phl_dynamic_to_container(new_sub);

fail:
	if (sub_dyn->is_just_holder || dynamic->no_stale) {
		phl_dynamic_delete(sub_dyn);
		return PHL_PTR_ERROR;
	}
	return phl_dynamic_to_container(sub_dyn); /* use stale */
}

void phl_dynamic_init(void)
{
	phl_dynamic_id = wuy_shmpool_alloc(sizeof(atomic_int));
	atomic_store(phl_dynamic_id, 1);

	atexit(wuy_shmpool_cleanup);
}

void phl_dynamic_set_container(struct phl_dynamic_conf *dynamic,
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

static const char *phl_dynamic_conf_post(void *data)
{
	struct phl_dynamic_conf *dynamic = data;

	if (!wuy_cflua_is_function_set(dynamic->get_name)) {
		return WUY_CFLUA_OK;
	}
	if (!wuy_cflua_is_function_set(dynamic->get_conf)) {
		return "dynamic get_conf must be set too";
	}
	dynamic->sub_dict = wuy_dict_new_type(WUY_DICT_KEY_STRING,
			offsetof(struct phl_dynamic_conf, name),
			offsetof(struct phl_dynamic_conf, dict_node));

	int expected = 0;
	int desired = atomic_fetch_add(phl_dynamic_id, 1);
	dynamic->shared_id = wuy_shmpool_alloc(sizeof(atomic_int));
	atomic_compare_exchange_strong(dynamic->shared_id, &expected, desired);

	return WUY_CFLUA_OK;
}

static void phl_dynamic_conf_free(void *data)
{
	struct phl_dynamic_conf *dynamic = data;

	if (dynamic->sub_dict != NULL) {
		assert(wuy_dict_count(dynamic->sub_dict) == 0);
		wuy_dict_destroy(dynamic->sub_dict);
	}
}

static struct wuy_cflua_command phl_dynamic_conf_commands[] = {
	/* father only */
	{	.name = "get_name",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct phl_dynamic_conf, get_name),
		.description = "Set this and the following `get_conf` to enable dynamic. "
			"This function should return a string as name of a sub-dynamic. "
			"This function is called for each request, so it should be fast. "
			"You can not call blocking APIs (such as `subrequest`) in this function.",
	},
	{	.name = "get_conf",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct phl_dynamic_conf, get_conf),
		.description = "This function accepts a argument as sub-dynamic's name, "
			"and should return its configration, both string or Lua table type is OK. "
			"This function is called only if the sub is not existed or expired, "
			"so it need not be fast and can call blocking APIs.",
	},
	{	.name = "sub_max",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_dynamic_conf, sub_max),
		.default_value.n = 1000,
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "log",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct phl_dynamic_conf, log),
		.u.table = &phl_log_omit_conf_table,
	},
	{	.name = "no_stale",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct phl_dynamic_conf, no_stale),
		.description = "For debug only.",
	},
	{	.name = "enable_sandbox",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct phl_dynamic_conf, enable_sandbox),
	},

	/* sub */
	{	.name = "check_interval",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_dynamic_conf, check_interval),
		.default_value.n = 0,
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{	.name = "check_filter",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct phl_dynamic_conf, check_filter),
	},
	{	.name = "idle_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_dynamic_conf, idle_timeout),
		.default_value.n = 3600,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{	.name = "error_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_dynamic_conf, error_timeout),
		.default_value.n = 1,
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{ NULL },
};

struct wuy_cflua_table phl_dynamic_conf_table = {
	.commands = phl_dynamic_conf_commands,
	.refer_name = "DYNAMIC",
	.post = phl_dynamic_conf_post,
	.free = phl_dynamic_conf_free,
};

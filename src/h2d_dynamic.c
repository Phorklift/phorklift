#include "h2d_main.h"

/* Call dynamic->get_name() which returns a name.
 * Return H2D_AGAIN, H2D_ERROR or H2D_OK. */
static int h2d_dynamic_get_name(struct h2d_dynamic_conf *dynamic,
		struct h2d_request *r, const char **p_name)
{
	struct h2d_dynamic_ctx *ctx = r->dynamic_ctx;

	const char *name;
	if (dynamic->is_name_blocking) {
		h2d_request_log(r, H2D_LOG_DEBUG, "dynamic get_name() blocking");
		name = h2d_lua_api_call_lstring(r, dynamic->get_name, NULL);

	} else {
		h2d_request_log(r, H2D_LOG_DEBUG, "dynamic get_name() non-blocking");

		if (ctx->lth == NULL) {
			ctx->lth = h2d_lua_api_thread_new(dynamic->get_name, r);
		}

		int ret = h2d_lua_api_thread_resume(ctx->lth);
		if (ret != H2D_OK) {
			return ret;
		}

		name = lua_tostring(ctx->lth->L, -1);

		h2d_lua_api_thread_free(ctx->lth);
		ctx->lth = NULL;
	}

	if (name == NULL) {
		return H2D_ERROR;
	}

	*p_name = name;
	return H2D_OK;
}

static void *h2d_dynamic_to_container(struct h2d_dynamic_conf *dynamic)
{
	return ((char *)dynamic) - dynamic->container_offset;
}
static struct h2d_dynamic_conf *h2d_dynamic_from_container(void *container,
		struct h2d_dynamic_conf *dynamic)
{
	return (void *)(((char *)container) + dynamic->container_offset);
}

static void h2d_dynamic_delete(struct h2d_dynamic_conf *dynamic,
		struct h2d_dynamic_conf *sub_dyn)
{
	wuy_dict_delete(dynamic->sub_dict, sub_dyn);
}

/* Call dynamic->get_conf(), which accepts 2 arguments (name, last_modify_time)
 * and returns WUY_HTTP_200 (with conf-table), WUY_HTTP_304, WUY_HTTP_404
 * or WUY_HTTP_500.
 *
 * If WUY_HTTP_200 is returned from get_conf(), we parse the conf-table into *p_dynsub.
 * Otherwise, return H2D_AGAIN, H2D_ERROR, or other WUY_HTTP_xxx */
static int h2d_dynamic_get_conf(struct h2d_dynamic_conf *dynamic,
		struct h2d_request *r)
{
	h2d_request_log(r, H2D_LOG_DEBUG, "dynamic get_conf()");

	struct h2d_dynamic_ctx *ctx = r->dynamic_ctx;

	if (ctx->lth == NULL) {
		ctx->lth = h2d_lua_api_thread_new(dynamic->get_conf, r);
		lua_pushstring(ctx->lth->L, ctx->sub_dyn->name);
		lua_pushinteger(ctx->lth->L, ctx->sub_dyn->modify_time);
		h2d_lua_api_thread_set_argn(ctx->lth, 2);
	}

	int ret = h2d_lua_api_thread_resume(ctx->lth);
	if (ret != H2D_OK) {
		return ret;
	}

	/* first return value: WUY_HTTP_200/304/404/500 */
	switch (lua_tointeger(ctx->lth->L, 1)) {
	case WUY_HTTP_200:
		/* goto parse */
		break;
	case WUY_HTTP_304:
		if (ctx->sub_dyn->is_just_holder) {
			return H2D_ERROR;
		}
		return H2D_OK;
	case WUY_HTTP_404:
		h2d_dynamic_delete(dynamic, ctx->sub_dyn);
		return WUY_HTTP_404;
	default:
		return WUY_HTTP_500;
	}

	/* second return value: conf-table */
	if (lua_gettop(ctx->lth->L) != 2 || !lua_istable(ctx->lth->L, -1)) {
		printf("invalid get_conf() return\n");
		return H2D_ERROR;
	}

	lua_xmove(ctx->lth->L, h2d_L, 1);
	h2d_lua_api_thread_free(ctx->lth);
	ctx->lth = NULL;

	/* parse */
	void *container = NULL;
	int err = wuy_cflua_parse(h2d_L, dynamic->container_table, &container);
	if (err < 0) {
		printf("parse dynamic sub error: %s\n", wuy_cflua_strerror(h2d_L, err));
		return H2D_ERROR;
	}

	/* replace */
	struct h2d_dynamic_conf *new_sub = h2d_dynamic_from_container(container, dynamic);
	new_sub->name = ctx->sub_dyn->name;
	ctx->sub_dyn->name = NULL;
	new_sub->create_time = ctx->sub_dyn->create_time;
	h2d_dynamic_delete(dynamic, ctx->sub_dyn);

	new_sub->modify_time = time(NULL);
	new_sub->access_time = new_sub->modify_time;
	new_sub->check_time = new_sub->modify_time;
	wuy_dict_add(dynamic->sub_dict, new_sub);

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
	h2d_request_log(r, H2D_LOG_DEBUG, "h2d_dynamic_get()");

	struct h2d_dynamic_ctx *ctx = r->dynamic_ctx;
	if (ctx == NULL) {
		ctx = calloc(1, sizeof(struct h2d_dynamic_ctx));
		r->dynamic_ctx = ctx;
	}

	if (ctx->sub_dyn != NULL) {
		goto state_get_conf;
	}

	/* get name to ctx->name */
	const char *name;
	int ret = h2d_dynamic_get_name(dynamic, r, &name);
	if (ret != H2D_OK) {
		goto not_ok;
	}

	/* search cache by name */
	ctx->sub_dyn = wuy_dict_get(dynamic->sub_dict, name);

	if (ctx->sub_dyn == NULL) {
		h2d_request_log(r, H2D_LOG_DEBUG, "dynamic new holder %s", name);
		ctx->sub_dyn = calloc(1, sizeof(struct h2d_dynamic_conf));
		ctx->sub_dyn->name = strdup(name);
		ctx->sub_dyn->create_time = time(NULL);
		ctx->sub_dyn->is_just_holder = true;
		wuy_dict_add(dynamic->sub_dict, ctx->sub_dyn);

	} else {
		h2d_request_log(r, H2D_LOG_DEBUG, "dynamic hit %s", name);

		ret = ctx->sub_dyn->error_ret;
		if (ret != H2D_OK) {
			goto not_ok;
		}
		if (!h2d_dynamic_need_check_conf(ctx->sub_dyn, r)) {
			return h2d_dynamic_to_container(ctx->sub_dyn);
		}

		/* also get_conf() to check */
		h2d_request_log(r, H2D_LOG_DEBUG, "dynamic check %s", name);
	}

state_get_conf:

	ret = h2d_dynamic_get_conf(dynamic, r);
	if (ret != H2D_OK) {
		goto not_ok;
	}

	void *container = h2d_dynamic_to_container(ctx->sub_dyn);
	ctx->sub_dyn = NULL;
	return container;

not_ok:
	if (ret != H2D_AGAIN) {
		r->resp.status_code = (ret == H2D_ERROR) ? WUY_HTTP_500 : ret;
		if (ctx->sub_dyn != NULL) {
			ctx->sub_dyn->error_ret = ret;
		}
	}
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
	free(ctx);
	r->dynamic_ctx = NULL;
}

static bool h2d_dynamic_sub_begin = false;
void h2d_dynamic_init(void)
{
	h2d_dynamic_sub_begin = true;
}

bool h2d_dynamic_set_container_table(struct h2d_dynamic_conf *dynamic,
		struct wuy_cflua_table *conf_table)
{
	if (dynamic->container_table != NULL) {
		if (dynamic->container_table != conf_table) {
			printf("Error: different container_table for one dynamic\n");
			return false;
		}
		return true;
	}

	dynamic->container_table = conf_table;

	for (struct wuy_cflua_command *cmd = conf_table->commands; cmd != NULL; cmd++) {
		if (cmd->name != NULL && strcmp(cmd->name, "dynamic") == 0) {
			dynamic->container_offset = cmd->offset;
			return true;
		}
	}

	printf("no dynamic command found\n");
	return false;
}

static bool h2d_dynamic_conf_post(void *data)
{
	struct h2d_dynamic_conf *dynamic = data;

	if (h2d_dynamic_sub_begin) { /* dynamic sub */
		dynamic->get_name = 0;
		return true;
	}

	if (!wuy_cflua_is_function_set(dynamic->get_name)) {
		return true;
	}
	if (!wuy_cflua_is_function_set(dynamic->get_conf)) {
		printf("dynamic get_conf must be set too\n");
		return false;
	}
	dynamic->sub_dict = wuy_dict_new_type(WUY_DICT_KEY_STRING,
			offsetof(struct h2d_dynamic_conf, name),
			offsetof(struct h2d_dynamic_conf, dict_node));

	return true;
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

	/* sub */
	{	.name = "check_interval",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_dynamic_conf, check_interval),
		.default_value.n = 600,
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
	.post = h2d_dynamic_conf_post,
};

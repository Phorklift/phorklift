#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>

#include "h2d_main.h"

struct h2d_lua_conf {
	wuy_cflua_function_t	content;
	wuy_cflua_function_t	before_host;
	wuy_cflua_function_t	req_headers;
	wuy_cflua_function_t	req_body;
	wuy_cflua_function_t	resp_headers;
	wuy_cflua_function_t	resp_body;
};

struct h2d_lua_ctx {
	lua_State		*L;
	uint8_t			*resp_body_buf;
	int			resp_body_len;

	int			(*resume_handler)(struct h2d_request *r);
};

extern struct h2d_module h2d_lua_module;


/* thread */

static struct h2d_request *h2d_lua_current_request;

static int h2d_lua_thread_resume(struct h2d_request *r)
{
	h2d_lua_current_request = r;

	struct h2d_lua_ctx *ctx = r->module_ctxs[h2d_lua_module.index];

	int argn = 0;
	if (ctx->resume_handler != NULL) {
		argn = ctx->resume_handler(r);
		if (argn < 0) {
			return H2D_ERROR;
		}
		ctx->resume_handler = NULL;
	}

	int ret = lua_resume(ctx->L, argn);
	printf("h2d_lua_thread_resume %d\n", ret);
	if (ret == LUA_YIELD) {
		return H2D_AGAIN;
	}
	if (ret != 0) {
		return H2D_ERROR;
	}

	// TODO read return values
	const char *str = lua_tostring(ctx->L, -1);
	if (str==NULL) {
		printf("null str\n");
		return H2D_ERROR;
	}
	memcpy(ctx->resp_body_buf, str, strlen(str));
	ctx->resp_body_len = strlen(str);
	h2d_request_active(r);
	return H2D_OK;
}

static lua_State *h2d_lua_thread_new(wuy_cflua_function_t entry)
{
	lua_State *new_L = lua_newthread(h2d_L);
	lua_rawgeti(h2d_L, LUA_REGISTRYINDEX, entry);
	lua_xmove(h2d_L, new_L, 1);

	/* mark it to avoid destroied by GC */
	/* TODO i am not sure whether this is the right way ... */
	lua_pushlightuserdata(h2d_L, new_L); /* use pointer as key */
	lua_insert(h2d_L, -2); /* use thread as value */
	lua_settable(h2d_L, LUA_REGISTRYINDEX);

	return new_L;
}


/* APIs */

static int64_t h2d_lua_api_sleep_timeout(int64_t at, void *data)
{
	// XXX the request may closed yet!!!
	printf("Lua timer finish.\n");
	h2d_lua_thread_resume(data);
	return -1;
}
static int h2d_lua_api_sleep(lua_State *L)
{
	loop_timer_t *timer = loop_timer_new(h2d_loop, h2d_lua_api_sleep_timeout,
			h2d_lua_current_request);

	lua_Number value = lua_tonumber(L, -1);
	loop_timer_set_after(timer, value * 1000); /* second -> ms */
	printf("Lua add timer: %f\n", value);
	return lua_yield(L, 0);
}

static int h2d_lua_api_url(lua_State *L)
{
	struct h2d_request *r = h2d_lua_current_request;
	lua_pushstring(L, h2d_header_value(r->req.url));
	return 1;
}

static int h2d_lua_api_headers(lua_State *L)
{
	lua_newtable(L);

	struct h2d_request *r = h2d_lua_current_request;
	struct h2d_header *h;
	for (h = r->req.buffer; h->name_len != 0; h = h2d_header_next(h)) {
		lua_pushstring(L, h2d_header_value(h));
		lua_setfield(L, -2, h->str);
	}

	return 1;
}

static int h2d_lua_api_subrequest_resume(struct h2d_request *r)
{
	struct h2d_lua_ctx *ctx = r->module_ctxs[h2d_lua_module.index];

	assert(r->subr != NULL);
	printf("push: %d %ld\n", r->subr->resp.status_code, r->subr->c->send_buf_pos - r->subr->c->send_buffer);
	lua_pushnumber(ctx->L, r->subr->resp.status_code);
	lua_pushlstring(ctx->L, (char *)r->subr->c->send_buffer, r->subr->c->send_buf_pos - r->subr->c->send_buffer);

	r->subr->father = NULL;
	h2d_request_close(r->subr);
	r->subr = NULL;

	return 2;
}
static int h2d_lua_api_subrequest(lua_State *L)
{
	size_t len;
	const char *url = lua_tolstring(L, -1, &len);
	struct h2d_request *subr = h2d_request_subreq_new(h2d_lua_current_request);
	subr->req.url = subr->req.buffer;
	subr->req.next = h2d_header_add(subr->req.next, ":url", 4, url, len);

	struct h2d_lua_ctx *ctx = h2d_lua_current_request->module_ctxs[h2d_lua_module.index];
	ctx->resume_handler = h2d_lua_api_subrequest_resume;

	return lua_yield(L, 0);
}

static const struct luaL_Reg h2d_lua_api_list [] = {
	{ "url", h2d_lua_api_url },
	{ "headers", h2d_lua_api_headers },
	{ "sleep", h2d_lua_api_sleep },
	{ "subrequest", h2d_lua_api_subrequest },
	{ NULL, NULL }  /* sentinel */
};
static bool h2d_lua_master_post(void)
{
	luaL_register(h2d_L, "h2d", h2d_lua_api_list);
	return true;
}


/* content handlers */

static int h2d_lua_generate_response_headers(struct h2d_request *r)
{
	struct h2d_lua_conf *conf = r->conf_path->module_confs[h2d_lua_module.index];
	struct h2d_lua_ctx *ctx = r->module_ctxs[h2d_lua_module.index];

	if (ctx == NULL) {
		ctx = malloc(sizeof(struct h2d_lua_ctx));
		bzero(ctx, sizeof(struct h2d_lua_ctx));
		ctx->L = h2d_lua_thread_new(conf->content);
		ctx->resp_body_buf = malloc(4096); // TODO
		r->module_ctxs[h2d_lua_module.index] = ctx;
	}

	int ret = h2d_lua_thread_resume(r);
	if (ret != H2D_OK) {
		return ret;
	}

	r->resp.status_code = 200;
	r->resp.content_length = ctx->resp_body_len;
	return H2D_OK;
}
static int h2d_lua_generate_response_body(struct h2d_request *r, uint8_t *buf, int len)
{
	struct h2d_lua_ctx *ctx = r->module_ctxs[h2d_lua_module.index];
	memcpy(buf, ctx->resp_body_buf, ctx->resp_body_len);
	return ctx->resp_body_len;
}

static void h2d_lua_ctx_free(struct h2d_request *r)
{
	struct h2d_lua_ctx *ctx = r->module_ctxs[h2d_lua_module.index];
	free(ctx->resp_body_buf);

	if (ctx->L != NULL) {
		/* unref it, and wait GC */
		lua_pushlightuserdata(h2d_L, ctx->L);
		lua_pushnil(h2d_L);
		lua_settable(h2d_L, LUA_REGISTRYINDEX);
		ctx->L = NULL;
	}
}

/* configuration */

static struct wuy_cflua_command h2d_lua_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_lua_conf, content),
		.flags = WUY_CFLUA_FLAG_UNIQ_MEMBER,
	},
	{	.name = "before_host",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_lua_conf, before_host),
	},
	{	.name = "req_headers",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_lua_conf, req_headers),
	},
	{	.name = "req_body",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_lua_conf, req_body),
	},
	{	.name = "resp_headers",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_lua_conf, resp_headers),
	},
	{	.name = "resp_body",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_lua_conf, resp_body),
	},
	{ NULL }
};
struct h2d_module h2d_lua_module = {
	.name = "lua",
	.command_path = {
		.name = "lua",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) {
			.commands = h2d_lua_conf_commands,
			.size = sizeof(struct h2d_lua_conf),
		}
	},

	.content = {
		.response_headers = h2d_lua_generate_response_headers,
		.response_body = h2d_lua_generate_response_body,
	},

	.ctx_free = h2d_lua_ctx_free,

	.master_post = h2d_lua_master_post,
};

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "h2d_main.h"

extern struct h2d_request *h2d_lua_api_request;

struct h2d_lua_thread {
	lua_State		*L;
	int			(*post) (struct h2d_request *);
	struct h2d_request	*r;
	int			nresults;
};

static int h2d_lua_thread_resume(struct h2d_lua_thread *thread);
static int64_t h2d_lua_api_sleep_timeout(int64_t at, void *data)
{
	h2d_lua_thread_resume(data);
	return -1;
}

static int h2d_lua_thread_resume(struct h2d_lua_thread *thread)
{
	h2d_lua_api_request = thread->r;

	int ret = lua_resume(thread->L, 0);
	printf("h2d_lua_thread_resume %d\n", ret);
	if (ret == LUA_YIELD) {
		/* timer */
		lua_Number value = lua_tonumber(thread->L, -1);
		int64_t after_ms = value * 1000; /* second -> ms */
		printf("add timer: %ld\n", after_ms);

		loop_timer_t *timer = loop_timer_new(h2d_loop, h2d_lua_api_sleep_timeout, thread);
		loop_timer_set_after(timer, after_ms);
		return H2D_AGAIN;
	} else if (ret != 0) {
		printf("lua_resume fail: %d\n", ret);
		return H2D_ERROR;
	} else {
		lua_xmove(thread->L, h2d_L, thread->nresults);
		int ret = thread->post(thread->r);
		lua_pop(h2d_L, thread->nresults + 1);
		free(thread);
		return ret;
	}
}

int h2d_lua_thread_new(wuy_cflua_function_t entry, int nresults,
		int (*post)(struct h2d_request *), struct h2d_request *r)
{
	struct h2d_lua_thread *thread = malloc(sizeof(struct h2d_lua_thread));

	thread->L = lua_newthread(h2d_L);
	thread->post = post;
	thread->r = r;
	thread->nresults = nresults;

	/* entry function */
	lua_rawgeti(h2d_L, LUA_REGISTRYINDEX, entry);
	lua_xmove(h2d_L, thread->L, 1);

	return h2d_lua_thread_resume(thread);
}

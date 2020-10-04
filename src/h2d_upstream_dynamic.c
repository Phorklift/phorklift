#include "h2d_main.h"

/* Call upstream->get_name() which returns a name, and save it to ctx->name.
 * Return H2D_AGAIN, H2D_ERROR or H2D_OK. */
static int h2d_upstream_dynamic_get_name(struct h2d_upstream_conf *upstream,
		struct h2d_request *r)
{
	struct h2d_upstream_dynamic_ctx *ctx = r->dynamic_upstream;

	const char *name;
	if (upstream->dynamic.is_name_blocking) {
		h2d_request_log(r, H2D_LOG_DEBUG, "dynamic upstream get_name() blocking");
		name = h2d_lua_api_call_lstring(r, upstream->dynamic.get_name, NULL);

	} else {
		h2d_request_log(r, H2D_LOG_DEBUG, "dynamic upstream get_name() non-blocking");

		if (ctx->lth == NULL) {
			ctx->lth = h2d_lua_api_thread_new(upstream->dynamic.get_name, r);
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

	ctx->name = strdup(name);
	return H2D_OK;
}

static struct h2d_upstream_conf *h2d_upstream_dynamic_dup(
		struct h2d_upstream_conf *upstream, const char *name)
{
	struct h2d_upstream_conf *subups = malloc(sizeof(struct h2d_upstream_conf));
	if (subups == NULL) {
		return NULL;
	}
	*subups = *upstream; /* inherit confs */
	subups->name = strdup(name); // XXX
	subups->address_num = 0;
	subups->dynamic.create_time = time(NULL);
	subups->dynamic.access_time = subups->dynamic.create_time;
	subups->dynamic.modify_time = subups->dynamic.create_time;
	subups->dynamic.check_time = subups->dynamic.create_time;
	subups->dynamic.get_name = 0;
	subups->dynamic.sub_dict = NULL;
	subups->lb_confs[0] = NULL; /* roundrobin is special */
	wuy_list_init(&subups->dynamic.wait_head);
	wuy_dict_add(upstream->dynamic.sub_dict, subups);
	return subups;
}

/* Call upstream->get_conf(), which accepts 2 arguments (name, last_check_time)
 * and returns WUY_HTTP_200 (with conf-table), WUY_HTTP_304, WUY_HTTP_404
 * or WUY_HTTP_500.
 *
 * If WUY_HTTP_200 is returned from get_conf(), we parse the conf-table into subups.
 * Otherwise, return H2D_AGAIN, H2D_ERROR, or other WUY_HTTP_xxx */
static int h2d_upstream_dynamic_get_conf(struct h2d_upstream_conf *upstream,
		struct h2d_request *r, struct h2d_upstream_conf **p_subups)
{
	h2d_request_log(r, H2D_LOG_DEBUG, "dynamic upstream get_conf()");

	struct h2d_upstream_dynamic_ctx *ctx = r->dynamic_upstream;

	if (ctx->lth == NULL) {
		ctx->lth = h2d_lua_api_thread_new(upstream->dynamic.get_conf, r);
		lua_pushstring(ctx->lth->L, ctx->name);
		lua_pushinteger(ctx->lth->L, upstream->dynamic.modify_time);
		h2d_lua_api_thread_set_argn(ctx->lth, 2);
	}

	int ret = h2d_lua_api_thread_resume(ctx->lth);
	if (ret != H2D_OK) {
		return ret;
	}

	/* first return value: WUY_HTTP_200/304/404/500 */
	ret = lua_tointeger(ctx->lth->L, 1);
	if (ret != WUY_HTTP_200) {
		h2d_lua_api_thread_free(ctx->lth);
		ctx->lth = NULL;
		return ret;
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
	struct wuy_cflua_table sub_table = h2d_upstream_conf_table;
	sub_table.size = 0; /* parse into @subups, but not allocate new container */
	sub_table.no_default_value = true; /* @subups was duplicated from father upstream as default value*/

	struct h2d_upstream_conf *subups = h2d_upstream_dynamic_dup(upstream, ctx->name);

	int err = wuy_cflua_parse(h2d_L, &sub_table, subups);
	if (err < 0) {
		printf("parse dynamic upstream error: %s\n", wuy_cflua_strerror(h2d_L, err));
		return H2D_ERROR;
	}

	if (wuy_cflua_is_function_set(subups->dynamic.get_name)) {
		printf("dynamic_get is not allowed in dynamic upstream\n");
		return H2D_ERROR;
	}

	*p_subups = subups;
	return WUY_HTTP_200;
}

static int h2d_upstream_dynamic_check_conf(struct h2d_upstream_conf *subups,
		struct h2d_request *r, struct h2d_upstream_conf **p_newsub)
{
	struct h2d_upstream_dynamic_ctx *ctx = r->dynamic_upstream;
	if (ctx->lth != NULL) {
		goto check;
	}

	/* need check? */
	if (subups->dynamic.check_interval == 0) {
		return H2D_OK;
	}
	time_t now = time(NULL);
	if (now - subups->dynamic.check_time < subups->dynamic.check_interval) {
		return H2D_OK;
	}
	if (wuy_cflua_is_function_set(subups->dynamic.check_filter)) {
		if (h2d_lua_api_call_boolean(r, subups->dynamic.check_filter) != 1) {
			return H2D_OK;
		}
	}
	subups->dynamic.check_time = now;

	h2d_request_log(r, H2D_LOG_DEBUG, "dynamic upstream check %s", subups->name);
check:;
	struct h2d_upstream_conf *newsub = NULL;
	int ret = h2d_upstream_dynamic_get_conf(subups, r, &newsub);
	if (ret == WUY_HTTP_200 || ret == WUY_HTTP_404) {
		// h2d_upstream_dynamic_delete(subups);
		*p_newsub = newsub;
	}
	return ret;
}

#if 0
static void h2d_upstream_dynamic_single_host_clear(struct h2d_upstream_conf *upstream)
{
	struct h2d_upstream_dynamic_conf *d = &upstream->dynamic;

	time_t now = time(NULL);
	struct h2d_upstream_conf *subups, *safe;
	wuy_list_iter_reverse_safe_type(&upstream->dynamic.single_host_head,
			subups, safe, list_node) {
		if (now - subups->dynamic.access_time < d->single_host_idle_timeout
				&& d->single_host_num <= d->single_host_max) {
			break;
		}

		/* delete subups */
		printf("delete single host upstream %s %s\n", upstream->name, subups->name);
		wuy_dict_delete(d->sub_dict, subups);
		// wuy_list_delete(&subups->list_node);

		subups->loadbalance->free(subups);
		struct h2d_upstream_address *address;
		while (wuy_list_pop_type(&subups->address_head, address, upstream_node)) {
			free(address);
		}
		free((void *)subups->name);
		free(subups->hostnames);
		free(subups);

		d->single_host_num--;
	}
}
#endif

struct h2d_upstream_conf *h2d_upstream_dynamic_get(struct h2d_upstream_conf *upstream,
		struct h2d_request *r)
{
	struct h2d_upstream_dynamic_ctx *ctx = r->dynamic_upstream;
	if (ctx == NULL) {
		ctx = calloc(1, sizeof(struct h2d_upstream_dynamic_ctx));
		r->dynamic_upstream = ctx;
	}

	if (ctx->name != NULL) {
		goto state_get_conf;
	}

	/* get name to ctx->name */
	int ret = h2d_upstream_dynamic_get_name(upstream, r);
	if (ret != H2D_OK) {
		goto not_ok;
	}

state_get_conf:;

	/* search cache by name */
	struct h2d_upstream_conf *subups = wuy_dict_get(upstream->dynamic.sub_dict, ctx->name);

	if (subups == NULL) {
		h2d_request_log(r, H2D_LOG_DEBUG, "dynamic upstream new %s", ctx->name);
		ret = h2d_upstream_dynamic_get_conf(upstream, r, &subups);
		if (ret != WUY_HTTP_200) {
			goto not_ok;
		}
	} else {
		ret = h2d_upstream_dynamic_check_conf(subups, r, &subups);
		if (ret == H2D_AGAIN || ret == WUY_HTTP_404) { /* ignore H2D_ERROR */
			goto not_ok;
		}
	}

	if (subups->address_num == 0) {
		/* wait for hostname resolving */
		if (wuy_list_node_linked(&r->list_node)) {
			printf("!!!!! where does it linked???\n");
			abort();
		}
		wuy_list_append(&subups->dynamic.wait_head, &r->list_node);
		return NULL;
	}

	// h2d_upstream_dynamic_single_host_clear(upstream); /* routine */
	return subups;

not_ok:
	if (ret == H2D_AGAIN) {
		return NULL;
	}
	r->resp.status_code = (ret == H2D_ERROR) ? WUY_HTTP_500 : ret;
	return NULL;
}

void h2d_upstream_dynamic_ctx_free(struct h2d_request *r)
{
	struct h2d_upstream_dynamic_ctx *ctx = r->dynamic_upstream;
	if (ctx == NULL) {
		return;
	}

	if (ctx->lth != NULL) {
		h2d_lua_api_thread_free(ctx->lth);
	}
	free((void *)ctx->name);
	free(ctx);
	r->dynamic_upstream = NULL;
}

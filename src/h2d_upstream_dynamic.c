#include "h2d_main.h"

/* Call upstream->get_name() which returns a name.
 * Return H2D_AGAIN, H2D_ERROR or H2D_OK. */
static int h2d_upstream_dynamic_get_name(struct h2d_upstream_conf *upstream,
		struct h2d_request *r, const char **p_name)
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

	*p_name = name;
	return H2D_OK;
}

/* Call upstream->get_conf(), which accepts 2 arguments (name, last_check_time)
 * and returns WUY_HTTP_200 (with conf-table), WUY_HTTP_304, WUY_HTTP_404
 * or WUY_HTTP_500.
 *
 * If WUY_HTTP_200 is returned from get_conf(), we parse the conf-table into
 * subups, and return H2D_OK.
 * Otherwise, return H2D_AGAIN, H2D_ERROR, or other WUY_HTTP_xxx */
static int h2d_upstream_dynamic_get_conf(struct h2d_upstream_conf *upstream,
		struct h2d_request *r, struct h2d_upstream_conf *subups)
{
	h2d_request_log(r, H2D_LOG_DEBUG, "dynamic upstream get_conf()");

	struct h2d_upstream_dynamic_ctx *ctx = r->dynamic_upstream;

	if (ctx->lth == NULL) {
		ctx->lth = h2d_lua_api_thread_new(upstream->dynamic.get_conf, r);
		lua_pushstring(ctx->lth->L, subups->name);
		lua_pushinteger(ctx->lth->L, subups->dynamic.check_time);
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

	int err = wuy_cflua_parse(h2d_L, &sub_table, subups);
	if (err < 0) {
		printf("parse dynamic upstream error: %s\n", wuy_cflua_strerror(h2d_L, err));
		return H2D_ERROR;
	}

	if (wuy_cflua_is_function_set(subups->dynamic.get_name)) {
		printf("dynamic_get is not allowed in dynamic upstream\n");
		return H2D_ERROR;
	}

	return H2D_OK;
}

static int h2d_upstream_dynamic_check_conf(struct h2d_upstream_conf *subups,
		struct h2d_request *r)
{
	return H2D_OK;

#if 0
	if (r->dynamic_upstream.lth != NULL) {
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

	/* check */
	int ret = h2d_upstream_dynamic_get_conf(upstream, r, subups);
	if (ret != H2D_OK) {
		return ret;
	}
#endif
}

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
		wuy_list_delete(&subups->list_node);

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

struct h2d_upstream_conf *h2d_upstream_dynamic_get(struct h2d_upstream_conf *upstream,
		struct h2d_request *r)
{
	struct h2d_upstream_dynamic_ctx *ctx = r->dynamic_upstream;
	if (ctx == NULL) {
		ctx = calloc(1, sizeof(struct h2d_upstream_dynamic_ctx));
		r->dynamic_upstream = ctx;
	}

	struct h2d_upstream_conf *subups = ctx->subups;

	if (ctx->lth != NULL) {
		/* resume the yielded states, if any */
		if (ctx->subups == NULL) {
			/* yielded at get_name(), no need goto */
		} else if (ctx->check_ups != NULL) {
			goto state_check_conf;
		} else {
			goto state_new_conf;
		}
	}

	const char *name;
	int ret = h2d_upstream_dynamic_get_name(upstream, r, &name);
	if (ret != H2D_OK) {
		goto not_ok;
	}

	/* search cache by name */
	subups = wuy_dict_get(upstream->dynamic.sub_dict, name);
	if (subups != NULL) {
		h2d_request_log(r, H2D_LOG_DEBUG, "dynamic upstream hit %s", name);
		if (name[0] != '@') {
			/* single-hostname: update LRU */
			subups->dynamic.access_time = time(NULL);
			wuy_list_delete(&subups->list_node);
			wuy_list_insert(&upstream->dynamic.single_host_head, &subups->list_node);
		} else {
state_check_conf:
			/* named-conf: check conf periodly */
			ret = h2d_upstream_dynamic_check_conf(subups, r);
			if (ret == H2D_AGAIN) { /* ignore H2D_ERROR */
				goto not_ok;
			}
		}
		goto out;
	}

	/* cache miss, so create new sub-upstream */
	subups = malloc(sizeof(struct h2d_upstream_conf));
	*subups = *upstream; /* inherit confs */
	subups->name = strdup(name);
	subups->address_num = 0;
	subups->dynamic.create_time = time(NULL);
	subups->dynamic.get_name = 0;
	subups->dynamic.sub_dict = NULL;
	subups->lb_confs[0] = NULL; /* roundrobin is special */
	wuy_list_init(&subups->dynamic.wait_head);
	wuy_dict_add(upstream->dynamic.sub_dict, subups);

	if (name[0] != '@') {
		/* single-hostname */
		subups->hostnames = calloc(2, sizeof(struct h2d_upstream_hostname));
		subups->hostnames->name = strdup(subups->name);
		if (!h2d_upstream_conf_table.post(subups)) {
			printf("!!! sub upstream fail\n");
			ret = H2D_ERROR;
			goto not_ok;
		}

		upstream->dynamic.single_host_num++;
		subups->dynamic.access_time = subups->dynamic.create_time;
		wuy_list_insert(&upstream->dynamic.single_host_head, &subups->list_node);

	} else {
		/* named-conf: get_conf() by name */
state_new_conf:
		ret = h2d_upstream_dynamic_get_conf(upstream, r, subups);
		if (ret != H2D_OK) {
			goto not_ok;
		}

		subups->dynamic.update_time = subups->dynamic.create_time;
		subups->dynamic.check_time = subups->dynamic.create_time;
		wuy_list_insert(&upstream->dynamic.name_conf_head, &subups->list_node);
	}

out:
	if (subups->address_num == 0) { /* wait for hostname resolving */
		if (wuy_list_node_linked(&r->list_node)) {
			printf("!!!!! where does it linked???\n");
			abort();
		}
		wuy_list_append(&subups->dynamic.wait_head, &r->list_node);
		return NULL;
	}

	h2d_upstream_dynamic_single_host_clear(upstream); /* routine */
	return subups;

not_ok: /* H2D_ERROR or H2D_AGAIN */
	if (ret == H2D_ERROR) {
		if (r->resp.status_code != 0) {
			r->resp.status_code = WUY_HTTP_500;
		}
	} else {
		ctx->subups = subups;
	}

	return NULL;
}

void h2d_upstream_dynamic_ctx_free(struct h2d_request *r)
{
	struct h2d_upstream_dynamic_ctx *ctx = r->dynamic_upstream;
	if (ctx == NULL) {
		return;
	}

	if (ctx->subups != NULL) {
		// wuy_dict_delete(upstream->dynamic.sub_dict, subups); // XXX
		wuy_list_delete(&ctx->subups->list_node);
		free(ctx->subups);
	}
	if (ctx->lth != NULL) {
		h2d_lua_api_thread_free(ctx->lth);
	}
	free(ctx);
	r->dynamic_upstream = NULL;
}

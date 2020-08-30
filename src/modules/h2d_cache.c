#include "h2d_main.h"

struct h2d_cache_item {
	wuy_dict_node_t		dict_node;
	wuy_list_node_t		lru_node;
	const char		*key;
	int			status_code;
	wuy_slist_t		headers;
	time_t			expire_at;
	size_t			content_length;
	uint8_t			body[0];
};

struct h2d_cache_conf {
	int			size;
	wuy_cflua_function_t	key;
	int			max_length;
	int			default_expire;
	int			force_expire;
	const char		**include_types;
	const char		**exclude_types;

	wuy_dict_t		*cache;
};

struct h2d_module h2d_cache_module;

#define H2D_CACHE_CTX_HIT ((struct h2d_cache_item *)0x1)

extern struct h2d_request *h2d_lua_current_request;
static int h2d_cache_process_headers(struct h2d_request *r)
{
	struct h2d_cache_conf *conf = r->conf_path->module_confs[h2d_cache_module.index];
	if (conf->size == 0) {
		return H2D_OK;
	}

	struct h2d_cache_item *item;
	if (h2d_conf_is_zero_function(conf->key)) {
		item = wuy_dict_get(conf->cache, r->req.url);

	} else {
		h2d_lua_current_request = r;
		lua_rawgeti(h2d_L, LUA_REGISTRYINDEX, conf->key);
		if (lua_pcall(h2d_L, 0, 1, 0) != 0) {
			printf("lua_pcall fail: %s\n", lua_tostring(h2d_L, -1));
			lua_pop(h2d_L, 1);
			return WUY_HTTP_500;
		}
		item = wuy_dict_get(conf->cache, lua_tostring(h2d_L, -1));
		lua_pop(h2d_L, 1);
	}

	if (item == NULL) {
		return H2D_OK;
	}

	r->module_ctxs[h2d_cache_module.index] = H2D_CACHE_CTX_HIT;

	r->resp.content_length = item->content_length;
	h2d_header_dup_list(&r->resp.headers, &item->headers);
	printf("cache hit : %ld\n", item->content_length);
	r->resp.broken_body_buf = item->body;
	r->resp.broken_body_len = item->content_length;
	return item->status_code;
}

static int h2d_cache_response_headers(struct h2d_request *r)
{
	if (r->module_ctxs[h2d_cache_module.index] == H2D_CACHE_CTX_HIT) {
		return H2D_OK;
	}

	struct h2d_cache_conf *conf = r->conf_path->module_confs[h2d_cache_module.index];
	if (conf->size == 0) {
		return H2D_OK;
	}
	if (r->resp.status_code != WUY_HTTP_200) {
		return H2D_OK;
	}
	if (r->resp.content_length == H2D_CONTENT_LENGTH_INIT) {
		return H2D_OK;
	}

	struct h2d_cache_item *item = malloc(sizeof(struct h2d_cache_item) + r->resp.content_length);

	if (h2d_conf_is_zero_function(conf->key)) {
		item->key = strdup(r->req.url);
	} else {
		h2d_lua_current_request = r;
		lua_rawgeti(h2d_L, LUA_REGISTRYINDEX, conf->key);
		if (lua_pcall(h2d_L, 0, 1, 0) != 0) {
			printf("lua_pcall fail: %s\n", lua_tostring(h2d_L, -1));
			lua_pop(h2d_L, 1);
			return WUY_HTTP_500;
		}
		item->key = strdup(lua_tostring(h2d_L, -1));
		lua_pop(h2d_L, 1);
	}

	item->status_code = r->resp.status_code;
	item->content_length = r->resp.content_length;
	wuy_slist_init(&item->headers);
	h2d_header_dup_list(&item->headers, &r->resp.headers);
	wuy_dict_add(conf->cache, item);

	r->module_ctxs[h2d_cache_module.index] = item;
	return H2D_OK;
}
static int h2d_cache_response_body(struct h2d_request *r, uint8_t *data, int data_len, int buf_len)
{
	struct h2d_cache_item *item = r->module_ctxs[h2d_cache_module.index];
	if (item == NULL || item == H2D_CACHE_CTX_HIT) {
		return data_len;
	}

	memcpy(item->body, data, data_len);
	return data_len;
}

/* configuration */

static bool h2d_cache_conf_post(void *data)
{
	struct h2d_cache_conf *conf = data;
	if (conf->size == 0) {
		return true;
	}

	conf->cache = wuy_dict_new_type(WUY_DICT_KEY_STRING,
			offsetof(struct h2d_cache_item, key),
			offsetof(struct h2d_cache_item, dict_node));

	return true;
}

static struct wuy_cflua_command h2d_cache_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_INTEGER,
		.flags = WUY_CFLUA_FLAG_UNIQ_MEMBER,
		.offset = offsetof(struct h2d_cache_conf, size),
	},
	{	.name = "key",
		.type = WUY_CFLUA_TYPE_FUNCTION,
		.offset = offsetof(struct h2d_cache_conf, key),
	},
	{	.name = "max_length",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_cache_conf, max_length),
	},
	{	.name = "default_expire",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_cache_conf, default_expire),
	},
	{	.name = "force_expire",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_cache_conf, force_expire),
	},
	{	.name = "include_types",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_cache_conf, include_types),
		.u.table = WUY_CFLUA_ARRAY_STRING_TABLE,
	},
	{	.name = "exclude_types",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_cache_conf, exclude_types),
		.u.table = WUY_CFLUA_ARRAY_STRING_TABLE,
	},
	{ NULL }
};

struct h2d_module h2d_cache_module = {
	.name = "cache",
	.command_path = {
		.name = "cache",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) {
			.commands = h2d_cache_conf_commands,
			.size = sizeof(struct h2d_cache_conf),
			.post = h2d_cache_conf_post,
		}
	},

	.filters = {
		.process_headers = h2d_cache_process_headers,
		.response_headers = h2d_cache_response_headers,
		.response_body = h2d_cache_response_body,
	},
};

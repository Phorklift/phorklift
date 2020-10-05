#ifndef H2D_DYNAMIC_H
#define H2D_DYNAMIC_H

struct h2d_dynamic_conf {
	bool			is_name_blocking;
	wuy_cflua_function_t	get_name;
	wuy_cflua_function_t	get_conf;
	wuy_cflua_function_t	check_filter;
	int			check_interval;
	int			idle_timeout;
	int			error_expire;
	int			sub_max;

	/* father only */
	wuy_dict_t		*sub_dict;
	struct wuy_cflua_table	*container_table;
	off_t			container_offset;

	/* sub only */
	time_t			create_time;
	time_t			modify_time;
	time_t			access_time;
	time_t			check_time;
	int			error_ret;
	bool			is_just_holder;
	bool			in_check_conf;
	const char		*name;
	wuy_dict_node_t		dict_node;
};

struct h2d_dynamic_ctx {
	struct h2d_dynamic_conf		*sub_dyn;
	struct h2d_lua_api_thread	*lth;
};

void *h2d_dynamic_get(struct h2d_dynamic_conf *dynamic, struct h2d_request *r);
void h2d_dynamic_ctx_free(struct h2d_request *r);

bool h2d_dynamic_set_container_table(struct h2d_dynamic_conf *dynamic,
		struct wuy_cflua_table *conf_table);

static inline bool h2d_dynamic_is_enabled(struct h2d_dynamic_conf *dynamic)
{
	return wuy_cflua_is_function_set(dynamic->get_name);
}
static inline bool h2d_dynamic_is_sub(struct h2d_dynamic_conf *dynamic)
{
	return dynamic->sub_dict == NULL;
}

void h2d_dynamic_init(void);

extern struct wuy_cflua_table h2d_dynamic_conf_table;

#endif

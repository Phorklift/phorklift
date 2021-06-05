#ifndef H2D_DYNAMIC_H
#define H2D_DYNAMIC_H

struct h2d_dynamic_conf {
	/* conf */
	wuy_cflua_function_t	get_name;
	wuy_cflua_function_t	get_conf;
	wuy_cflua_function_t	check_filter;
	int			check_interval;
	int			idle_timeout;
	int			error_expire;
	int			sub_max;
	struct h2d_log		*log;

	/* runtime: father only */
	atomic_int		*shared_id;
	wuy_dict_t		*sub_dict;
	struct wuy_cflua_table	*sub_table;
	off_t			container_offset;

	/* runtime: sub only */
	struct h2d_dynamic_conf	*father;
	time_t			modify_time;
	time_t			check_time;
	loop_timer_t		*timer;
	int			error_ret;
	bool			is_just_holder;
	bool			in_check_conf;
	const char		*name;
	wuy_list_t		holder_wait_head;
	wuy_dict_node_t		dict_node;
	wuy_shmpool_t		*shmpool;
	wuy_pool_t		*pool;
};

struct h2d_dynamic_ctx {
	struct h2d_dynamic_conf		*sub_dyn;
	struct h2d_lua_api_thread	*lth;
};

void *h2d_dynamic_get(struct h2d_dynamic_conf *dynamic, struct h2d_request *r);
void h2d_dynamic_ctx_free(struct h2d_request *r);

void h2d_dynamic_set_container(struct h2d_dynamic_conf *dynamic,
		struct wuy_cflua_table *conf_table);

static inline bool h2d_dynamic_is_enabled(struct h2d_dynamic_conf *dynamic)
{
	return wuy_cflua_is_function_set(dynamic->get_name);
}
static inline bool h2d_dynamic_is_sub(struct h2d_dynamic_conf *dynamic)
{
	return dynamic->father != NULL;
}

void h2d_dynamic_init(void);

extern struct wuy_cflua_table h2d_dynamic_conf_table;

#endif

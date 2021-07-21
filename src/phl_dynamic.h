#ifndef PHL_DYNAMIC_H
#define PHL_DYNAMIC_H

struct phl_dynamic_conf {
	/* conf */
	wuy_cflua_function_t	get_name;
	wuy_cflua_function_t	get_conf;
	wuy_cflua_function_t	check_filter;
	int			check_interval;
	int			idle_timeout;
	int			error_timeout;
	int			sub_max;
	bool			safe_mode_inherit;
	bool			safe_mode;
	bool			no_stale;
	struct phl_log		*log;

	/* runtime: father only */
	atomic_int		*shared_id;
	wuy_dict_t		*sub_dict;
	struct wuy_cflua_table	*sub_table;
	off_t			container_offset;

	/* runtime: sub only */
	struct phl_dynamic_conf	*father;
	time_t			check_time;
	loop_timer_t		*timer;
	int			error_ret;
	bool			is_just_holder;
	const char		*name;
	uint64_t		tag;
	wuy_list_t		holder_wait_head;
	wuy_dict_node_t		dict_node;
	wuy_shmpool_t		*shmpool;
	wuy_pool_t		*pool;
};

struct phl_dynamic_ctx {
	struct phl_dynamic_conf		*sub_dyn;
	struct phl_lua_api_thread	*lth;
};

void *phl_dynamic_get(struct phl_dynamic_conf *dynamic, struct phl_request *r);
void phl_dynamic_ctx_free(struct phl_request *r);

void phl_dynamic_set_container(struct phl_dynamic_conf *dynamic,
		struct wuy_cflua_table *conf_table);

static inline bool phl_dynamic_is_enabled(struct phl_dynamic_conf *dynamic)
{
	return wuy_cflua_is_function_set(dynamic->get_name);
}
static inline bool phl_dynamic_is_sub(struct phl_dynamic_conf *dynamic)
{
	return dynamic->father != NULL;
}

bool phl_dynamic_in_safe_mode(void);

void phl_dynamic_init(void);

extern struct wuy_cflua_table phl_dynamic_conf_table;

#endif

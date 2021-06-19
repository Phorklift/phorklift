#ifndef PHL_MODULE_H
#define PHL_MODULE_H

#include <stdbool.h>

#include "phl_module_list.h"

/* calculate PHL_MODULE_STATIC_NUMBER in preprocess */
enum _nonuse {
	#define X(m) phl_module_index_##m,
	PHL_MODULE_X_LIST
	#undef X

	PHL_MODULE_STATIC_NUMBER
};

#define PHL_MODULE_DYNAMIC_MAX	20
#define PHL_MODULE_MAX		(PHL_MODULE_STATIC_NUMBER + PHL_MODULE_DYNAMIC_MAX)

#include "phl_request.h"

struct phl_module {

	const char		*name;
	int			index;

	struct wuy_cflua_command	command_listen;
	struct wuy_cflua_command	command_host;
	struct wuy_cflua_command	command_path;

	void		(*stats_listen)(void *conf, wuy_json_t *json);
	void		(*stats_path)(void *conf, wuy_json_t *json);
	void		(*stats_host)(void *conf, wuy_json_t *json);

	struct {
		bool	(*is_enabled)(void *conf);
		int	(*process_headers)(struct phl_request *);
		int	(*process_body)(struct phl_request *);
		int	(*response_headers)(struct phl_request *);
		int	(*response_body)(struct phl_request *, uint8_t *buf, int len);
	} content;

	struct {
		int	(*process_headers)(struct phl_request *);
		int	(*process_body)(struct phl_request *);
		int	(*response_headers)(struct phl_request *);
		int	(*response_body)(struct phl_request *, uint8_t *data,
				int data_len, int buf_len, bool *p_is_last);

		double	ranks[4];
	} filters;

	void	(*ctx_free)(struct phl_request *);

	void	(*master_init)(void);
	void	(*worker_init)(void);
};

struct phl_module_dynamic {
	const char	*filename; /* at top for configration parsing */
	void		*dl_handle;
	void 		*sym;
};

void phl_module_master_init(void);
void phl_module_worker_init(void);

struct phl_module *phl_module_next(struct phl_module *m);

struct wuy_cflua_command *phl_module_next_listen_command(struct wuy_cflua_command *cmd);
struct wuy_cflua_command *phl_module_next_host_command(struct wuy_cflua_command *cmd);
struct wuy_cflua_command *phl_module_next_path_command(struct wuy_cflua_command *cmd);

bool phl_module_command_is_set(struct wuy_cflua_command *cmd, void *conf);

void phl_module_stats_listen(struct phl_conf_listen *, wuy_json_t *json);
void phl_module_stats_host(struct phl_conf_host *, wuy_json_t *json);
void phl_module_stats_path(struct phl_conf_path *, wuy_json_t *json);

void phl_module_request_ctx_free(struct phl_request *r);
int phl_module_filter_process_headers(struct phl_request *r);
int phl_module_filter_process_body(struct phl_request *r);
int phl_module_filter_response_headers(struct phl_request *r);
int phl_module_filter_response_body(struct phl_request *r, uint8_t *data,
		int data_len, int buf_len, bool *p_is_last);

extern int phl_module_number;

extern struct wuy_cflua_table phl_module_filters_conf_table;
extern struct wuy_cflua_table phl_module_dynamic_table;
extern struct wuy_cflua_table phl_module_dynamic_upstream_table;

#endif

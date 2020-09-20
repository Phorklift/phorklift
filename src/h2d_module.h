#ifndef H2D_MODULE_H
#define H2D_MODULE_H

#include <stdbool.h>

#include "h2d_module.list.h"

/* calculate H2D_MODULE_STATIC_NUMBER in preprocess */
struct _nonuse {
	#define X(m) char m;
	H2D_MODULE_X_LIST
	#undef X
};
#define H2D_MODULE_STATIC_NUMBER (sizeof(struct _nonuse) / sizeof(char))

#define H2D_MODULE_DYNAMIC_MAX	20
#define H2D_MODULE_MAX		(H2D_MODULE_STATIC_NUMBER + H2D_MODULE_DYNAMIC_MAX)

#include "h2d_request.h"

struct h2d_module {

	const char		*name;
	int			index;

	struct wuy_cflua_command	command_listen;
	struct wuy_cflua_command	command_host;
	struct wuy_cflua_command	command_path;

	void		(*stats_listen)(void *conf, wuy_json_ctx_t *json);
	void		(*stats_path)(void *conf, wuy_json_ctx_t *json);
	void		(*stats_host)(void *conf, wuy_json_ctx_t *json);

	struct {
		int	(*process_headers)(struct h2d_request *);
		int	(*process_body)(struct h2d_request *);
		int	(*response_headers)(struct h2d_request *);
		int	(*response_body)(struct h2d_request *, uint8_t *buf, int len);
	} content;

	struct {
		int	(*process_headers)(struct h2d_request *);
		int	(*process_body)(struct h2d_request *);
		int	(*response_headers)(struct h2d_request *);
		int	(*response_body)(struct h2d_request *, uint8_t *data, int data_len, int buf_len);

		double	rank_process_headers;
		double	rank_process_body;
		double	rank_response_headers;
		double	rank_response_body;
	} filters;

	void	(*ctx_free)(struct h2d_request *);

	void	(*master_init)(void);
	bool	(*master_post)(void);
	void	(*worker_init)(void);
};

void h2d_module_master_init(const char *dynamic_dir);
void h2d_module_master_post(void);
void h2d_module_worker_init(void);

struct wuy_cflua_command *h2d_module_next_listen_command(struct wuy_cflua_command *cmd);
struct wuy_cflua_command *h2d_module_next_host_command(struct wuy_cflua_command *cmd);
struct wuy_cflua_command *h2d_module_next_path_command(struct wuy_cflua_command *cmd);

bool h2d_module_command_is_set(struct wuy_cflua_command *cmd, void *conf);

void h2d_module_stats_listen(struct h2d_conf_listen *, wuy_json_ctx_t *json);
void h2d_module_stats_host(struct h2d_conf_host *, wuy_json_ctx_t *json);
void h2d_module_stats_path(struct h2d_conf_path *, wuy_json_ctx_t *json);

struct h2d_module *h2d_module_content_is_enabled(int i, void *conf);
void h2d_module_request_ctx_free(struct h2d_request *r);
int h2d_module_filter_process_headers(struct h2d_request *r);
int h2d_module_filter_process_body(struct h2d_request *r);
int h2d_module_filter_response_headers(struct h2d_request *r);
int h2d_module_filter_response_body(struct h2d_request *r, uint8_t *data, int data_len, int buf_len);

extern int h2d_module_number;

#endif

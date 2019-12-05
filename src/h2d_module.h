#ifndef H2D_MODULE_H
#define H2D_MODULE_H

#include <stdbool.h>

#include "h2d_request.h"

struct h2d_module {

	const char		*name;
	int			index;

	struct wuy_cflua_command	command_listen;
	struct wuy_cflua_command	command_host;
	struct wuy_cflua_command	command_path;

	struct {
		bool	(*is_enable)(void *conf);
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
	} filters;

	struct {
		int		index;
		void		(*free)(struct h2d_request *);
	} request_ctx;

	void	(*master_init)(void);
	bool	(*master_post)(void);
	void	(*worker_init)(void);
};

extern int h2d_module_ctx_number;

void h2d_module_master_init(void);
void h2d_module_master_post(void);
void h2d_module_worker_init(void);

struct wuy_cflua_command *h2d_module_next_listen_command(struct wuy_cflua_command *cmd);
struct wuy_cflua_command *h2d_module_next_host_command(struct wuy_cflua_command *cmd);
struct wuy_cflua_command *h2d_module_next_path_command(struct wuy_cflua_command *cmd);

struct h2d_module *h2d_module_content_is_enable(int i, void *conf);
void h2d_module_request_ctx_free(struct h2d_request *r);
int h2d_module_filter_process_headers(struct h2d_request *r);
int h2d_module_filter_process_body(struct h2d_request *r);
int h2d_module_filter_response_headers(struct h2d_request *r);
int h2d_module_filter_response_body(struct h2d_request *r, uint8_t *data, int data_len, int buf_len);

#endif

#include <stdlib.h>
#include <string.h>

#include "h2d_main.h"

#include "h2d_module.list.c"

static struct wuy_cflua_command *h2d_module_next_command(struct wuy_cflua_command *cmd, unsigned offset)
{
	int index = 0;
	if (cmd->type != WUY_CFLUA_TYPE_END || cmd->u.next == NULL) {
		struct h2d_module *m = (struct h2d_module *)((char *)cmd - offset);
		index = m->index + 1;
	}

	for (; index < H2D_MODULE_NUMBER; index++) {
		struct wuy_cflua_command *next = (struct wuy_cflua_command *)(((char *)h2d_modules[index]) + offset);
		if (next->type != WUY_CFLUA_TYPE_END) {
			return next;
		}
	}
	return NULL;
}
struct wuy_cflua_command *h2d_module_next_listen_command(struct wuy_cflua_command *cmd)
{
	return h2d_module_next_command(cmd, offsetof(struct h2d_module, command_listen));
}
struct wuy_cflua_command *h2d_module_next_host_command(struct wuy_cflua_command *cmd)
{
	return h2d_module_next_command(cmd, offsetof(struct h2d_module, command_host));
}
struct wuy_cflua_command *h2d_module_next_path_command(struct wuy_cflua_command *cmd)
{
	return h2d_module_next_command(cmd, offsetof(struct h2d_module, command_path));
}

int h2d_module_ctx_number = 0;
void h2d_module_master_init(void)
{
	int i;
	for (i = 0; i < H2D_MODULE_NUMBER; i++) {
		struct h2d_module *m = h2d_modules[i];
		m->index = i;

		if (m->request_ctx.free != NULL) {
			m->request_ctx.index = h2d_module_ctx_number++;
		}

		unsigned offset = sizeof(void *) * i;
		m->command_listen.offset = offsetof(struct h2d_conf_listen, module_confs) + offset;
		m->command_host.offset = offsetof(struct h2d_conf_host, module_confs) + offset;
		m->command_path.offset = offsetof(struct h2d_conf_path, module_confs) + offset;

		if (m->master_init != NULL) {
			m->master_init();
		}
	}
}
void h2d_module_master_post(void)
{
	int i;
	for (i = 0; i < H2D_MODULE_NUMBER; i++) {
		struct h2d_module *m = h2d_modules[i];
		if (m->master_post != NULL) {
			if (!m->master_post()) {
				exit(1);
			}
		}
	}
}

void h2d_module_worker_init(void)
{
	int i;
	for (i = 0; i < H2D_MODULE_NUMBER; i++) {
		struct h2d_module *m = h2d_modules[i];
		if (m->worker_init != NULL) {
			m->worker_init();
		}
	}
}

struct h2d_module *h2d_module_content_is_enable(int i, void *conf)
{
	struct h2d_module *m = h2d_modules[i];
	if (m->content.is_enable == NULL) {
		return NULL;
	}
	return m->content.is_enable(conf) ? m : NULL;
}

void h2d_module_request_ctx_free(struct h2d_request *r)
{
	int i;
	for (i = 0; i < H2D_MODULE_NUMBER; i++) {
		struct h2d_module *m = h2d_modules[i];
		if (m->request_ctx.free != NULL && r->module_ctxs[m->request_ctx.index] != NULL) {
			m->request_ctx.free(r);
		}
	}
}

int h2d_module_filter_process_headers(struct h2d_request *r)
{
	while (r->filter_step_process_headers < H2D_MODULE_NUMBER) {
		struct h2d_module *m = h2d_modules[r->filter_step_process_headers];
		if (m->filters.process_headers != NULL) {
			int ret = m->filters.process_headers(r);
			if (ret != H2D_OK) {
				return ret;
			}
		}
		r->filter_step_process_headers++;
	}

	return H2D_OK;
}
int h2d_module_filter_process_body(struct h2d_request *r)
{
	int i;
	for (i = 0; i < H2D_MODULE_NUMBER; i++) {
		struct h2d_module *m = h2d_modules[i];
		if (m->filters.process_body != NULL) {
			int ret = m->filters.process_body(r);
			if (ret != H2D_OK) {
				return ret;
			}
		}
	}

	return H2D_OK;
}
int h2d_module_filter_response_headers(struct h2d_request *r)
{
	int i;
	for (i = 0; i < H2D_MODULE_NUMBER; i++) {
		struct h2d_module *m = h2d_modules[i];
		if (m->filters.response_headers != NULL) {
			int ret = m->filters.response_headers(r);
			if (ret != H2D_OK) {
				return ret;
			}
		}
	}

	return H2D_OK;
}
int h2d_module_filter_response_body(struct h2d_request *r, uint8_t *data, int data_len, int buf_len)
{
	int i;
	for (i = 0; i < H2D_MODULE_NUMBER; i++) {
		struct h2d_module *m = h2d_modules[i];
		if (m->filters.response_body != NULL) {
			int ret = m->filters.response_body(r, data, data_len, buf_len);
			if (ret != H2D_OK) {
				return ret;
			}
		}
	}

	return H2D_OK;
}

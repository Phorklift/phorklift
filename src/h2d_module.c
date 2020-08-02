#include <stdlib.h>
#include <string.h>

#include "h2d_main.h"

#define X(m) extern struct h2d_module m;
H2D_MODULE_X_LIST
#undef X
static struct h2d_module *h2d_modules[] =
{
	#define X(m) &m,
	H2D_MODULE_X_LIST
	#undef X
};

static struct wuy_cflua_command *h2d_module_next_command(struct wuy_cflua_command *cmd, unsigned offset)
{
	int index = 0;
	if (cmd->type != WUY_CFLUA_TYPE_END || cmd->u.next == NULL) {
		struct h2d_module *m = (struct h2d_module *)((char *)cmd - offset);
		index = m->index + 1;
	}

	for (; index < H2D_MODULE_NUMBER; index++) {
		struct wuy_cflua_command *next = (void *)(((char *)h2d_modules[index]) + offset);
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

int h2d_module_path_stats(void **confs, char *buf, int len)
{
	char *pos = buf;
	char *end = buf + len;
	for (int i = 0; i < H2D_MODULE_NUMBER; i++) {
		struct h2d_module *m = h2d_modules[i];
		if (m->stats_path != NULL) {
			pos += m->stats_path(confs[i], pos, end - pos);
		}
	}
	return pos - buf;
}

void h2d_module_master_init(void)
{
	int i;
	for (i = 0; i < H2D_MODULE_NUMBER; i++) {
		struct h2d_module *m = h2d_modules[i];
		m->index = i;

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
				exit(H2D_EXIT_MODULE_INIT);
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

struct h2d_module *h2d_module_content_is_enabled(int i, void *conf)
{
	struct h2d_module *m = h2d_modules[i];
	bool is_enabled;

	if (m->content.response_headers == NULL) {
		return NULL;
	}
	if (m->command_path.type == WUY_CFLUA_TYPE_END) {
		abort();
	}

	/* simple type, not table */
	if (m->command_path.type != WUY_CFLUA_TYPE_TABLE) {
		is_enabled = conf != NULL;
		goto out;
	}

	/* table type, check the first command */
	struct wuy_cflua_command *first = &m->command_path.u.table->commands[0];
	if (first->name != NULL) {
		/* must be array-member */
		abort();
	}

	void *ptr = (char *)conf + first->offset;

	/* it's multi-value array */
	if ((first->flags & WUY_CFLUA_FLAG_UNIQ_MEMBER) == 0) {
		is_enabled = *(char **)ptr != NULL;
		goto out;
	}

	/* it's single value */
	const char *pstr;
	wuy_cflua_function_t func;
	switch (first->type) {
	case WUY_CFLUA_TYPE_BOOLEAN:
		is_enabled = *(bool *)ptr;
		break;
	case WUY_CFLUA_TYPE_DOUBLE:
		is_enabled = *(double *)ptr != 0;
		break;
	case WUY_CFLUA_TYPE_INTEGER:
		is_enabled = *(int *)ptr != 0;
		break;
	case WUY_CFLUA_TYPE_STRING:
		pstr = *(char **)ptr;
		is_enabled = pstr != NULL && pstr[0] != '\0';
		break;
	case WUY_CFLUA_TYPE_FUNCTION:
		func = *(wuy_cflua_function_t *)ptr;
		is_enabled = func != 0 && !h2d_conf_is_zero_function(func);
		break;
	default:
		abort();
	}
out:
	return is_enabled ? m : NULL;
}

void h2d_module_request_ctx_free(struct h2d_request *r)
{
	int i;
	for (i = 0; i < H2D_MODULE_NUMBER; i++) {
		struct h2d_module *m = h2d_modules[i];
		if (m->ctx_free != NULL && r->module_ctxs[m->index] != NULL) {
			m->ctx_free(r);
			r->module_ctxs[m->index] = (void *)(uintptr_t)(-1L); /* reset */
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

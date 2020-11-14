#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <dirent.h>

#include "h2d_main.h"

int h2d_module_number = H2D_MODULE_STATIC_NUMBER;

#define X(m) extern struct h2d_module m;
H2D_MODULE_X_LIST
#undef X
static struct h2d_module *h2d_modules[H2D_MODULE_MAX] =
{
	#define X(m) &m,
	H2D_MODULE_X_LIST
	#undef X
};

static struct h2d_module *h2d_module_process_headers[H2D_MODULE_MAX];
static struct h2d_module *h2d_module_process_body[H2D_MODULE_MAX];
static struct h2d_module *h2d_module_response_headers[H2D_MODULE_MAX];
static struct h2d_module *h2d_module_response_body[H2D_MODULE_MAX];

static struct wuy_cflua_command *h2d_module_next_command(struct wuy_cflua_command *cmd, unsigned offset)
{
	int index = 0;
	if (cmd->type != WUY_CFLUA_TYPE_END || cmd->u.next == NULL) {
		struct h2d_module *m = (struct h2d_module *)((char *)cmd - offset);
		index = m->index + 1;
	}

	for (; index < h2d_module_number; index++) {
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

void h2d_module_stats_listen(struct h2d_conf_listen *conf_listen, wuy_json_ctx_t *json)
{
	for (int i = 0; i < h2d_module_number; i++) {
		struct h2d_module *m = h2d_modules[i];
		if (m->stats_listen != NULL) {
			m->stats_listen(conf_listen->module_confs[i], json);
		}
	}
}
void h2d_module_stats_host(struct h2d_conf_host *conf_host, wuy_json_ctx_t *json)
{
	for (int i = 0; i < h2d_module_number; i++) {
		struct h2d_module *m = h2d_modules[i];
		if (m->stats_host != NULL) {
			m->stats_host(conf_host->module_confs[i], json);
		}
	}
}
void h2d_module_stats_path(struct h2d_conf_path *conf_path, wuy_json_ctx_t *json)
{
	for (int i = 0; i < h2d_module_number; i++) {
		struct h2d_module *m = h2d_modules[i];
		if (m->stats_path != NULL) {
			m->stats_path(conf_path->module_confs[i], json);
		}
	}
}

static int h2d_module_filter_cmp(const struct h2d_module *ma,
		const struct h2d_module *mb, double ranka, double rankb)
{
	if (ranka == rankb) {
		return ma->index - mb->index;
	} else {
		return ranka < rankb ? -1 : 1;
	}
}
static int h2d_module_cmp_process_headers(const void *a, const void *b)
{
	const struct h2d_module *ma = *(const struct h2d_module **)a;
	const struct h2d_module *mb = *(const struct h2d_module **)b;
	return h2d_module_filter_cmp(ma, mb, ma->filters.rank_process_headers, mb->filters.rank_process_headers);
}
static int h2d_module_cmp_process_body(const void *a, const void *b)
{
	const struct h2d_module *ma = *(const struct h2d_module **)a;
	const struct h2d_module *mb = *(const struct h2d_module **)b;
	return h2d_module_filter_cmp(ma, mb, ma->filters.rank_process_body, mb->filters.rank_process_body);
}
static int h2d_module_cmp_response_headers(const void *a, const void *b)
{
	const struct h2d_module *ma = *(const struct h2d_module **)a;
	const struct h2d_module *mb = *(const struct h2d_module **)b;
	return h2d_module_filter_cmp(ma, mb, ma->filters.rank_response_headers, mb->filters.rank_response_headers);
}
static int h2d_module_cmp_response_body(const void *a, const void *b)
{
	const struct h2d_module *ma = *(const struct h2d_module **)a;
	const struct h2d_module *mb = *(const struct h2d_module **)b;
	return h2d_module_filter_cmp(ma, mb, ma->filters.rank_response_body, mb->filters.rank_response_body);
}

static const char *trim_whitespace(char *str) // TODO move this out
{
	while (isspace(*str)) {
		str++;
	}
	if (*str == 0) {
		return str;
	}

	char *end = str + strlen(str) - 1;
	while (end > str && isspace(*end)) {
		end--;
	}
	end[1] = '\0';

	return str;
}

void h2d_module_dynamic_add(const char *filename)
{
	/* list-file of module files */
	if (filename[0] == '@') {
		FILE *fp = fopen(filename + 1, "r");
		if (fp == NULL) {
			fprintf(stderr, "error in open module list file: %s: %s\n",
					filename, strerror(errno));
			exit(H2D_EXIT_DYNAMIC);
		}
		char line[2000];
		while (fgets(line, sizeof(line), fp) != NULL) {
			const char *name = trim_whitespace(line);
			if (name[0] == '#' || name[0] == '\0') {
				continue;
			}
			if (name[0] == '@') {
				fprintf(stderr, "no @ in module list file!\n");
				exit(H2D_EXIT_DYNAMIC);
			}
			h2d_module_dynamic_add(name);
		}
	}

	if (h2d_module_number++ >= H2D_MODULE_MAX) {
		fprintf(stderr, "excess dynamic module limit: %d\n", H2D_MODULE_DYNAMIC_MAX);
		exit(H2D_EXIT_DYNAMIC);
	}

	/* make the module name */
	const char *p = strrchr(filename, '/');
	if (p == NULL) {
		p = filename;
	} else {
		p++;
	}

	int len = strlen(p);
	if (memcmp(p, "h2d_", 4) != 0 || memcmp(p + len - 3, ".so", 3) != 0) {
		fprintf(stderr, "invalid dynamic module filename: %s\n", filename);
		exit(H2D_EXIT_DYNAMIC);
	}

	char mod_name[len + sizeof("_module") - 3];
	memcpy(mod_name, p, len - 3);
	memcpy(mod_name + len - 3, "_module", 7);
	mod_name[len + 7 - 3] = '\0';

	/* load */
	void *dyn = dlopen(filename, RTLD_NOW | RTLD_NODELETE);
	if (dyn == NULL) {
		fprintf(stderr, "fail in dlopen: %s\n", dlerror());
		exit(H2D_EXIT_DYNAMIC);
	}
	struct h2d_module *m = dlsym(dyn, mod_name);
	if (m == NULL) {
		fprintf(stderr, "fail in dlsym: %s\n", dlerror());
		exit(H2D_EXIT_DYNAMIC);
	}
	dlclose(dyn);

	h2d_modules[h2d_module_number++] = m;
	printf("load module: %s\n", mod_name);
}

void h2d_module_master_init(void)
{
	int iph = 0, ipb = 0, irh = 0, irb = 0;
	for (int i = 0; i < h2d_module_number; i++) {
		struct h2d_module *m = h2d_modules[i];
		m->index = i;

		off_t offset = sizeof(void *) * i;
		m->command_listen.offset = offsetof(struct h2d_conf_listen, module_confs) + offset;
		m->command_host.offset = offsetof(struct h2d_conf_host, module_confs) + offset;
		m->command_path.offset = offsetof(struct h2d_conf_path, module_confs) + offset;

		m->command_path.meta_level_offset = offsetof(struct h2d_conf_path, content_meta_levels) + sizeof(int) * i;

		if (m->filters.process_headers) {
			h2d_module_process_headers[iph++] = m;
		}
		if (m->filters.process_body) {
			h2d_module_process_body[ipb++] = m;
		}
		if (m->filters.response_headers) {
			h2d_module_response_headers[irh++] = m;
		}
		if (m->filters.response_body) {
			h2d_module_response_body[irb++] = m;
		}

		if (m->master_init != NULL) {
			m->master_init();
		}
	}

	qsort(h2d_module_process_headers, iph, sizeof(struct h2d_module *), h2d_module_cmp_process_headers);
	qsort(h2d_module_process_body, ipb, sizeof(struct h2d_module *), h2d_module_cmp_process_body);
	qsort(h2d_module_response_headers, irh, sizeof(struct h2d_module *), h2d_module_cmp_response_headers);
	qsort(h2d_module_response_body, irb, sizeof(struct h2d_module *), h2d_module_cmp_response_body);

	/* debug log */
	printf("process_headers: ");
	for (int i = 0; i < iph; i++) {
		struct h2d_module *m = h2d_module_process_headers[i];
		printf("%s(%g) -> ", m->name, m->filters.rank_process_headers);
	}
	printf("\nprocess_body: ");
	for (int i = 0; i < ipb; i++) {
		struct h2d_module *m = h2d_module_process_body[i];
		printf("%s(%g) -> ", m->name, m->filters.rank_process_body);
	}
	printf("\nresponse_headers: ");
	for (int i = 0; i < irh; i++) {
		struct h2d_module *m = h2d_module_response_headers[i];
		printf("%s(%g) -> ", m->name, m->filters.rank_response_headers);
	}
	printf("\nresponse_body: ");
	for (int i = 0; i < irb; i++) {
		struct h2d_module *m = h2d_module_response_body[i];
		printf("%s(%g) -> ", m->name, m->filters.rank_response_body);
	}
	printf("\n");
}

void h2d_module_master_post(void)
{
	int i;
	for (i = 0; i < h2d_module_number; i++) {
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
	for (i = 0; i < h2d_module_number; i++) {
		struct h2d_module *m = h2d_modules[i];
		if (m->worker_init != NULL) {
			m->worker_init();
		}
	}
}

bool h2d_module_command_is_set(struct wuy_cflua_command *cmd, void *conf)
{
	if (cmd->type == WUY_CFLUA_TYPE_END) {
		return false;
	}

	/* simple type, not table */
	if (cmd->type != WUY_CFLUA_TYPE_TABLE) {
		return conf != NULL;
	}

	/* table type */
	if (conf == NULL) {
		return false;
	}

	/* check the first command */
	struct wuy_cflua_command *first = &cmd->u.table->commands[0];
	if (first->name != NULL) {
		/* must be array-member */
		abort();
	}

	void *ptr = (char *)conf + first->offset;

	/* it's multi-value array */
	if (!first->is_single_array) {
		return *(char **)ptr != NULL;
	}

	/* it's single value */
	switch (first->type) {
	case WUY_CFLUA_TYPE_BOOLEAN:
		return *(bool *)ptr;
	case WUY_CFLUA_TYPE_DOUBLE:
		return *(double *)ptr != 0;
	case WUY_CFLUA_TYPE_INTEGER:
		return *(int *)ptr != 0;
	case WUY_CFLUA_TYPE_STRING:
		return *(char **)ptr != NULL;
	case WUY_CFLUA_TYPE_FUNCTION:
		return wuy_cflua_is_function_set(*(wuy_cflua_function_t *)ptr);
	case WUY_CFLUA_TYPE_TABLE:
		return h2d_module_command_is_set(first, *(char **)ptr);
	default:
		abort();
	}
}

struct h2d_module *h2d_module_content_is_enabled(int i, void *conf)
{
	struct h2d_module *m = h2d_modules[i];

	if (m->content.response_headers == NULL) {
		return NULL;
	}

	return h2d_module_command_is_set(&m->command_path, conf) ? m : NULL;
}

void h2d_module_request_ctx_free(struct h2d_request *r)
{
	int i;
	for (i = 0; i < h2d_module_number; i++) {
		struct h2d_module *m = h2d_modules[i];
		if (m->ctx_free != NULL && r->module_ctxs[m->index] != NULL) {
			m->ctx_free(r);
			r->module_ctxs[m->index] = (void *)(uintptr_t)(-1L); /* reset */
		}
	}
}

int h2d_module_filter_process_headers(struct h2d_request *r)
{
	while (1) {
		struct h2d_module *m = h2d_module_process_headers[r->filter_step_process_headers];
		if (m == NULL) {
			return H2D_OK;
		}
		int ret = m->filters.process_headers(r);
		if (ret != H2D_OK) {
			return ret;
		}
		r->filter_step_process_headers++;
	}
}
int h2d_module_filter_process_body(struct h2d_request *r)
{
	while (1) {
		struct h2d_module *m = h2d_module_process_body[r->filter_step_process_body];
		if (m == NULL) {
			return H2D_OK;
		}
		int ret = m->filters.process_body(r);
		if (ret != H2D_OK) {
			return ret;
		}
		r->filter_step_process_body++;
	}
}
int h2d_module_filter_response_headers(struct h2d_request *r)
{
	int i = 0;
	while (1) {
		struct h2d_module *m = h2d_module_response_headers[i++];
		if (m == NULL) {
			return H2D_OK;
		}
		int ret = m->filters.response_headers(r);
		if (ret != H2D_OK) {
			return ret;
		}
	}
}
int h2d_module_filter_response_body(struct h2d_request *r, uint8_t *data, int data_len, int buf_len)
{
	int i = 0;
	while (1) {
		struct h2d_module *m = h2d_module_response_body[i++];
		if (m == NULL) {
			break;
		}
		data_len = m->filters.response_body(r, data, data_len, buf_len);
		if (data_len < 0) {
			return data_len;
		}
	}
	return data_len;
}

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <math.h>

#include "h2d_main.h"

enum {
	H2D_MODULE_FILTER_PROCESS_HEADERS = 0,
	H2D_MODULE_FILTER_PROCESS_BODY,
	H2D_MODULE_FILTER_RESPONSE_HEADERS,
	H2D_MODULE_FILTER_RESPONSE_BODY,
	H2D_MODULE_FILTER_NUM,
};
struct h2d_module_filters {
	double			ranks[H2D_MODULE_FILTER_NUM][H2D_MODULE_MAX];
	struct h2d_module	*modules[H2D_MODULE_FILTER_NUM][H2D_MODULE_MAX];
};


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
				fprintf(stderr, "no @ allowed in module list file!\n");
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
	for (int i = 0; i < h2d_module_number; i++) {
		struct h2d_module *m = h2d_modules[i];
		m->index = i;

		off_t offset = sizeof(void *) * i;
		m->command_listen.offset = offsetof(struct h2d_conf_listen, module_confs) + offset;
		m->command_host.offset = offsetof(struct h2d_conf_host, module_confs) + offset;
		m->command_path.offset = offsetof(struct h2d_conf_path, module_confs) + offset;

		m->command_path.meta_level_offset = offsetof(struct h2d_conf_path, content_meta_levels) + sizeof(int) * i;

		if (m->master_init != NULL) {
			m->master_init();
		}
	}
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

	bool is_enabled;
	if (m->content.is_enabled != NULL) {
		is_enabled = m->content.is_enabled(conf);
	} else {
		is_enabled = h2d_module_command_is_set(&m->command_path, conf);
	}

	return is_enabled ? m : NULL;
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

static int h2d_module_filter_run(struct h2d_request *r, int index)
{
	struct h2d_module **modules = r->conf_path->filters->modules[index];
	while (1) {
		struct h2d_module *m = modules[r->filter_indexs[index]];
		if (m == NULL) {
			return H2D_OK;
		}
		int ret = (*(&m->filters.process_headers + index))(r);
		if (ret != H2D_OK) {
			if (ret > 0) { /* HTTP status_code */
				r->filter_terminal = m;
			}
			return ret;
		}
		r->filter_indexs[index]++;
	}
}
int h2d_module_filter_process_headers(struct h2d_request *r)
{
	return h2d_module_filter_run(r, H2D_MODULE_FILTER_PROCESS_HEADERS);
}
int h2d_module_filter_process_body(struct h2d_request *r)
{
	return h2d_module_filter_run(r, H2D_MODULE_FILTER_PROCESS_BODY);
}
int h2d_module_filter_response_headers(struct h2d_request *r)
{
	return h2d_module_filter_run(r, H2D_MODULE_FILTER_RESPONSE_HEADERS);
}
int h2d_module_filter_response_body(struct h2d_request *r, uint8_t *data,
		int data_len, int buf_len, bool *p_is_last)
{
	struct h2d_module **modules = r->conf_path->filters->modules[H2D_MODULE_FILTER_RESPONSE_BODY];

	int i = 0;
	while (1) {
		struct h2d_module *m = modules[i++];
		if (m == NULL) {
			break;
		}
		data_len = m->filters.response_body(r, data, data_len, buf_len, p_is_last);
		if (data_len < 0) {
			return data_len;
		}
	}
	return data_len;
}


/* configuration */

static int h2d_module_filters_rank_index;
static double *h2d_module_filters_ranks;
static double h2d_module_filter_get_rank(const struct h2d_module *m)
{
	double rank = h2d_module_filters_ranks[m->index];
	if (!isnan(rank)) {
		return rank;
	}
	return m->filters.ranks[h2d_module_filters_rank_index];
}
static int h2d_module_filter_cmp(const void *a, const void *b)
{
	const struct h2d_module *ma = *(const struct h2d_module **)a;
	const struct h2d_module *mb = *(const struct h2d_module **)b;
	double ranka = h2d_module_filter_get_rank(ma);
	double rankb = h2d_module_filter_get_rank(mb);
	if (ranka == rankb) {
		return ma->index - mb->index;
	} else {
		return ranka < rankb ? -1 : 1;
	}
}

static const char *h2d_module_filters_arbitrary(lua_State *L, void *data)
{
	struct h2d_module_filters *conf = data;

	if (!lua_istable(L, -1)) {
		return "expect array";
	}

	const char *name = lua_tostring(L, -2);

	struct h2d_module *m = NULL;
	for (int i = 0; i < h2d_module_number; i++) {
		if (strcmp(h2d_modules[i]->name, name) == 0) {
			m = h2d_modules[i];
			break;
		}
	}
	if (m == NULL) {
		return "unknown module name";
	}

	lua_pushnil(L);
	while (lua_next(L, -2) != 0) {
		int index = lua_tointeger(L, -2);
		if (index == 0 || index > H2D_MODULE_FILTER_NUM) {
			return "invalid key";
		}
		if (!lua_isnumber(L, -1)) {
			return "invalid rank value";
		}
		conf->ranks[index - 1][m->index] = lua_tonumber(L, -1);
		lua_pop(L, 1);
	}

	return WUY_CFLUA_OK;
}
static void h2d_module_filters_init(void *data)
{
	struct h2d_module_filters *conf = data;

	for (int i = 0; i < H2D_MODULE_FILTER_NUM; i++) {
		for (int j = 0; j < h2d_module_number; j++) {
			conf->ranks[i][j] = NAN;
		}
	}
}
static const char *h2d_module_filters_post(void *data)
{
	struct h2d_module_filters *conf = data;

	int counts[H2D_MODULE_FILTER_NUM] = {0};
	for (int i = 0; i < h2d_module_number; i++) {
		struct h2d_module *m = h2d_modules[i];
		if (m->filters.process_headers) {
			int j = H2D_MODULE_FILTER_PROCESS_HEADERS;
			conf->modules[j][counts[j]++] = m;
		}
		if (m->filters.process_body) {
			int j = H2D_MODULE_FILTER_PROCESS_BODY;
			conf->modules[j][counts[j]++] = m;
		}
		if (m->filters.response_headers) {
			int j = H2D_MODULE_FILTER_RESPONSE_HEADERS;
			conf->modules[j][counts[j]++] = m;
		}
		if (m->filters.response_body) {
			int j = H2D_MODULE_FILTER_RESPONSE_BODY;
			conf->modules[j][counts[j]++] = m;
		}
	}

	for (int i = 0; i < H2D_MODULE_FILTER_NUM; i++) {
		h2d_module_filters_rank_index = i;
		h2d_module_filters_ranks = conf->ranks[i];
		qsort(conf->modules[i], counts[i], sizeof(struct h2d_module *), h2d_module_filter_cmp);
	}

	return WUY_CFLUA_OK;
}

struct wuy_cflua_table h2d_module_filters_conf_table = {
	.commands = (struct wuy_cflua_command[1]) { { NULL } },
	.size = sizeof(struct h2d_module_filters),
	.arbitrary = h2d_module_filters_arbitrary,
	.init = h2d_module_filters_init,
	.post = h2d_module_filters_post,
};

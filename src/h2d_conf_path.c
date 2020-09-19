#include "h2d_main.h"

static int h2d_conf_path_name(void *data, char *buf, int size)
{
	struct h2d_conf_path *conf_path = data;
	if (conf_path->pathnames == NULL) {
		return 0;
	}
	return snprintf(buf, size, "Path(%s)>", conf_path->pathnames[0]);
}

/* make sure there is one and only one content module is enabled */
static bool h2d_conf_path_post(void *data)
{
	struct h2d_conf_path *conf_path = data;

	int i;
	for (i = 0; i < h2d_module_number; i++) {
		void *mod_conf = conf_path->module_confs[i];
		if (mod_conf == NULL) {
			continue;
		}

		struct h2d_module *m = h2d_module_content_is_enabled(i, mod_conf);
		if (m == NULL) {
			continue;
		}

		if (conf_path->content == NULL) {
			conf_path->content = m;
			continue;
		}

		/* compare meta_level, pick the smaller */
		int meta_level_new = conf_path->content_meta_levels[i];
		int meta_level_old = conf_path->content_meta_levels[conf_path->content->index];
		if (meta_level_new == meta_level_old) {
			printf("duplicate content %s %s\n", conf_path->content->name, m->name);
			return false;
		}
		if (meta_level_new < meta_level_old) {
			conf_path->content = m;
		}
	}

	if (conf_path->content == NULL && conf_path->pathnames != NULL) {
		printf("no content set, %s\n", conf_path->pathnames[0]);
		return false;
	}

	return true;
}

static struct wuy_cflua_command h2d_conf_path_commands[] = {
	{	.name = "_pathnames",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_path, pathnames),
		.u.table = WUY_CFLUA_ARRAY_STRING_TABLE,
	},
	{	.name = "error_log",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = offsetof(struct h2d_conf_path, error_log),
		.u.table = &h2d_log_conf_table,
	},
	{	.type = WUY_CFLUA_TYPE_END,
		.u.next = h2d_module_next_path_command,
	},
};

struct wuy_cflua_table h2d_conf_path_table = {
	.commands = h2d_conf_path_commands,
	.size = sizeof(struct h2d_conf_path),
	.post = h2d_conf_path_post,
	.name = h2d_conf_path_name,
};

#include "h2d_main.h"

static int h2d_conf_path_name(void *data, char *buf, int size)
{
	struct h2d_conf_path *conf_path = data;
	return snprintf(buf, size, "Path(%s)>", conf_path->pathnames[0]);
}

/* make sure there is one and only one content module is enabled */
static bool h2d_conf_path_post(void *data)
{
	struct h2d_conf_path *conf_path = data;

	int i;
	for (i = 0; i < H2D_MODULE_NUMBER; i++) {
		void *mod_conf = conf_path->module_confs[i];
		if (mod_conf == NULL) {
			continue;
		}

		struct h2d_module *m = h2d_module_content_is_enabled(i, mod_conf);
		if (m == NULL) {
			continue;
		}

		if (conf_path->content != NULL) {
			printf("duplicate content %s %s\n", conf_path->content->name, m->name);
			return false;
		}

		conf_path->content = m;
	}

	if (conf_path->content == NULL) {
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

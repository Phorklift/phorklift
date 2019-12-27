#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "h2d_main.h"

struct h2d_static_stats {
	atomic_int	total;
	atomic_int	fail;
};
struct h2d_static_conf {
	const char	*dir_name;
	int		dirfd;

	const char	*index;

	struct h2d_static_stats	*stats;
};

extern struct h2d_module h2d_static_module;


/* content handlers */
#define H2D_STATIC_CTX_FD(R) (int)(uintptr_t)(r->module_ctxs[h2d_static_module.request_ctx.index])

static int h2d_static_process_request_headers(struct h2d_request *r)
{
	struct h2d_static_conf *conf = r->conf_path->module_confs[h2d_static_module.index];
	atomic_fetch_add(&conf->stats->total, 1);

	const char *url = h2d_header_value(r->req.url);
	int fd = openat(conf->dirfd, url + 1, O_RDONLY);
	if (fd < 0) {
		atomic_fetch_add(&conf->stats->fail, 1);
		printf("error to open file: %s\n", url);
		return H2D_HTTP_404;
	}
	r->module_ctxs[h2d_static_module.request_ctx.index] = (void *)(uintptr_t)fd;
	return H2D_OK;
}
static int h2d_static_process_request_body(struct h2d_request *r)
{
	return 0;
}
static int h2d_static_generate_response_headers(struct h2d_request *r)
{
	int fd = H2D_STATIC_CTX_FD(r);

	struct stat st_buf;
	fstat(fd, &st_buf);
	r->resp.content_length = st_buf.st_size;
	// r->date = st_buf.st_mtim;

	r->resp.status_code = 200;
	return H2D_OK;
}
static int h2d_static_generate_response_body(struct h2d_request *r, uint8_t *buf, int len)
{
	int fd = H2D_STATIC_CTX_FD(r);
	int ret = read(fd, buf, len);
	if (ret < 0) {
		perror("read file fail");
		return -1;
	}
	return ret;
}

static void h2d_static_ctx_free(struct h2d_request *r)
{
	int fd = H2D_STATIC_CTX_FD(r);
	close(fd);
}


/* configuration */

static bool h2d_static_conf_is_enable(void *data)
{
	struct h2d_static_conf *conf = data;
	return conf->dirfd != 0;
}

static bool h2d_static_conf_post(void *data)
{
	struct h2d_static_conf *conf = data;

	if (conf->dir_name == NULL) {
		return true;
	}

	conf->dirfd = open(conf->dir_name, O_RDONLY, O_DIRECTORY);
	if (conf->dirfd < 0) {
		printf("static: fail to open dir\n");
		return false;
	}
	// printf("debug: open %s\n", conf->dir_name);

	conf->stats = wuy_shmem_alloc(sizeof(struct h2d_static_stats));

	return true;
}
static void h2d_static_conf_cleanup(void *data)
{
	struct h2d_static_conf *conf = data;
	if (conf->dirfd != 0) {
		close(conf->dirfd);
	}
}

static int h2d_static_conf_stats(void *data, char *buf, int len)
{
	struct h2d_static_conf *conf = data;
	struct h2d_static_stats *stats = conf->stats;
	if (stats == NULL) {
		return 0;
	}
	return snprintf(buf, len, "static: %d %d\n", atomic_load(&stats->total), atomic_load(&stats->fail));
}

static struct wuy_cflua_command h2d_static_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_static_conf, dir_name),
		.flags = WUY_CFLUA_FLAG_UNIQ_MEMBER,
	},
	{	.name = "index",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_static_conf, index),
	},
	{ NULL }
};

struct h2d_module h2d_static_module = {
	.name = "static",
	.command_path = {
		.name = "static",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = 0, /* reset later */
		.u.table = &(struct wuy_cflua_table) {
			.commands = h2d_static_conf_commands,
			.size = sizeof(struct h2d_static_conf),
			.post = h2d_static_conf_post,
			.cleanup = h2d_static_conf_cleanup,
		}
	},
	.stats_path = h2d_static_conf_stats,

	.content = {
		.is_enable = h2d_static_conf_is_enable,
		.process_headers = h2d_static_process_request_headers,
		.process_body = h2d_static_process_request_body,
		.response_headers = h2d_static_generate_response_headers,
		.response_body = h2d_static_generate_response_body,
	},

	.request_ctx = {
		.free = h2d_static_ctx_free,
	},

	/* TODO stats in module angle. do we need path,host,listen, or a single one?
	.stats = {
		.size = sizeof(struct h2d_static_stats),
	},
	*/
};

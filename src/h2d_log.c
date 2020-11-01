#include "h2d_main.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static WUY_LIST(h2d_log_file_list);

struct h2d_log_file {
	wuy_list_node_t		list_node;
	const char		*name;
	int			fd;
	char			*pos;
	int			buf_size;
	char			buffer[0];
};

struct h2d_log_file *h2d_log_file_open(const char *filename, int buf_size)
{
	/* search file */
	struct h2d_log_file *file;
	wuy_list_iter_type(&h2d_log_file_list, file, list_node) {
		if (strcmp(file->name, filename) == 0) {
			return file;
		}
	}

	/* open new file */
	file = malloc(sizeof(struct h2d_log_file) + buf_size);
	file->fd = open(filename, O_WRONLY | O_APPEND | O_CREAT, 0644);
	if (file->fd < 0) {
		printf("error in open log file %s %s\n", filename, strerror(errno));
		return NULL;
	}
	file->name = filename;
	file->pos = file->buffer;
	file->buf_size = buf_size;
	wuy_list_append(&h2d_log_file_list, &file->list_node);

	return file;
}

static void h2d_log_file_flush(struct h2d_log_file *file)
{
	if (write(file->fd, file->buffer, file->pos - file->buffer) < 0) {
		perror("fail in flush log");
	}
	file->pos = file->buffer;
}

void h2d_log_file_write(struct h2d_log_file *file, int max_line, const char *fmt, ...)
{
	char *end = file->buffer + file->buf_size;
	if (end - file->pos < max_line) {
		h2d_log_file_flush(file);
	}

	file->pos += wuy_time_rfc3339(file->pos, WUY_TIME_ZONE_LOCAL);
	*file->pos++ = ' ';

        va_list ap;
        va_start(ap, fmt);
        file->pos += vsnprintf(file->pos, end - file->pos - 1, fmt, ap);
        va_end(ap);

	if (file->pos > end - 1) {
		printf("too long line. %ld %d\n", file->pos - end, file->buf_size);
		file->pos = end - 1;
	}

	*file->pos++ = '\n';
}

static void h2d_log_routine(void *data)
{
	struct h2d_log_file *file;
	wuy_list_iter_type(&h2d_log_file_list, file, list_node) {
		if (file->pos > file->buffer) {
			h2d_log_file_flush(file);
		}
	}
}

void h2d_log_init(void)
{
	loop_idle_add(h2d_loop, h2d_log_routine, NULL);
}

/* error log */

static enum h2d_log_level h2d_log_parse_level(const char *str)
{
	if (strcmp(str, "debug") == 0) {
		return H2D_LOG_DEBUG;
	} else if (strcmp(str, "info") == 0) {
		return H2D_LOG_INFO;
	} else if (strcmp(str, "warn") == 0) {
		return H2D_LOG_WARN;
	} else if (strcmp(str, "error") == 0) {
		return H2D_LOG_ERROR;
	} else if (strcmp(str, "fatal") == 0) {
		return H2D_LOG_FATAL;
	} else {
		return -1;
	}
}

static bool h2d_log_conf_post(void *data)
{
	struct h2d_log *log = data;

	log->level = h2d_log_parse_level(log->conf_level);
	if (log->level < 0) {
		printf("invalid log level\n");
		return false;
	}
	if (log->max_line > log->buf_size) {
		printf("expect: max_line <= buffer_size\n");
		return false;
	}

	log->file = h2d_log_file_open(log->conf_filename, log->buf_size);
	return log->file != NULL;
}

static struct wuy_cflua_command h2d_log_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.is_single_array = true,
		.offset = offsetof(struct h2d_log, conf_filename),
		.default_value.s = "error.log",
	},
	{	.name = "buffer_size",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_log, buf_size),
		.limits.n = WUY_CFLUA_LIMITS_LOWER(4 * 1024),
		.default_value.n = 16 * 1024,
	},
	{	.name = "max_line",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_log, max_line),
		.default_value.n = 2 * 1024,
	},
	{	.name = "level",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_log, conf_level),
		.default_value.s = "error",
	},
	{ NULL },
};
struct wuy_cflua_table h2d_log_conf_table = {
	.commands = h2d_log_conf_commands,
	.size = sizeof(struct h2d_log),
	.post = h2d_log_conf_post,
};

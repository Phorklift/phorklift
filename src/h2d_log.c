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

void h2d_log_file_vwrite(struct h2d_log_file *file, int max_line, const char *fmt, va_list ap)
{
	char *end = file->buffer + file->buf_size;
	if (end - file->pos < max_line) {
		h2d_log_file_flush(file);
	}

	file->pos += wuy_time_rfc3339(file->pos, WUY_TIME_ZONE_LOCAL);
	*file->pos++ = ' ';

	file->pos += vsnprintf(file->pos, end - file->pos - 1, fmt, ap);

	if (file->pos > end - 1) {
		printf("too long line. %ld %d\n", file->pos - end, file->buf_size);
		file->pos = end - 1;
	}

	*file->pos++ = '\n';
}

void h2d_log_file_write(struct h2d_log_file *file, int max_line, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	h2d_log_file_vwrite(file, max_line, fmt, ap);
	va_end(ap);
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

struct h2d_log h2d_global_log;
void h2d_log_global(const char *filename)
{
	h2d_global_log.level = H2D_LOG_ERROR;
	h2d_global_log.max_line = 2 * 1024;
	h2d_global_log.buf_size = 16 * 1024;
	h2d_global_log.file = h2d_log_file_open(filename, 16*1024);

	if (h2d_global_log.file == NULL) {
		fprintf(stderr, "fail in open global error.log: %s %s\n",
				filename, strerror(errno));
		exit(H2D_EXIT_GETOPT);
	}
}

void h2d_log_init(void)
{
	loop_defer_add(h2d_loop, h2d_log_routine, NULL);
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

static const char *h2d_log_conf_post(void *data)
{
	struct h2d_log *log = data;

	log->level = h2d_log_parse_level(log->level_str);
	if (log->level < 0) {
		return "invalid log level";
	}
	if (log->max_line > log->buf_size) {
		return "expect max_line <= buffer_size";
	}

	if (log->filename == NULL) {
		log->file = h2d_global_log.file;
		return WUY_CFLUA_OK;
	}

	log->file = h2d_log_file_open(log->filename, log->buf_size);
	if (log->file == NULL) {
		wuy_cflua_post_arg = log->filename;
		return "fail in open log file";
	}

	return WUY_CFLUA_OK;
}

static struct wuy_cflua_command h2d_log_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.is_single_array = true,
		.offset = offsetof(struct h2d_log, filename),
		.meta_level_offset = offsetof(struct h2d_log, filename_meta_level),
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
		.offset = offsetof(struct h2d_log, level_str),
		.meta_level_offset = offsetof(struct h2d_log, level_meta_level),
		.default_value.s = "error",
	},
	{ NULL },
};
struct wuy_cflua_table h2d_log_conf_table = {
	.commands = h2d_log_conf_commands,
	.size = sizeof(struct h2d_log),
	.post = h2d_log_conf_post,
};

#include "h2d_main.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static WUY_LIST(h2d_log_file_list);

struct h2d_log_file {
	wuy_list_node_t		list_node;
	const char		*name;
	int			fd;
	int			refs;
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
			file->refs++;
			return file;
		}
	}

	/* open new file */
	file = malloc(sizeof(struct h2d_log_file) + buf_size);
	file->fd = open(filename, O_WRONLY | O_APPEND | O_CREAT, 0644);
	if (file->fd < 0) {
		return NULL;
	}
	file->refs = 1;
	file->name = filename;
	file->pos = file->buffer;
	file->buf_size = buf_size;
	wuy_list_append(&h2d_log_file_list, &file->list_node);

	return file;
}

static void h2d_log_file_close(struct h2d_log_file *file)
{
	if (--file->refs > 0) {
		return;
	}
	close(file->fd);
	wuy_list_delete(&file->list_node);
	free(file);
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

void h2d_log_init(void)
{
	loop_defer_add(h2d_loop, h2d_log_routine, NULL);
}

/* error log */

static enum h2d_log_level h2d_log_parse_level(const char *str)
{
#define X(c, l)	if (strcmp(str, #l) == 0) return H2D_LOG_##c;
	H2D_LOG_LEVEL_TABLE
#undef X
	return -1;
}

static const char *h2d_log_conf_post(void *data)
{
	struct h2d_log *log = data;

	log->level = h2d_log_parse_level(log->level_str);
	if (log->level == -1) {
		return "invalid log level";
	}
	if (log->buf_size == 0) {
		log->is_line_buffer = true;
		log->buf_size = 16 * 1024;
	} else if (log->max_line > log->buf_size) {
		return "expect max_line <= buffer_size";
	}

	if (log->filename == NULL) {
		log->filename = (h2d_conf_runtime != NULL) ? h2d_conf_runtime->error_log->filename : "error.log";
	}
	log->file = h2d_log_file_open(log->filename, log->buf_size);
	if (log->file == NULL) {
		wuy_cflua_post_arg = log->filename;
		return "fail in open log file";
	}

	return WUY_CFLUA_OK;
}

static void h2d_log_conf_free(void *data)
{
	struct h2d_log *log = data;
	if (log->file != NULL) {
		h2d_log_file_close(log->file);
	}
}

static struct wuy_cflua_command h2d_log_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_STRING,
		.is_single_array = true,
		.offset = offsetof(struct h2d_log, filename),
	},
	{	.name = "buffer_size",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_log, buf_size),
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
		.default_value.n = 16 * 1024,
	},
	{	.name = "max_line",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_log, max_line),
		.limits.n = WUY_CFLUA_LIMITS_LOWER(80),
		.default_value.n = 4 * 1024,
	},
	{	.name = "level",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_log, level_str),
		.default_value.s = "error",
	},
	{ NULL },
};
struct wuy_cflua_table h2d_log_conf_table = {
	.commands = h2d_log_conf_commands,
	.refer_name = "LOG",
	.size = sizeof(struct h2d_log),
	.post = h2d_log_conf_post,
	.free = h2d_log_conf_free,
};
struct wuy_cflua_table h2d_log_omit_conf_table = {
	.commands = h2d_log_conf_commands,
	.refer_name = "LOG",
	.may_omit = true,
	.size = sizeof(struct h2d_log),
	.post = h2d_log_conf_post,
	.free = h2d_log_conf_free,
};

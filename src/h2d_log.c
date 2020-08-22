#include "h2d_main.h"

#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define H2D_LOG_BUFFER_SIZE	1024*16
#define H2D_LOG_MAX_LENGTH	1024

static WUY_LIST(h2d_log_file_list);

static pid_t h2d_log_pid;

struct h2d_log_file {
	wuy_list_node_t		list_node;
	const char		*name;
	int			fd;
	char			*pos;
	char			buffer[H2D_LOG_BUFFER_SIZE];
};

static int h2d_log_time(char *buffer)
{
/* TODO need to optimize? */

#define H2D_LOG_TIME_SIZE_TZ	(sizeof("+0800") - 1)
#define H2D_LOG_TIME_SIZE_SEC	(sizeof("2018-09-19T16:53:50.") - 1)
#define H2D_LOG_TIME_SIZE_USEC	(sizeof("123456") - 1)

        static char buf_sec[H2D_LOG_TIME_SIZE_SEC + 1];
        static char buf_usec[H2D_LOG_TIME_SIZE_USEC + 1];
        static char buf_tz[H2D_LOG_TIME_SIZE_TZ + 1];

        static struct timeval last;

        struct timeval now;
        gettimeofday(&now, NULL);

        if (now.tv_sec != last.tv_sec) {
                struct tm *tm = localtime(&now.tv_sec);
                sprintf(buf_sec, "%04d-%02d-%02dT%02d:%02d:%02d.",
                                tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                                tm->tm_hour, tm->tm_min, tm->tm_sec);
        }

        if (now.tv_usec != last.tv_usec) {
                sprintf(buf_usec, "%06ld", now.tv_usec);
        }

        if (last.tv_sec == 0) {
		/* timezone */
                time_t tmp = time(NULL);
                struct tm *tm = localtime(&tmp);

                int off_sign = '+';
                int off = (int) tm->tm_gmtoff;
                if (tm->tm_gmtoff < 0) {
                        off_sign = '-';
                        off = -off;
                }

                off /= 60; /* second to minute */
                sprintf(buf_tz, "%c%02d%02d", off_sign, off / 60, off % 60);
        }

        last = now;

	char *p = buffer;
	memcpy(p, buf_sec, H2D_LOG_TIME_SIZE_SEC);
	p += H2D_LOG_TIME_SIZE_SEC;
	memcpy(p, buf_usec, H2D_LOG_TIME_SIZE_USEC);
	p += H2D_LOG_TIME_SIZE_USEC;
	memcpy(p, buf_tz, H2D_LOG_TIME_SIZE_SEC);
	p += H2D_LOG_TIME_SIZE_TZ;

        return p - buffer;
}

#define H2D_STRMOVE(buf, str)  memcpy(buf, str, sizeof(str) - 1); return sizeof(str) - 1;
static int h2d_log_strlevel(char *buffer, enum h2d_log_level level)
{
	switch (level) {
	case H2D_LOG_DEBUG: H2D_STRMOVE(buffer, "[debug]");
	case H2D_LOG_INFO:  H2D_STRMOVE(buffer, "[info]");
	case H2D_LOG_WARN:  H2D_STRMOVE(buffer, "[warn]");
	case H2D_LOG_ERROR: H2D_STRMOVE(buffer, "[error]");
	case H2D_LOG_FATAL: H2D_STRMOVE(buffer, "[fatal]");
	default: abort();
	}
}

static void h2d_log_file_flush(struct h2d_log_file *file)
{
	if (write(file->fd, file->buffer, file->pos - file->buffer) < 0) {
		perror("fail in flush log");
	}
	file->pos = file->buffer;
}

void h2d_log_write(struct h2d_log *log, enum h2d_log_level level, const char *fmt, ...)
{
	struct h2d_log_file *file = log->file;

	if (H2D_LOG_BUFFER_SIZE - (file->pos - file->buffer) < H2D_LOG_MAX_LENGTH) {
		h2d_log_file_flush(file);
	}

	file->pos += h2d_log_time(file->pos);
	*file->pos++ = ' ';

	file->pos += h2d_log_strlevel(file->pos, level);
	*file->pos++ = ' ';

	file->pos += sprintf(file->pos, "%d ", h2d_log_pid);

        va_list ap;
        va_start(ap, fmt);
	size_t size = H2D_LOG_BUFFER_SIZE - (file->pos - file->buffer) - 1;
        file->pos += vsnprintf(file->pos, size, fmt, ap);
        va_end(ap);
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

struct h2d_log *h2d_log_new(const char *filename, enum h2d_log_level level)
{
	struct h2d_log *log = malloc(sizeof(struct h2d_log));
	log->level = level;

	/* search file */
	struct h2d_log_file *file;
	wuy_list_iter_type(&h2d_log_file_list, file, list_node) {
		if (strcmp(file->name, filename) == 0) {
			log->file = file;
			return log;
		}
	}

	/* open new file */
	file = malloc(sizeof(struct h2d_log_file));
	file->fd = open(filename, O_WRONLY | O_APPEND | O_CREAT, 0644);
	if (file->fd < 0) {
		printf("error in open log file %s %s\n", filename, strerror(errno));
		return NULL;
	}
	file->name = strdup(filename);
	file->pos = file->buffer;
	wuy_list_append(&h2d_log_file_list, &file->list_node);

	log->file = file;
	return log;
}

void h2d_log_init(void)
{
	h2d_log_pid = getpid();
	loop_idle_add(h2d_loop, h2d_log_routine, NULL);
}

#ifndef H2D_LOG_H
#define H2D_LOG_H

/* log file */

struct h2d_log_file;

struct h2d_log_file *h2d_log_file_open(const char *filename, int buf_size);

void h2d_log_file_write(struct h2d_log_file *file, int max_line, const char *fmt, ...);

void h2d_log_file_vwrite(struct h2d_log_file *file, int max_line, const char *fmt, va_list ap);

/* error log */

#define H2D_LOG_LEVEL_TABLE \
	X(DEBUG, debug) \
	X(INFO, info) \
	X(WARN, warn) \
	X(ERROR, error) \
	X(FATAL, fatal)

enum h2d_log_level {
#define X(c, l) H2D_LOG_##c,
	H2D_LOG_LEVEL_TABLE
#undef X
};

static inline const char *h2d_log_strlevel(enum h2d_log_level level)
{
	switch (level) {
#define X(c, l) case H2D_LOG_##c: return "[" #l "]";
	H2D_LOG_LEVEL_TABLE
#undef X
	default: abort();
	}
}

struct h2d_log {
	const char		*filename;
	const char		*level_str;
	int			filename_meta_level;
	int			level_meta_level;
	int			buf_size;
	int			max_line;
	bool			is_line_buffer;

	enum h2d_log_level	level;
	struct h2d_log_file	*file;
};

#define h2d_log_level_nocheck(log, level2, fmt, ...) \
	h2d_log_file_write(log->file, log->max_line, \
			"%s %d:" fmt, h2d_log_strlevel(level2), h2d_pid, ##__VA_ARGS__)

// XXX add level
#define h2d_log_level_v_nocheck(log, level2, fmt, ap) \
	h2d_log_file_vwrite(log->file, log->max_line, fmt, ap)

#define h2d_log_level(log, level2, fmt, ...) \
	if (level2 >= log->level) h2d_log_level_nocheck(log, level2, fmt, ##__VA_ARGS__)

#define h2d_log_level_v(log, level2, fmt, ap) \
	if (level2 >= log->level) h2d_log_level_v_nocheck(log, level2, fmt, ap)

#define h2d_assert(expr) if (!(expr)) h2d_log_fatal("assert fail: " #expr " at %s()", __FUNCTION__)

extern struct wuy_cflua_table h2d_log_conf_table; 

void h2d_log_init(void);

#endif

#ifndef H2D_LOG_H
#define H2D_LOG_H

enum h2d_log_level {
	H2D_LOG_DEBUG,
	H2D_LOG_INFO,
	H2D_LOG_WARN,
	H2D_LOG_ERROR,
	H2D_LOG_FATAL,
};

struct h2d_log {
	const char		*conf_filename;
	const char		*conf_level;

	enum h2d_log_level	level;
	struct h2d_log_file	*file;
};

/* internal */
void h2d_log_write(struct h2d_log *log, enum h2d_log_level level, const char *fmt, ...);
#define h2d_log_level(log, level2, fmt, ...) \
	if (level2 <= log->level) h2d_log_write(log, level2, fmt, ##__VA_ARGS__)


/* API */
#define h2d_log_debug(log, fmt, ...)	h2d_log_level(log, H2D_LOG_DEBUG, fmt, ##__VA_ARGS__)
#define h2d_log_info(log, fmt, ...)	h2d_log_level(log, H2D_LOG_INFO, fmt, ##__VA_ARGS__)
#define h2d_log_warn(log, fmt, ...)	h2d_log_level(log, H2D_LOG_WARN, fmt, ##__VA_ARGS__)
#define h2d_log_error(log, fmt, ...)	h2d_log_level(log, H2D_LOG_ERROR, fmt, ##__VA_ARGS__)
#define h2d_log_fatal(log, fmt, ...)	h2d_log_level(log, H2D_LOG_FATAL, fmt, ##__VA_ARGS__)

#define h2d_assert(expr) if (!(expr)) h2d_log_fatal("assert fail: " #expr " at %s()", __FUNCTION__)

struct h2d_log *h2d_log_new(const char *filename, enum h2d_log_level level);

void h2d_log_init(void);

extern struct wuy_cflua_table h2d_log_conf_table; 

#endif

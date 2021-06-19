#ifndef PHL_LOG_H
#define PHL_LOG_H

/* log file */

struct phl_log_file;

struct phl_log_file *phl_log_file_open(const char *filename, int buf_size);

void phl_log_file_write(struct phl_log_file *file, int max_line, const char *fmt, ...);

void phl_log_file_vwrite(struct phl_log_file *file, int max_line, const char *fmt, va_list ap);

/* error log */

#define PHL_LOG_LEVEL_TABLE \
	X(DEBUG, debug) \
	X(INFO, info) \
	X(WARN, warn) \
	X(ERROR, error) \
	X(FATAL, fatal)

enum phl_log_level {
#define X(c, l) PHL_LOG_##c,
	PHL_LOG_LEVEL_TABLE
#undef X
};

static inline const char *phl_log_strlevel(enum phl_log_level level)
{
	switch (level) {
#define X(c, l) case PHL_LOG_##c: return "[" #l "]";
	PHL_LOG_LEVEL_TABLE
#undef X
	default: abort();
	}
}

struct phl_log {
	const char		*filename;
	const char		*level_str;
	int			buf_size;
	int			max_line;
	bool			is_line_buffer;

	enum phl_log_level	level;
	struct phl_log_file	*file;
};

#define phl_log_level(log, level2, fmt, ...) \
	if (level2 >= log->level) { \
		phl_log_file_write(log->file, log->max_line, \
				"%s %d:" fmt, phl_log_strlevel(level2), \
				phl_pid, ##__VA_ARGS__); \
	}

#define phl_assert(expr) if (!(expr)) phl_log_fatal("assert fail: " #expr " at %s()", __FUNCTION__)

extern struct wuy_cflua_table phl_log_conf_table; 
extern struct wuy_cflua_table phl_log_omit_conf_table;

void phl_log_init(void);

#endif

#ifndef H2D_REQUEST_H
#define H2D_REQUEST_H

struct h2d_request;

#include "h2d_module.h"
#include "h2d_header.h"
#include "h2d_conf.h"
#include "h2d_connection.h"

#define H2D_CONTENT_LENGTH_INIT	(SIZE_MAX-1)

struct h2d_request {
	struct {
		enum wuy_http_method	method;
		int			version;
		size_t			content_length;

		struct {
			const char	*raw;
			const char	*path;
			bool		is_rewrited;

			const char	*path_pos;
			const char	*query_pos;
			int		path_len;
			int		query_len;
		} uri;

		const char		*host;
		wuy_slist_t		headers;

		wuy_http_chunked_t	chunked;

		uint8_t			*body_buf;
		int			body_len;
		bool			body_finished;
	} req;

	struct {
		enum wuy_http_status_code  status_code;
		int			version;
		wuy_slist_t		headers;

		size_t			content_length;
		size_t			content_generate_length;
		size_t			sent_length;
		uint8_t			*broken_body_buf;
		int			broken_body_len;
	} resp;

	enum {
		H2D_REQUEST_STATE_PARSE_HEADERS = 0,
		H2D_REQUEST_STATE_PROCESS_HEADERS,
		H2D_REQUEST_STATE_PROCESS_BODY,
		H2D_REQUEST_STATE_RESPONSE_HEADERS,
		H2D_REQUEST_STATE_RESPONSE_BODY,
		H2D_REQUEST_STATE_DONE,
	} state;

	bool			closed;
	bool			is_broken; //TODO may put in h2d_request_run()?

	int			filter_step_process_headers;
	int			filter_step_process_body;

	long			create_time;
	long			req_end_time;
	long			resp_begin_time;

	struct h2d_request	*father; /* only for subreq */
	wuy_list_t		subr_head;
	wuy_list_node_t		subr_node;

	wuy_list_node_t		list_node;

	http2_stream_t		*h2s;

	struct h2d_connection	*c;

	struct h2d_conf_host	*conf_host;
	struct h2d_conf_path	*conf_path;

	/* #module_ctxs should be $h2d_module_number.
	 * However it's not known in compiling because of dynamic
	 * modules, so set 0 by now. */
	void 			*module_ctxs[0];
};

struct h2d_request *h2d_request_new(struct h2d_connection *c);
void h2d_request_close(struct h2d_request *r);

bool h2d_request_set_uri(struct h2d_request *r, const char *uri_str, int uri_len);
bool h2d_request_set_host(struct h2d_request *r, const char *host_str, int host_len);

void h2d_request_reset_response(struct h2d_request *r);

static inline bool h2d_request_is_subreq(struct h2d_request *r)
{
	return r->father != NULL;
}

void h2d_request_run(struct h2d_request *r, int window);

void h2d_request_active(struct h2d_request *r);

void h2d_request_init(void);

struct h2d_request *h2d_request_subrequest(struct h2d_request *father);

/* used only for h2d_request_log and h2d_request_log_at */
static inline struct h2d_log *h2d_request_get_log(struct h2d_request *r)
{
	if (r->conf_path != NULL) {
		return r->conf_path->error_log;
	}
	if (r->conf_host != NULL) {
		return r->conf_host->default_path->error_log;
	}
	return r->c->conf_listen->default_host->default_path->error_log;
}

#define h2d_request_do_log(r, log, level, fmt, ...) \
	if (level >= H2D_LOG_ERROR && r->req.uri.raw) { \
		h2d_log_level_nocheck(log, level, "%s " fmt, r->req.uri.raw, ##__VA_ARGS__); \
	} else { \
		h2d_log_level_nocheck(log, level, fmt, ##__VA_ARGS__); \
	}

#define h2d_request_log_at(r, log, level2, fmt, ...) \
	do { \
		if (level2 < log->level) break; \
		struct h2d_log *_log = log->file ? log : h2d_request_get_log(r); \
		h2d_request_do_log(r, _log, level2, fmt, ##__VA_ARGS__); \
	} while(0)

#define h2d_request_log(r, level2, fmt, ...) \
	do { \
		struct h2d_log *_log = h2d_request_get_log(r); \
		if (level2 < _log->level) break; \
		h2d_request_do_log(r, _log, level2, fmt, ##__VA_ARGS__); \
	} while(0)

#endif

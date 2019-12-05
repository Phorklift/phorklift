#ifndef H2D_REQUEST_H
#define H2D_REQUEST_H

struct h2d_request;

#include "h2d_header.h"
#include "h2d_conf.h"
#include "h2d_connection.h"

#define H2D_CONTENT_LENGTH_INIT		(SIZE_MAX-1)
#define H2D_CONTENT_LENGTH_CHUNKED	(SIZE_MAX-3)

enum h2d_request_state {
	H2D_REQUEST_STATE_PARSE_HEADERS = 0,
	H2D_REQUEST_STATE_PROCESS_HEADERS,
	H2D_REQUEST_STATE_PROCESS_BODY,
	H2D_REQUEST_STATE_RESPONSE_HEADERS,
	H2D_REQUEST_STATE_RESPONSE_BODY,
	H2D_REQUEST_STATE_CLOSED,
};

struct h2d_request {
	struct {
		int			method;
		int			version;
		struct h2d_header	*url;
		struct h2d_header	*host;
		size_t			content_length;

		struct h2d_header	*buffer;
		struct h2d_header	*next;

		wuy_http_chunked_t	chunked;

		uint8_t			*body_buf;
		int			body_len;
		bool			body_finished;
	} req;

	struct {
		int			status_code;
		int			version;

		struct h2d_header	*buffer;
		struct h2d_header	*next;

		size_t			content_length;
		size_t			content_generate_length;
		size_t			sent_length;
		bool			is_body_filtered;
	} resp;

	enum h2d_request_state	state;

	struct h2d_request	*father; /* only for subreq */
	struct h2d_request	*subr; /* only for subreq */

	wuy_list_node_t		list_node;

	http2_stream_t		*h2s;

	struct h2d_connection	*c;

	struct h2d_conf_host	*conf_host;
	struct h2d_conf_path	*conf_path;

	void 			*module_ctxs[0];
};

struct h2d_request *h2d_request_new(struct h2d_connection *c);
void h2d_request_close(struct h2d_request *r);

static inline bool h2d_request_is_closed(struct h2d_request *r)
{
	return r->state == H2D_REQUEST_STATE_CLOSED;
}
static inline bool h2d_request_is_subreq(struct h2d_request *r)
{
	return r->father != NULL;
}

void h2d_request_run(struct h2d_request *r, int window);

void h2d_request_active(struct h2d_request *r);

void h2d_request_init(void);

struct h2d_request *h2d_request_subreq_new(struct h2d_request *father);

#endif

#ifndef H2D_STATUS_CODE_H
#define H2D_STATUS_CODE_H

#define H2D_STATUS_CODE_TABLE \
	X(200, "OK") \
	X(201, "Created") \
	X(202, "Accepted") \
	X(204, "No Content") \
	X(301, "Moved Permanently") \
	X(302, "Found") \
	X(303, "See Other") \
	X(307, "Temporary Redirect") \
	X(400, "Bad Request") \
	X(401, "Unauthorized") \
	X(403, "Forbidden") \
	X(404, "Not Found") \
	X(405, "Method Not Allowed") \
	X(406, "Not Acceptable") \
	X(408, "Request Timeout") \
	X(500, "Internal Server Error") \
	X(502, "Bad Gateway") \
	X(503, "Service Unavailable") \
	X(504, "Gateway Timeout")

enum h2d_status_code {
#define X(n, s) H2D_HTTP_##n = n,
	H2D_STATUS_CODE_TABLE
#undef X
};

static inline const char *h2d_status_code_string(int code)
{
	switch (code) {
#define X(n, s) case n: return s;
	H2D_STATUS_CODE_TABLE
#undef X
	default:
		return "XXX";
	}
}

static inline int h2d_status_code_response_body(int code, char *buf, int len)
{
#define H2D_STATUS_CODE_RESPONSE_BODY_FORMAT \
	"<html>\n" \
	"<head><title>%d %s</title></head>\n" \
	"<body>\n" \
	"<h1>%d %s</h1>\n" \
	"<hr><p><em>by h2tpd</em></p>\n" \
	"</body>\n" \
	"</html>\n"

	if (code < 400) {
		return 0;
	}
	const char *str = h2d_status_code_string(code);
	return snprintf(buf, len, H2D_STATUS_CODE_RESPONSE_BODY_FORMAT,
			code, str, code, str);
}

#endif

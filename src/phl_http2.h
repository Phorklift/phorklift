#ifndef H2D_HTTP2_H
#define H2D_HTTP2_H

#include "phl_connection.h"

void phl_http2_on_readable(struct phl_connection *c);
void phl_http2_on_writable(struct phl_connection *c);

int phl_http2_response_headers(struct phl_request *r);

void phl_http2_response_body_packfix(struct phl_request *r,
		uint8_t **p_buf_pos, int *p_buf_len);
int phl_http2_response_body_pack(struct phl_request *r, uint8_t *payload,
		int length, bool is_body_finished);

void phl_http2_connection_init(struct phl_connection *c);

void phl_http2_init(void);

void phl_http2_request_close(struct phl_request *r);

extern struct wuy_cflua_command phl_conf_listen_http2_commands[];

#endif

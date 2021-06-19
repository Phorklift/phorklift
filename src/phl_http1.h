#ifndef H2D_HTTP1_H
#define H2D_HTTP1_H

#include "phl_connection.h"

void phl_http1_on_readable(struct phl_connection *c);
void phl_http1_on_writable(struct phl_connection *c);

int phl_http1_request_headers(struct phl_request *r);
int phl_http1_request_body(struct phl_request *r);

int phl_http1_response_headers(struct phl_request *r);

void phl_http1_response_body_packfix(struct phl_request *r,
		uint8_t **p_buf_pos, int *p_buf_len);
int phl_http1_response_body_pack(struct phl_request *r, uint8_t *payload,
		int length, bool is_body_finished);

void phl_http1_request_close(struct phl_request *r);

extern struct wuy_cflua_command phl_conf_listen_http1_commands[];

#endif

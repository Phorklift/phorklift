#ifndef H2D_HTTP1_H
#define H2D_HTTP1_H

#include "h2d_connection.h"

int h2d_http1_on_read(struct h2d_connection *c, void *data, int buf_len);
void h2d_http1_on_writable(struct h2d_connection *c);

int h2d_http1_response_headers(struct h2d_request *r);

void h2d_http1_response_body_packfix(struct h2d_request *r,
		uint8_t **p_buf_pos, int *p_buf_len);
int h2d_http1_response_body_pack(struct h2d_request *r, uint8_t *payload,
		int length, bool is_body_finished);

void h2d_http1_request_close(struct h2d_request *r);

extern struct wuy_cflua_command h2d_conf_listen_http1_commands[];

#endif

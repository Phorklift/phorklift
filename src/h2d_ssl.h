#ifndef H2D_SSL_H
#define H2D_SSL_H

#include <openssl/ossl_typ.h>

SSL_CTX *h2d_ssl_ctx_new_server(const char *cert_fname, const char *pkey_fname);
SSL_CTX *h2d_ssl_ctx_new_client(void);

void h2d_ssl_stream_set(loop_stream_t *s, SSL_CTX *ctx, bool is_server);
int h2d_ssl_stream_handshake(loop_stream_t *s);

int h2d_ssl_stream_underlying_read(void *underlying, void *buffer, int buf_len);
int h2d_ssl_stream_underlying_write(void *underlying, const void *data, int len);
void h2d_ssl_stream_underlying_close(void *underlying);

const char *h2d_ssl_stream_error_string(loop_stream_t *s);

void h2d_ssl_init(void);

#endif

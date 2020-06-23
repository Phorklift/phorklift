#ifndef H2D_SSL_H
#define H2D_SSL_H

#include <openssl/ossl_typ.h>

SSL_CTX *h2d_ssl_ctx_new_server(const char *cert_fname, const char *pkey_fname);

SSL_CTX *h2d_ssl_ctx_new_client(void);

void h2d_ssl_stream_set(loop_stream_t *s, SSL_CTX *ctx, bool is_server, void *data);

void h2d_ssl_init(void);

#endif

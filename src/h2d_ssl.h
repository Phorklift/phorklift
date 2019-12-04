#ifndef H2D_SSL_H
#define H2D_SSL_H

#include <openssl/ssl.h>

SSL_CTX *h2d_ssl_ctx_new(const char *cert_fname, const char *pkey_fname);

void h2d_ssl_init(void);

#endif

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "h2d_main.h"

static int h2d_ssl_alpn_callback(SSL *ssl, const unsigned char **out,
		unsigned char *outlen, const unsigned char *in,
		unsigned int inlen, void *arg)
{
#define ALPN_ADVERTISE       (unsigned char *)"\x02h2\x08http/1.1"
	int ret = SSL_select_next_proto((unsigned char **)out, outlen, ALPN_ADVERTISE,
			sizeof(ALPN_ADVERTISE) - 1, in, inlen);
	if (ret != OPENSSL_NPN_NEGOTIATED) {
		return SSL_TLSEXT_ERR_NOACK;
	}

	if (*outlen == 2 && (*out)[0] == 'h' && (*out)[1] == '2') {
		h2d_http2_connection_init(SSL_get_ex_data(ssl, 0));
	}

	return SSL_TLSEXT_ERR_OK;
}

static int h2d_ssl_sni_callback(SSL *ssl, int *ad, void *arg)
{
	const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (name == NULL) {
		return SSL_TLSEXT_ERR_OK;
	}

	struct h2d_connection *c = SSL_get_ex_data(ssl, 0);
	c->ssl_sni_conf_host = h2d_conf_listen_search_hostname(c->conf_listen, name);
	if (c->ssl_sni_conf_host == NULL) {
		*ad = SSL_AD_INTERNAL_ERROR;
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}

	if (c->ssl_sni_conf_host->ssl.ctx != c->conf_listen->ssl_ctx) {
		// SSL_set_ssl_ctx(ssl, c->ssl_sni_conf_host->ssl.ctx);
	}

	return SSL_TLSEXT_ERR_OK;
}

SSL_CTX *h2d_ssl_ctx_new(const char *cert_fname, const char *pkey_fname)
{
	SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());
	SSL_CTX_set_ecdh_auto(ctx, 1);
	SSL_CTX_set_alpn_select_cb(ctx, h2d_ssl_alpn_callback, NULL);
	SSL_CTX_set_tlsext_servername_callback(ctx, h2d_ssl_sni_callback);

	if (cert_fname != NULL) {
		if (SSL_CTX_use_certificate_chain_file(ctx, cert_fname) != 1) {
			return NULL;
		}
		if (SSL_CTX_use_PrivateKey_file(ctx, pkey_fname, SSL_FILETYPE_PEM) != 1) {
			return NULL;
		}
	}

	return ctx;
}

SSL *h2d_ssl_new_server(SSL_CTX *ctx, int fd)
{
	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, fd);
	SSL_set_accept_state(ssl);
	return ssl;
}

void h2d_ssl_init(void)
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}
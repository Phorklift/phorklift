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
		printf("ssl NPN fail\n");
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
		printf("ssl SNI fail\n");
		*ad = SSL_AD_INTERNAL_ERROR;
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}

	if (c->ssl_sni_conf_host->ssl.ctx != c->conf_listen->ssl_ctx) {
		// SSL_set_ssl_ctx(ssl, c->ssl_sni_conf_host->ssl.ctx);
	}

	return SSL_TLSEXT_ERR_OK;
}

SSL_CTX *h2d_ssl_ctx_new_server(const char *cert_fname, const char *pkey_fname)
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

SSL_CTX *h2d_ssl_ctx_new_client(void)
{
	SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
	SSL_CTX_set_ecdh_auto(ctx, 1);
	return ctx;
}

void h2d_ssl_stream_set(loop_stream_t *s, SSL_CTX *ctx, bool is_server)
{
	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, loop_stream_fd(s));
	if (is_server) {
		SSL_set_accept_state(ssl);
		SSL_set_ex_data(ssl, 0, loop_stream_get_app_data(s));
	} else {
		SSL_set_connect_state(ssl);
	}

	loop_stream_set_underlying(s, ssl);
}

int h2d_ssl_stream_underlying_read(void *ssl, void *buffer, int buf_len)
{
	errno = 0;
	int read_len = SSL_read(ssl, buffer, buf_len);
	if (read_len <= 0) {
		int sslerr = SSL_get_error(ssl, read_len);
		if (sslerr == SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE) {
			errno = EAGAIN;
			return -1;
		}
		if (sslerr == SSL_ERROR_ZERO_RETURN) {
			return 0;
		}
		return -1;
	}
	return read_len;
}

int h2d_ssl_stream_underlying_write(void *ssl, const void *data, int len)
{
	errno = 0;
	int write_len = SSL_write(ssl, data, len);
	if (write_len <= 0) {
		int sslerr = SSL_get_error(ssl, write_len);
		if (sslerr != SSL_ERROR_WANT_READ && sslerr != SSL_ERROR_WANT_WRITE) {
			errno = EAGAIN;
		}
		return -1;
	}
	return write_len;
}

void h2d_ssl_stream_underlying_close(void *ssl)
{
	SSL_free(ssl);
}

void h2d_ssl_init(void)
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

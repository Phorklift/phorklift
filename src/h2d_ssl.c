#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "h2d_main.h"

struct h2d_ssl_ticket_secret {
	uint8_t		name[16];
	uint8_t		aes_key[16];
	uint8_t		hmac_key[16];
};

#define H2D_SSL_EX_DATA			0
#define H2D_SSL_CTX_EX_TICKET_SECRET	0
#define H2D_SSL_CTX_EX_STATS		1

static struct h2d_ssl_stats *h2d_ssl_get_stats(SSL *ssl)
{
	SSL_CTX *ssl_ctx = SSL_get_SSL_CTX(ssl);
	return SSL_CTX_get_ex_data(ssl_ctx, H2D_SSL_CTX_EX_STATS);
}

static int h2d_ssl_alpn_callback(SSL *ssl, const unsigned char **out,
		unsigned char *outlen, const unsigned char *in,
		unsigned int inlen, void *arg)
{
	struct h2d_ssl_stats *stats = h2d_ssl_get_stats(ssl);

#define ALPN_ADVERTISE       (unsigned char *)"\x02h2\x08http/1.1"
	int ret = SSL_select_next_proto((unsigned char **)out, outlen, ALPN_ADVERTISE,
			sizeof(ALPN_ADVERTISE) - 1, in, inlen);
	if (ret != OPENSSL_NPN_NEGOTIATED) {
		printf("ssl NPN fail\n");
		atomic_fetch_add(&stats->alpn_fail, 1);
		return SSL_TLSEXT_ERR_NOACK;
	}

	if (*outlen == 2 && (*out)[0] == 'h' && (*out)[1] == '2') {
		atomic_fetch_add(&stats->alpn_h2, 1);
		h2d_http2_connection_init(SSL_get_ex_data(ssl, H2D_SSL_EX_DATA));
	} else {
		atomic_fetch_add(&stats->alpn_miss, 1);
	}

	return SSL_TLSEXT_ERR_OK;
}

static int h2d_ssl_sni_callback(SSL *ssl, int *ad, void *arg)
{
	struct h2d_ssl_stats *stats = h2d_ssl_get_stats(ssl);

	const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (name == NULL) {
		return SSL_TLSEXT_ERR_OK;
	}

	struct h2d_connection *c = SSL_get_ex_data(ssl, H2D_SSL_EX_DATA);
	c->ssl_sni_conf_host = h2d_conf_host_locate(c->conf_listen, name);
	if (c->ssl_sni_conf_host == NULL) {
		printf("ssl SNI fail\n");
		atomic_fetch_add(&stats->sni_miss, 1);
		*ad = SSL_AD_INTERNAL_ERROR;
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}

	atomic_fetch_add(&stats->sni_ok, 1);
	if (c->ssl_sni_conf_host->ssl->ctx != c->conf_listen->default_host->ssl->ctx) {
		// SSL_set_ssl_ctx(ssl, c->ssl_sni_conf_host->ssl.ctx);
	}

	return SSL_TLSEXT_ERR_OK;
}

static int h2d_ssl_ticket_callback(SSL *ssl, unsigned char *name,
		unsigned char *iv, EVP_CIPHER_CTX *ectx,
		HMAC_CTX *hctx, int enc)
{
	struct h2d_ssl_stats *stats = h2d_ssl_get_stats(ssl);

	SSL_CTX *ssl_ctx = SSL_get_SSL_CTX(ssl);
	struct h2d_ssl_ticket_secret *secret = SSL_CTX_get_ex_data(ssl_ctx,
			H2D_SSL_CTX_EX_TICKET_SECRET);

	const EVP_MD *digest = EVP_sha256();
	const EVP_CIPHER *cipher = EVP_aes_128_cbc();

	if (enc == 1) { /* encrypt session ticket */
		if (RAND_bytes(iv, EVP_CIPHER_iv_length(cipher)) != 1) {
			return -1;
		}
		if (EVP_EncryptInit_ex(ectx, cipher, NULL, secret->aes_key, iv) != 1) {
			return -1;
		}
		if (HMAC_Init_ex(hctx, secret->hmac_key, 16, digest, NULL) != 1) {
			return -1;
		}
		atomic_fetch_add(&stats->ticket_sign, 1);
		memcpy(name, secret->name, 16);
		return 1;

	} else {
		if (memcmp(name, secret->name, 16) != 0) {
			return 0;
		}
		if (HMAC_Init_ex(hctx, secret->hmac_key, 16, digest, NULL) != 1) {
			return -1;
		}
		if (EVP_DecryptInit_ex(ectx, cipher, NULL, secret->aes_key, iv) != 1) {
			return -1;
		}
		atomic_fetch_add(&stats->ticket_reuse, 1);
		return 1;
	}
}

static SSL_CTX *h2d_ssl_new_empty_server_ctx(void)
{
	SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());
	SSL_CTX_set_ecdh_auto(ctx, 1);
	SSL_CTX_set_alpn_select_cb(ctx, h2d_ssl_alpn_callback, NULL);
	SSL_CTX_set_tlsext_servername_callback(ctx, h2d_ssl_sni_callback);
	return ctx;
}

SSL_CTX *h2d_ssl_ctx_empty_server(void)
{
	static SSL_CTX *empty = NULL;
	if (empty == NULL) {
		empty = h2d_ssl_new_empty_server_ctx();
	}
	return empty;
}

SSL_CTX *h2d_ssl_ctx_new_client(void)
{
	SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
	SSL_CTX_set_ecdh_auto(ctx, 1);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); // TODO move this out as config
	return ctx;
}

void h2d_ssl_stream_set(loop_stream_t *s, SSL_CTX *ctx, bool is_server)
{
	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, loop_stream_fd(s));
	if (is_server) {
		SSL_set_accept_state(ssl);
		struct h2d_connection *c = loop_stream_get_app_data(s);
		SSL_set_ex_data(ssl, H2D_SSL_EX_DATA, c);
	} else {
		SSL_set_connect_state(ssl);
	}

	loop_stream_set_underlying(s, ssl);
}

int h2d_ssl_stream_handshake(loop_stream_t *s)
{
	SSL *ssl = loop_stream_get_underlying(s);
	if (ssl == NULL) { /* non-SSL */
		return H2D_OK;
	}
	int ret = SSL_do_handshake(ssl);
	if (ret == 1) { /* done */
		return H2D_OK;
	}
	if (ret == 0) { /* SSL closed */
		return H2D_ERROR;
	}

	/* handshake error */
	int sslerr = SSL_get_error(ssl, ret);
	if (sslerr == SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE) {
		return H2D_AGAIN;
	}
	return H2D_ERROR;
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
		if (sslerr == SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE) {
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

const char *h2d_ssl_stream_error_string(loop_stream_t *s)
{
	if (loop_stream_get_underlying(s) == NULL) {
		return "non-SSL";
	}
	return ERR_error_string(ERR_get_error(), NULL);
}

void h2d_ssl_init(void)
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}


/* configuration */

static const char *h2d_ssl_conf_post(void *data)
{
	struct h2d_ssl_conf *conf = data;

	if (conf->certificate == NULL || conf->private_key == NULL) {
		return "miss certificate or private_key";
	}

	conf->ctx = h2d_ssl_new_empty_server_ctx();

	SSL_CTX_set_cipher_list(conf->ctx, conf->ciphers);

	/* certificate and private_key */
	if (SSL_CTX_use_certificate_chain_file(conf->ctx, conf->certificate) != 1) {
		wuy_cflua_post_arg = conf->certificate;;
		return ERR_error_string(ERR_get_error(), NULL);
	}
	if (SSL_CTX_use_PrivateKey_file(conf->ctx, conf->private_key, SSL_FILETYPE_PEM) != 1) {
		wuy_cflua_post_arg = conf->private_key;
		return ERR_error_string(ERR_get_error(), NULL);
	}

	/* ticket secret */
#define H2D_SECRET_SIZE sizeof(struct h2d_ssl_ticket_secret)
	struct h2d_ssl_ticket_secret *secret = wuy_pool_alloc(wuy_cflua_pool, H2D_SECRET_SIZE + 1);
	if (conf->ticket_secret != NULL) {
		FILE *fp = fopen(conf->ticket_secret, "r");
		if (fp == NULL) {
			wuy_cflua_post_arg = conf->ticket_secret;
			return "fail in open ticket_secret file";
		}

		size_t len = fread(secret, 1, H2D_SECRET_SIZE + 1, fp);
		fclose(fp);
		if (len != H2D_SECRET_SIZE) {
			wuy_cflua_post_arg = conf->ticket_secret;
			return "invalid ticket_secret length";
		}
	} else {
		if (!RAND_bytes((unsigned char *)secret, H2D_SECRET_SIZE)) {
			printf("fail in generate random ticket_secret");
		}
	}
	SSL_CTX_set_tlsext_ticket_key_cb(conf->ctx, h2d_ssl_ticket_callback);
	SSL_CTX_set_ex_data(conf->ctx, H2D_SSL_CTX_EX_TICKET_SECRET, secret);

	SSL_CTX_set_timeout(conf->ctx, conf->session_timeout);

	/* others */
	conf->stats = wuy_shmpool_alloc(sizeof(struct h2d_ssl_stats));
	SSL_CTX_set_ex_data(conf->ctx, H2D_SSL_CTX_EX_STATS, conf->stats);

	return WUY_CFLUA_OK;
}

static void h2d_ssl_conf_free(void *data)
{
	struct h2d_ssl_conf *conf = data;

	if (conf->ctx != NULL) {
		SSL_CTX_free(conf->ctx);
	}
}

static struct wuy_cflua_command h2d_ssl_conf_commands[] = {
	{	.name = "certificate",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_ssl_conf, certificate),
	},
	{	.name = "private_key",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_ssl_conf, private_key),
	},
	{	.name = "ciphers",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_ssl_conf, ciphers),
		.default_value.s = "ECDHE-ECDSA-AES128-GCM-SHA256"
			":ECDHE-RSA-AES128-GCM-SHA256"
			":ECDHE-ECDSA-AES256-GCM-SHA384"
			":ECDHE-RSA-AES256-GCM-SHA384"
			":ECDHE-ECDSA-CHACHA20-POLY1305"
			":ECDHE-RSA-CHACHA20-POLY1305"
			":DHE-RSA-AES128-GCM-SHA256"
			":DHE-RSA-AES256-GCM-SHA384",
	},
	{	.name = "ticket_secret",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct h2d_ssl_conf, ticket_secret),
	},
	{	.name = "session_timeout",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_ssl_conf, session_timeout),
		.default_value.n = 86400,
		.limits.n = WUY_CFLUA_LIMITS_NON_NEGATIVE,
	},
	{ NULL }
};

struct wuy_cflua_table h2d_ssl_conf_table = {
	.commands = h2d_ssl_conf_commands,
	.may_omit = true,
	.size = sizeof(struct h2d_ssl_conf),
	.post = h2d_ssl_conf_post,
	.free = h2d_ssl_conf_free,
};

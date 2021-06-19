#ifndef H2D_SSL_H
#define H2D_SSL_H

#include <openssl/ossl_typ.h>

struct phl_ssl_stats {
	atomic_long	total;
	atomic_long	alpn_h2;
	atomic_long	alpn_miss;
	atomic_long	alpn_fail;
	atomic_long	sni_ok;
	atomic_long	sni_miss;
	atomic_long	ticket_sign;
	atomic_long	ticket_reuse;
};

struct phl_ssl_conf {
	const char	*certificate;
	const char	*private_key;
	const char	*ticket_secret;
	const char	*ciphers;
	int		session_timeout;

	SSL_CTX		*ctx;

	struct phl_ssl_stats	*stats;
};

struct phl_ssl_client_conf {
	bool		verify;
	SSL_CTX		*ctx;
};

extern struct wuy_cflua_table phl_ssl_conf_table;
extern struct wuy_cflua_table phl_ssl_client_conf_table;

SSL_CTX *phl_ssl_ctx_empty_server(void);
SSL_CTX *phl_ssl_ctx_new_client(void);

void phl_ssl_stream_set(loop_stream_t *s, SSL_CTX *ctx, bool is_server);
int phl_ssl_stream_handshake(loop_stream_t *s);

int phl_ssl_stream_underlying_read(void *underlying, void *buffer, int buf_len);
int phl_ssl_stream_underlying_write(void *underlying, const void *data, int len);
void phl_ssl_stream_underlying_close(void *underlying);

const char *phl_ssl_stream_error_string(loop_stream_t *s);

void phl_ssl_init(void);

#define H2D_SSL_LOOP_STREAM_UNDERLYINGS \
	.underlying_read = phl_ssl_stream_underlying_read, \
	.underlying_write = phl_ssl_stream_underlying_write, \
	.underlying_close = phl_ssl_stream_underlying_close \

#endif

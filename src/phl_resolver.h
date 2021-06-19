#ifndef PHL_RESOLVER_H
#define PHL_RESOLVER_H

struct phl_resolver_query {
	int	expire_after;
	char	hostname[4096];
};

void phl_resolver_init(void);
void phl_resolver_init_if_fork(void);

int phl_resolver_connect(void);

uint8_t *phl_resolver_hostname(const char *hostname, int *plen);

extern struct wuy_cflua_table phl_conf_runtime_resolver_table;

#endif

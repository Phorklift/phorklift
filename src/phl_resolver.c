#include "phl_main.h"

#include <pthread.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>

static char phl_resolver_address[100];
static int phl_resolver_fd = 0;

static int phl_resolver_client_id = 0;

static wuy_dict_t *phl_resolver_result_cache;
static wuy_heap_t *phl_resolver_result_expire;

struct phl_resolver_result {
	const char		*hostname;
	uint8_t			*buffer;
	int			length;
	time_t			expire_at;
	wuy_dict_node_t		dict_node;
	wuy_heap_node_t		heap_node;
};

static int phl_resolver_addrcmp(const void *a, const void *b)
{
	struct sockaddr * const *sa = a;
	struct sockaddr * const *sb = b;
	return wuy_sockaddr_addrcmp(*sa, *sb);
}

static void phl_resolver_expire(void)
{
	time_t now = time(NULL);
	while (1) {
		struct phl_resolver_result *result = wuy_heap_min(phl_resolver_result_expire);
		if (result == NULL) {
			break;
		}
		if (result->expire_at > now) {
			break;
		}
		wuy_dict_delete(phl_resolver_result_cache, result);
		wuy_heap_delete(phl_resolver_result_expire, result);
		free((char *)result->hostname);
		free(result->buffer);
		free(result);
	}
}

/* resolve hostname and sort the results */
uint8_t *phl_resolver_hostname(const char *hostname, int *plen)
{
	struct addrinfo hints;
	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = phl_conf_runtime->resolver.ai_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG;

	time_t before = time(NULL);

	struct addrinfo *results;
	int rr = getaddrinfo(hostname, NULL, &hints, &results); /* blocks here! */
	if (rr != 0) {
		phl_conf_log(PHL_LOG_ERROR, "getaddrinfo() fail: hostname=%s ret=%d:%s",
				hostname, rr, strerror(errno));
		return NULL;
	}

	time_t after = time(NULL);
	if (after - before > 1) {
		phl_conf_log(PHL_LOG_INFO, "getaddrinfo() lasts long: hostname=%s, %lds",
				hostname, after - before);
	}

	/* sort */
	*plen = 0;
	int num = 0;
	struct sockaddr *addresses[1000];
	for (struct addrinfo *rp = results; rp != NULL; rp = rp->ai_next) {
		addresses[num++] = rp->ai_addr;
		*plen += rp->ai_addrlen;
		if (num == 1000) {
			break;
		}
	}
	qsort(addresses, num, sizeof(struct sockaddr *), phl_resolver_addrcmp);

	/* store */
	uint8_t *buffer = malloc(*plen);
	uint8_t *p = buffer;
	for (int i = 0; i < num; i++) {
		size_t size = wuy_sockaddr_size(addresses[i]);
		memcpy(p, addresses[i], size);
		p += size;
	}

	freeaddrinfo(results);

	return buffer;
}

static struct phl_resolver_result *phl_resolver_process(struct phl_resolver_query *q)
{
	static struct phl_resolver_result error = { .buffer = (uint8_t *)"ERROR", .length = 6 };

	/* search cache first */
	struct phl_resolver_result *result = wuy_dict_get(phl_resolver_result_cache, q->hostname);
	if (result != NULL) { /* hit */
		return result;
	}

	/* resolve */
	int length;
	uint8_t *buffer = phl_resolver_hostname(q->hostname, &length);
	if (buffer == NULL) {
		return &error;
	}

	/* new result */
	result = malloc(sizeof(struct phl_resolver_result));
	result->length = length;
	result->buffer = buffer;
	result->hostname = strdup(q->hostname);
	result->expire_at = time(NULL) + q->expire_after;
	wuy_heap_push(phl_resolver_result_expire, result);
	wuy_dict_add(phl_resolver_result_cache, result);
	return result;
}

static void *phl_resolver_routine(void *dummy)
{
	while (1) {
		struct phl_resolver_query query;
		struct sockaddr_un client;
		socklen_t addr_len = sizeof(struct sockaddr_un);

		int query_len = recvfrom(phl_resolver_fd, &query, sizeof(query)-1, 0,
				(struct sockaddr *)&client, &addr_len);
		if (query_len <= 0) {
			phl_conf_log(PHL_LOG_ERROR, "recvfrom() error %s", strerror(errno));
			continue;
		}

		query.hostname[query_len - offsetof(struct phl_resolver_query, hostname)] = '\0';

		struct phl_resolver_result *result = phl_resolver_process(&query);

		sendto(phl_resolver_fd, result->buffer, result->length, 0,
				(struct sockaddr *)&client, addr_len);

		phl_resolver_expire();
	}
	return NULL;
}

static void phl_resolver_at_exit(void)
{
	if (!phl_in_worker) {
		unlink(phl_resolver_address);
		return;
	}

	for (int i = 0; i < phl_resolver_client_id; i++) {
		char path[100];
		sprintf(path, "/tmp/phl_resolver_client_%d_%d", getpid(), i);
		unlink(path);
	}
}

void phl_resolver_init_if_fork(void)
{
	pthread_t tid;
	pthread_create(&tid, 0, phl_resolver_routine, NULL);
}

/* Create a thread as resolver.
 * This is called in master process. */
void phl_resolver_init(void)
{
	sprintf(phl_resolver_address, "/tmp/phl_resolver_%d", getpid());

	phl_resolver_result_cache = wuy_dict_new_type(WUY_DICT_KEY_STRING,
			offsetof(struct phl_resolver_result, hostname),
			offsetof(struct phl_resolver_result, dict_node));

	phl_resolver_result_expire = wuy_heap_new_type(WUY_HEAP_KEY_INT64,
			offsetof(struct phl_resolver_result, expire_at), false,
			offsetof(struct phl_resolver_result, heap_node));

	atexit(phl_resolver_at_exit);

	phl_resolver_fd = socket(AF_UNIX, SOCK_DGRAM, 0);

	struct sockaddr_un un;
	un.sun_family = AF_UNIX;
	strcpy(un.sun_path, phl_resolver_address);
	unlink(phl_resolver_address);
	if (bind(phl_resolver_fd, (struct sockaddr *)&un, sizeof(un)) < 0) {
		perror("bind resolver address");
		exit(PHL_EXIT_RESOLVER);
	}

	phl_resolver_init_if_fork();
}

/* Create a client socket, connect it to the resolver server, and return its fd.
 * Connect() so we can use it as a stream.
 * This is called in worker process. */
int phl_resolver_connect(void)
{
	char path[100];
	sprintf(path, "/tmp/phl_resolver_client_%d_%d", getpid(), phl_resolver_client_id++);

	int fd = socket(AF_UNIX, SOCK_DGRAM, 0);

	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);

	struct sockaddr_un un;
	un.sun_family = AF_UNIX;
	strcpy(un.sun_path, path);
	unlink(path);
	if (bind(fd, (struct sockaddr *)&un, sizeof(un)) < 0) {
		return -1;
	}

	strcpy(un.sun_path, phl_resolver_address);
	if (connect(fd, (struct sockaddr *)&un, sizeof(un)) < 0) {
		return -1;
	}

	return fd;
}

static const char *phl_conf_runtime_resolver_post(void *data)
{
	struct phl_conf_runtime_resolver *conf = data;
	const char *str = conf->ai_family_str;

	if (strcmp(str, "both46") == 0) {
		conf->ai_family = AF_UNSPEC;
	} else if (strcmp(str, "ipv4") == 0) {
		conf->ai_family = AF_INET;
	} else if (strcmp(str, "ipv6") == 0) {
		conf->ai_family = AF_INET6;
	} else {
		return "only accept: 'ipv4', 'ipv6' and 'both46' for IPv4, IPv6 and both.";
	}

	return WUY_CFLUA_OK;
}

static struct wuy_cflua_command phl_conf_runtime_resovler_commands[] = {
	{	.name = "ai_family",
		.type = WUY_CFLUA_TYPE_STRING,
		.offset = offsetof(struct phl_conf_runtime_resolver, ai_family_str),
		.default_value.s = "both46",
	},
	{ NULL },
};
struct wuy_cflua_table phl_conf_runtime_resolver_table = {
	.commands = phl_conf_runtime_resovler_commands,
	.post = phl_conf_runtime_resolver_post,
};

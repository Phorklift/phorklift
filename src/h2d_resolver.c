#include "h2d_main.h"

#include <pthread.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>

static char h2d_resolver_address[100];

static wuy_dict_t *h2d_resolver_result_cache;

struct h2d_resolver_result {
	const char		*hostname;
	uint8_t			*buffer;
	int			length;
	time_t			expire_at;
	wuy_dict_node_t		dict_node;
};

static int h2d_resolver_addrcmp(const void *a, const void *b)
{
	struct sockaddr * const *sa = a;
	struct sockaddr * const *sb = b;
	return wuy_sockaddr_addrcmp(*sa, *sb);
}

/* resolve hostname and sort the results */
uint8_t *h2d_resolver_hostname(const char *hostname, int *plen)
{
	struct addrinfo hints;
	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG;

	time_t before = time(NULL);

	struct addrinfo *results;
	int rr = getaddrinfo(hostname, NULL, &hints, &results); /* blocks here! */
	if (rr != 0) {
		return NULL;
	}

	time_t after = time(NULL);
	if (after - before > 1) {
		printf("getaddrinfo %ld\n", after - before);
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
	qsort(addresses, num, sizeof(struct sockaddr *), h2d_resolver_addrcmp);

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

static struct h2d_resolver_result *h2d_resolver_process(struct h2d_resolver_query *q)
{
	static struct h2d_resolver_result error = { .buffer = (uint8_t *)"ERROR", .length = 6 };

	/* search cache first */
	struct h2d_resolver_result *result = wuy_dict_get(h2d_resolver_result_cache, q->hostname);

	if (result != NULL) { /* hit */
		if (result->expire_at >= time(NULL)) {
			return result;
		}
		free(result->buffer); /* but expired */
	} else {
		result = malloc(sizeof(struct h2d_resolver_result));
		result->hostname = strdup(q->hostname);
		wuy_dict_add(h2d_resolver_result_cache, result);
	}

	/* resolve */
	result->buffer = h2d_resolver_hostname(q->hostname, &result->length);
	if (result->buffer == NULL) {
		return &error;
	}

	result->expire_at = time(NULL) + q->expire_after;
	return result;
}

static void *h2d_resolver_routine(void *dummy)
{
	int fd = socket(AF_UNIX, SOCK_DGRAM, 0);

	struct sockaddr_un un;
	un.sun_family = AF_UNIX;
	strcpy(un.sun_path, h2d_resolver_address);
	unlink(h2d_resolver_address);
	if (bind(fd, (struct sockaddr *)&un, sizeof(un)) < 0) {
		perror("bind resolver address");
		exit(H2D_EXIT_RESOLVER);
	}

	while (1) {
		struct h2d_resolver_query query;
		struct sockaddr_un client;
		socklen_t addr_len = sizeof(struct sockaddr_un);

		int query_len = recvfrom(fd, &query, sizeof(query)-1, 0,
				(struct sockaddr *)&client, &addr_len);
		if (query_len <= 0) {
			perror("recvfrom() error");
			continue;
		}

		query.hostname[query_len - offsetof(struct h2d_resolver_query, hostname)] = '\0';

		struct h2d_resolver_result *result = h2d_resolver_process(&query);

		sendto(fd, result->buffer, result->length, 0, (struct sockaddr *)&client, addr_len);
	}

	unlink(h2d_resolver_address);
	close(fd);
	return NULL;
}

/* Create a thread as resolver.
 * This is called in master process. */
void h2d_resolver_init(void)
{
	sprintf(h2d_resolver_address, "/tmp/h2d_resolver_%d", getpid());

	h2d_resolver_result_cache = wuy_dict_new_type(WUY_DICT_KEY_STRING,
			offsetof(struct h2d_resolver_result, hostname),
			offsetof(struct h2d_resolver_result, dict_node));

	pthread_t tid;
	pthread_create(&tid, 0, h2d_resolver_routine, NULL);
}

/* Create a client socket, connect it to the resolver server, and return its fd.
 * Connect() so we can use it as a stream.
 * This is called in worker process. */
int h2d_resolver_connect(void)
{
	static int id = 1;
	char path[200];
	snprintf(path, sizeof(path), "/tmp/h2d_resolver_client_%d_%d", getpid(), id++);
	// TODO remove path after process quit

	int fd = socket(AF_UNIX, SOCK_DGRAM, 0);

	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);

	struct sockaddr_un un;
	un.sun_family = AF_UNIX;
	strcpy(un.sun_path, path);
	unlink(path);
	if (bind(fd, (struct sockaddr *)&un, sizeof(un)) < 0) {
		return -1;
	}

	strcpy(un.sun_path, h2d_resolver_address);
	if (connect(fd, (struct sockaddr *)&un, sizeof(un)) < 0) {
		return -1;
	}

	return fd;
}

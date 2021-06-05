#include "h2d_main.h"
#include <pthread.h>

#define _log(level, fmt, ...) h2d_conf_log_at(upstream->log, level, \
		"upstream: %s " fmt, upstream->name, ##__VA_ARGS__)


static void h2d_upstream_address_defer_free(struct h2d_upstream_conf *upstream)
{
	struct h2d_upstream_address *address, *safe;
	wuy_list_iter_safe_type(&upstream->deleted_address_defer, address, safe, hostname_node) {
		if (!wuy_list_empty(&address->active_head) || !wuy_list_empty(&address->idle_head)) {
			continue;
		}
		h2d_upstream_healthcheck_stop(address);
		atomic_fetch_sub(&address->stats->refs, 1);
		wuy_list_delete(&address->hostname_node);
		free((void *)address->name);
		free(address);
	}
}

static void h2d_upstream_address_delete(struct h2d_upstream_address *address)
{
	struct h2d_upstream_conf *upstream = address->upstream;
	_log(H2D_LOG_INFO, "delete address %s", address->name);

	wuy_list_delete(&address->hostname_node);
	wuy_list_delete(&address->upstream_node);
	wuy_list_append(&upstream->deleted_address_defer, &address->hostname_node);
}

static struct h2d_upstream_address_stats *h2d_upstream_alloc_stats(
		struct h2d_upstream_conf *upstream, const char *name)
{
	uint64_t key = wuy_vhash64(name, strlen(name));

	struct h2d_upstream_address_stats *first_idle = NULL;

	pthread_mutex_lock(upstream->address_stats_lock);

	for (int i = 0; i < upstream->resolved_addresses_max * 2; i++) {
		struct h2d_upstream_address_stats *stats = &upstream->address_stats_start[i];
		if (stats->refs == 0) {
			if (first_idle == NULL) {
				first_idle = stats;
			}
			if (stats->key == 0) { /* has not been touched */
				break;
			}
		} else {
			if (stats->key == key) {
				atomic_fetch_add(&stats->refs, 1);
				pthread_mutex_unlock(upstream->address_stats_lock);
				return stats;
			}
		}
	}
	if (first_idle != NULL) {
		bzero(first_idle, sizeof(struct h2d_upstream_address_stats));
		first_idle->key = key;
		first_idle->create_time = time(NULL);
		atomic_store(&first_idle->refs, h2d_in_worker ? 1 : h2d_conf_runtime->worker.num);
	} else {
		static struct h2d_upstream_address_stats fake_stats;
		first_idle = &fake_stats;
		_log(H2D_LOG_ERROR, "no address stats for %s", name);
	}

	pthread_mutex_unlock(upstream->address_stats_lock);
	return first_idle;
}

static void h2d_upstream_address_add(struct h2d_upstream_conf *upstream,
		struct h2d_upstream_hostname *hostname, struct sockaddr *sockaddr,
		struct h2d_upstream_address *before)
{
	struct h2d_upstream_address *address = calloc(1, sizeof(struct h2d_upstream_address));

	switch (sockaddr->sa_family) {
	case AF_INET:
		address->sockaddr.sin = *((struct sockaddr_in *)sockaddr);
		if (hostname->port != 0) {
			address->sockaddr.sin.sin_port = htons(hostname->port);
		}
		break;

	case AF_INET6:
		address->sockaddr.sin6 = *((struct sockaddr_in6 *)sockaddr);
		if (hostname->port != 0) {
			address->sockaddr.sin6.sin6_port = htons(hostname->port);
		}
		break;

	case AF_UNIX:
		address->sockaddr.sun = *((struct sockaddr_un *)sockaddr);
		break;

	default:
		abort();
	}

	char buf[128];
	wuy_sockaddr_dumps(sockaddr, buf, sizeof(buf));
	address->name = strdup(buf);
	_log(H2D_LOG_INFO, "new address %s", address->name);

	wuy_list_init(&address->idle_head);
	wuy_list_init(&address->active_head);
	address->upstream = upstream;
	address->weight = hostname->weight;

	if (hostname->need_resolved) {
		address->stats = h2d_upstream_alloc_stats(upstream, address->name);
	} else {
		address->stats = wuy_shmpool_alloc(sizeof(struct h2d_upstream_address_stats));
		address->stats->create_time = time(NULL);
	}

	if (upstream->healthcheck.interval != 0) {
		h2d_upstream_healthcheck_start(address);
	}

	if (before != NULL) {
		wuy_list_add_before(&before->upstream_node, &address->upstream_node);
		wuy_list_add_before(&before->hostname_node, &address->hostname_node);
	} else {
		wuy_list_append(&upstream->address_head, &address->upstream_node);
		wuy_list_append(&hostname->address_head, &address->hostname_node);
	}
}

static void h2d_upstream_resolve_hostname(struct h2d_upstream_conf *upstream)
{
	/* try to pick next hostname */
	while (upstream->resolve_index < upstream->hostname_num) {
		struct h2d_upstream_hostname *hostname = &upstream->hostnames[upstream->resolve_index++];
		if (!hostname->need_resolved) {
			continue;
		}

		/* picked. send resolve query */
		struct h2d_resolver_query query;
		query.expire_after = upstream->resolve_interval;
		memcpy(query.hostname, hostname->name, hostname->host_len);
		loop_stream_write(upstream->resolve_stream, &query,
				sizeof(query.expire_after) + hostname->host_len);
		return;
	}

	/* no picked. finish resolve all hostnames */
	upstream->resolve_index = 0;
	if (!upstream->resolve_updated) {
		return;
	}

	/* clear deleted addresses, just before loadbalance->update() */
	upstream->address_num = 0;
	struct h2d_upstream_address *address, *safe;
	wuy_list_iter_safe_type(&upstream->address_head, address, safe, upstream_node) {
		if (address->resolve_deleted) {
			h2d_upstream_address_delete(address);
		} else {
			upstream->address_num++;
		}
	}

	if (upstream->address_num == 0) {
		_log(H2D_LOG_ERROR, "!!! no address. no update\n");
		return;
	}

	upstream->loadbalance->update(upstream);
	upstream->resolve_updated = false;

	h2d_request_active_list(&upstream->wait_head, "dynamic upstream resolved");
}

static int h2d_upstream_resolve_on_read(loop_stream_t *s, void *data, int len)
{
	struct h2d_upstream_conf *upstream = loop_stream_get_app_data(s);
	struct h2d_upstream_hostname *hostname = &upstream->hostnames[upstream->resolve_index-1];

	if (memcmp(data, "ERROR", 5) == 0) {
		_log(H2D_LOG_ERROR, "resolve error");
		goto next;
	}

	/* diff */
	uint8_t *p = data;
	uint8_t *end = p + len;
	wuy_list_node_t *node = wuy_list_first(&hostname->address_head);
	while (p < end && node != NULL) {
		struct h2d_upstream_address *address = wuy_containerof(node,
				struct h2d_upstream_address, hostname_node);

		struct sockaddr *newaddr = (struct sockaddr *)p;

		/* compare in the same way with h2d_resolver_addrcmp() */
		int cmp = wuy_sockaddr_addrcmp(newaddr, &address->sockaddr.s);
		if (cmp == 0) {
			p += wuy_sockaddr_size(newaddr);
			node = wuy_list_next(&hostname->address_head, node);
			continue;
		}

		if (cmp < 0) { /* new address */
			h2d_upstream_address_add(upstream, hostname, newaddr, address);
			p += wuy_sockaddr_size(newaddr);

		} else {
			/* delete address.
			 * We can not free the address now because it is used
			 * by loadbalance. We just mark it here and free it
			 * just before loadbalance->update(). */
			address->resolve_deleted = true;
			node = wuy_list_next(&hostname->address_head, node);
		}

		upstream->resolve_updated = true;
	}
	while (node != NULL) {
		struct h2d_upstream_address *address = wuy_containerof(node,
				struct h2d_upstream_address, hostname_node);
		node = wuy_list_next(&hostname->address_head, node);
		address->resolve_deleted = true;
		upstream->resolve_updated = true;
	}
	while (p < end) {
		struct sockaddr *newaddr = (struct sockaddr *)p;
		h2d_upstream_address_add(upstream, hostname, newaddr, NULL);
		p += wuy_sockaddr_size(newaddr);
		upstream->resolve_updated = true;
	}

	/* resolve next hostname */
next:
	h2d_upstream_resolve_hostname(upstream);

	return len;
}
static loop_stream_ops_t h2d_upstream_resolve_ops = {
	.on_read = h2d_upstream_resolve_on_read,
};

static int64_t h2d_upstream_resolve_timer_handler(int64_t at, void *data)
{
	struct h2d_upstream_conf *upstream = data;

	if (upstream->resolve_stream == NULL) {
		/* initialize the loop_stream.
		 * We can not initialize this at h2d_upstream_conf_post() because
		 * it is called in master process while we need the worker. */
		int fd = h2d_resolver_connect();
		upstream->resolve_stream = loop_stream_new(h2d_loop, fd, &h2d_upstream_resolve_ops, false);
		loop_stream_set_app_data(upstream->resolve_stream, upstream);
	}

	if (upstream->resolve_index != 0) { /* in processing already */
		return upstream->resolve_interval * 1000;
	}

	h2d_upstream_address_defer_free(upstream);

	h2d_upstream_resolve_hostname(upstream);

	return upstream->resolve_interval * 1000;
}

static void h2d_upstream_resolve_start_after(struct h2d_upstream_conf *conf, bool immediately)
{
	conf->resolve_timer = loop_timer_new(h2d_loop, h2d_upstream_resolve_timer_handler, conf);

	int64_t after = immediately ? 0 : random() % (conf->resolve_interval * 1000);
	loop_timer_set_after(conf->resolve_timer, after);
}

const char *h2d_upstream_conf_resolve_init(struct h2d_upstream_conf *conf)
{
	/* pre-alloc lock and shared-memory for resolved address stats */
	conf->address_stats_lock = wuy_shmpool_alloc(sizeof(pthread_mutex_t));
	pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_setpshared(&attr, 1);
	pthread_mutex_init(conf->address_stats_lock, &attr);
	pthread_mutexattr_destroy(&attr);

	conf->address_stats_start = wuy_shmpool_alloc(sizeof(struct h2d_upstream_address_stats)
			* conf->resolved_addresses_max * 2);

	conf->hostnames = wuy_pool_alloc(wuy_cflua_pool,
			conf->hostname_num * sizeof(struct h2d_upstream_hostname));

	/* resolve */
	bool need_resolved = false;
	for (int i = 0; i < conf->hostname_num; i++) {
		struct h2d_upstream_hostname *hostname = &conf->hostnames[i];

		hostname->name = conf->hostnames_str[i];

		wuy_list_init(&hostname->address_head);

		hostname->host_len = strlen(hostname->name);
		if (hostname->host_len > 4096) {
			return "too long hostname";
		}

		/* parse weight, marked by # */
		const char *pweight = strchr(hostname->name, '#');
		if (pweight != NULL) {
			hostname->host_len = pweight - hostname->name;
			hostname->weight = atof(pweight + 1);
			if (hostname->weight == 0) {
				return "invalid weight";
			}
		} else {
			hostname->weight = 1.0;
		}

		/* it's static address, no need resolve */
		struct sockaddr_storage sockaddr;
		if (wuy_sockaddr_loads(hostname->name, &sockaddr, conf->default_port)) {
			hostname->need_resolved = false;
			hostname->port = 0;
			h2d_upstream_address_add(conf, hostname, (struct sockaddr *)&sockaddr, NULL);
			conf->address_num++;
			continue;
		}

		/* it's hostname, resolve it */
		need_resolved = true;
		hostname->need_resolved = true;
		hostname->port = conf->default_port;

		/* parse the port */
		const char *pport = strchr(hostname->name, ':');
		if (pport != NULL) {
			hostname->host_len = pport - hostname->name;
			hostname->port = atoi(pport + 1);
			if (hostname->port == 0) {
				return "invalid port";
			}
		}

		if (h2d_in_worker) {
			/* sub-upstream is created during h2tpd running, so we
			 * can not call h2d_resolver_hostname() which is blocking. */
			continue;
		}

		/* resolve the hostname */
		int length;
		char tmpname[hostname->host_len + 1];
		memcpy(tmpname, hostname->name, hostname->host_len);
		tmpname[hostname->host_len] = '\0';
		uint8_t *buffer = h2d_resolver_hostname(tmpname, &length);
		if (buffer == NULL) {
			return "resolve fail";
		}

		uint8_t *p = buffer;
		while (p < buffer + length) {
			struct sockaddr *sa = (struct sockaddr *)p;
			h2d_upstream_address_add(conf, hostname, sa, NULL);
			p += wuy_sockaddr_size(sa);
			conf->address_num++;
		}

		free(buffer);
	}

	if (h2d_in_worker) { /* dynamic sub upstreams have different checking rule */
		goto sub_check;
	}

	if (conf->address_num == 0) {
		return "no address for upstream";
	}

	/* resolve stream */
	if (need_resolved && conf->resolve_interval > 0) {
		h2d_upstream_resolve_start_after(conf, false);
	}

	return WUY_CFLUA_OK;

sub_check:
	if (need_resolved) {
		if (conf->resolve_interval == 0) {
			return "resolve_interval can not be 0 for dynamic upstream with hostnames";
		}
		h2d_upstream_resolve_start_after(conf, true);
	} else {
		if (conf->address_num == 0) {
			return "no address for dynamic upstream";
		}
	}

	return WUY_CFLUA_OK;
}

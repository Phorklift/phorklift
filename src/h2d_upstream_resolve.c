#include "h2d_main.h"

static void h2d_upstream_address_defer_free(struct h2d_upstream_conf *upstream)
{
	struct h2d_upstream_address *address, *safe;
	wuy_list_iter_safe_type(&upstream->deleted_address_defer, address, safe, hostname_node) {
		if (!wuy_list_empty(&address->active_head) || !wuy_list_empty(&address->idle_head)
				|| wuy_list_node_linked(&address->down_node)) {
			continue;
		}
		wuy_list_delete(&address->hostname_node);
		free(address);
	}
}

static void h2d_upstream_address_delete(struct h2d_upstream_address *address)
{
	wuy_list_delete(&address->hostname_node);
	wuy_list_delete(&address->upstream_node);
	wuy_list_append(&address->upstream->deleted_address_defer, &address->hostname_node);
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
		printf("sa_family: %d\n", sockaddr->sa_family);
		abort();
	}

	wuy_list_init(&address->idle_head);
	wuy_list_init(&address->active_head);
	address->upstream = upstream;
	address->weight = hostname->weight;
	address->stats.create_time = time(NULL);

	char buf[128];
	wuy_sockaddr_ntop(sockaddr, buf, sizeof(buf));
	address->name = strdup(buf);

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
	/* pick next hostname */
	char *name = NULL;
	while (1) {
		struct h2d_upstream_hostname *hostname = &upstream->hostnames[upstream->resolve_index++];
		if (hostname->name == NULL) {
			break;
		}
		if (hostname->need_resolved) {
			name = hostname->name;
			break;
		}
	}

	/* finish resolve all hostnames */
	if (name == NULL) {
		upstream->resolve_last = time(NULL);
		upstream->resolve_index = 0;
		if (!upstream->resolve_updated) {
			return;
		}

		/* clear deleted addresses, just before loadbalance->update() */
		upstream->address_num = 0;
		struct h2d_upstream_address *address, *safe;
		wuy_list_iter_safe_type(&upstream->address_head, address, safe, upstream_node) {
			if (address->deleted) {
				h2d_upstream_address_delete(address);
			} else {
				upstream->address_num++;
			}
		}

		if (upstream->address_num == 0) {
			printf("!!! no address. no update\n");
			return;
		}

		upstream->loadbalance->update(upstream);
		upstream->resolve_updated = false;

		wuy_list_t *wait_head = &upstream->dynamic.wait_head;
		if (wuy_list_inited(wait_head)) {
			struct h2d_request *r;
			while (wuy_list_pop_type(wait_head, r, list_node)) {
				h2d_request_active(r, "dynamic upstream resolved");
			}
		}
		return;
	}

	/* send resolve query */
	struct h2d_resolver_query query;
	int name_len = strlen(name);
	assert(name_len < sizeof(query.hostname));
	memcpy(query.hostname, name, name_len);
	query.expire_after = upstream->resolve_interval;
	loop_stream_write(upstream->resolve_stream, &query,
			sizeof(query.expire_after) + name_len);
}

static int h2d_upstream_resolve_on_read(loop_stream_t *s, void *data, int len)
{
	if (memcmp(data, "ERROR", 5) == 0) {
		return len; /* stop or goto resolve next? */
	}

	struct h2d_upstream_conf *upstream = loop_stream_get_app_data(s);
	struct h2d_upstream_hostname *hostname = &upstream->hostnames[upstream->resolve_index-1];

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
			address->deleted = true;
			node = wuy_list_next(&hostname->address_head, node);
		}

		upstream->resolve_updated = true;
	}
	while (node != NULL) {
		struct h2d_upstream_address *address = wuy_containerof(node,
				struct h2d_upstream_address, hostname_node);
		node = wuy_list_next(&hostname->address_head, node);
		address->deleted = true;
		upstream->resolve_updated = true;
	}
	while (p < end) {
		struct sockaddr *newaddr = (struct sockaddr *)p;
		h2d_upstream_address_add(upstream, hostname, newaddr, NULL);
		p += wuy_sockaddr_size(newaddr);
		upstream->resolve_updated = true;
	}

	/* resolve next hostname */
	h2d_upstream_resolve_hostname(upstream);

	return len;
}
static loop_stream_ops_t h2d_upstream_resolve_ops = {
	.on_read = h2d_upstream_resolve_on_read,
};

void h2d_upstream_resolve(struct h2d_upstream_conf *upstream)
{
	if (upstream->resolve_last == 0) {
		/* all static addresses, no need resolve */
		return;
	}

	if (upstream->resolve_stream == NULL) {
		/* initialize the loop_stream.
		 * We can not initialize this at h2d_upstream_conf_post() because
		 * it is called in master process while we need the worker. */
		int fd = h2d_resolver_connect();
		upstream->resolve_stream = loop_stream_new(h2d_loop, fd, &h2d_upstream_resolve_ops, false);
		loop_stream_set_app_data(upstream->resolve_stream, upstream);
	}

	if (time(NULL) - upstream->resolve_last < upstream->resolve_interval) {
		return;
	}
	if (upstream->resolve_index != 0) { /* in processing already */
		return;
	}

	h2d_upstream_address_defer_free(upstream);

	/* begin the resolve */
	h2d_upstream_resolve_hostname(upstream);
}

bool h2d_upstream_conf_resolve_init(struct h2d_upstream_conf *conf)
{
	bool is_sub = wuy_list_inited(&conf->dynamic.wait_head);

	bool need_resolved = false;
	for (int i = 0; conf->hostnames[i].name != NULL; i++) {
		struct h2d_upstream_hostname *hostname = &conf->hostnames[i];

		wuy_list_init(&hostname->address_head);

		/* parse weight, marked by # */
		char *wstr = strchr(hostname->name, '#');
		if (wstr != NULL) {
			*wstr++ = '\0';
			hostname->weight = atof(wstr);
			if (hostname->weight == 0) {
				printf("invalid weight of %s %s", hostname->name, wstr);
				return false;
			}
		}

		/* it's static address, no need resolve */
		struct sockaddr sockaddr;
		if (wuy_sockaddr_pton(hostname->name, &sockaddr, conf->default_port)) {
			hostname->need_resolved = false;
			hostname->port = 0;
			h2d_upstream_address_add(conf, hostname, &sockaddr, NULL);
			conf->address_num++;
			continue;
		}

		/* it's hostname, resolve it */
		need_resolved = true;
		hostname->need_resolved = true;
		hostname->port = conf->default_port;

		/* parse the port */
		char *pport = strchr(hostname->name, ':');
		if (pport != NULL) {
			hostname->port = atoi(pport + 1);
			if (hostname->port == 0) {
				printf("invalid port %s\n", hostname->name);
				return false;
			}
			*pport = '\0';
		}

		if (is_sub) {
			/* sub-upstream is created during h2tpd running, so we
			 * can not call h2d_resolver_hostname() which is blocking. */
			continue;
		}

		/* resolve the hostname */
		int length;
		uint8_t *buffer = h2d_resolver_hostname(hostname->name, &length);
		if (buffer == NULL) {
			printf("resolve fail %s\n", hostname->name);
			return false;
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

	if (is_sub) {
		goto sub_check;
	}

	if (conf->address_num == 0) {
		printf("no address for upstream\n");
		return false;
	}

	/* resolve stream */
	if (need_resolved && conf->resolve_interval > 0) {
		conf->resolve_last = time(NULL);
	}

	return true;

sub_check:
	if (need_resolved) {
		if (conf->resolve_interval == 0) {
			printf("resolve_interval can not be 0 for dynamic upstream with hostnames\n");
			return false;
		}
		conf->resolve_last = 1;
		h2d_upstream_resolve(conf);
	} else {
		if (conf->address_num == 0) {
			printf("no address for dynamic upstream\n");
			return false;
		}
	}

	return true;
}

#include "h2d_main.h"

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

	/* begin the resolve */
	h2d_upstream_resolve_hostname(upstream);
}

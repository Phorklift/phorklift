#include "h2d_main.h"

#include "libwuya/wuy_murmurhash.h"

struct h2d_upstream_hash_conf {
	/* configrations */
	wuy_cflua_function_t	key;
	int			address_vnodes;

	/* run time */
	int				vnode_num;
	struct h2d_upstream_hash_vnode	*vnodes;
};

struct h2d_upstream_hash_vnode {
	uint64_t			hash;
	struct h2d_upstream_address	*address;
};

struct h2d_upstream_loadbalance h2d_upstream_hash;

static uint64_t h2d_upstream_hash_data(const void *data, int len)
{
	union {
		unsigned char out[16];
		uint64_t ret[2];
	} u;

	wuy_murmurhash(data, len, u.out);
	return u.ret[0] ^ u.ret[1];
}

static int h2d_upstream_hash_vnode_cmp(const void *a, const void *b)
{
	const struct h2d_upstream_hash_vnode *va = a;
	const struct h2d_upstream_hash_vnode *vb = b;
	if (va->hash == vb->hash) {
		return 0;
	}
	return (va->hash > vb->hash) ? 1 : -1;
}

static int h2d_upstream_hash_address_vnode_num(struct h2d_upstream_address *address)
{
	struct h2d_upstream_hash_conf *conf = address->upstream->lb_confs[h2d_upstream_hash.index];
	if (address->weight == 0) {
		return conf->address_vnodes;
	}
	return (int)(address->weight * conf->address_vnodes + 0.5);
}
static void h2d_upstream_hash_update(struct h2d_upstream_conf *upstream)
{
	struct h2d_upstream_hash_conf *conf = upstream->lb_confs[h2d_upstream_hash.index];

	conf->vnode_num = 0;
	struct h2d_upstream_address *address;
	wuy_list_iter_type(&upstream->address_head, address, upstream_node) {
		conf->vnode_num += h2d_upstream_hash_address_vnode_num(address);
	}

	conf->vnodes = realloc(conf->vnodes, sizeof(struct h2d_upstream_hash_vnode) * conf->vnode_num);

	struct h2d_upstream_hash_vnode *vnode = conf->vnodes;
	wuy_list_iter_type(&upstream->address_head, address, upstream_node) {
		uint64_t hash = h2d_upstream_hash_data(&address->sockaddr.s,
				wuy_sockaddr_size(&address->sockaddr.s));

		for (int i = 0; i < h2d_upstream_hash_address_vnode_num(address); i++) {
			vnode->hash = hash ^ h2d_upstream_hash_data(&i, sizeof(int));
			vnode->address = address;
			vnode++;
		}
	}

	qsort(conf->vnodes, conf->vnode_num, sizeof(struct h2d_upstream_hash_vnode),
			h2d_upstream_hash_vnode_cmp);
}

static struct h2d_upstream_address *h2d_upstream_hash_pick(
		struct h2d_upstream_conf *upstream, struct h2d_request *r)
{
	struct h2d_upstream_hash_conf *conf = upstream->lb_confs[h2d_upstream_hash.index];

	int key_len;
	const char *key_str = h2d_lua_api_call_lstring(r, conf->key, &key_len);
	if (key_str == NULL) {
		return NULL;
	}
	uint64_t hash = h2d_upstream_hash_data(key_str, key_len);

	/* pick one address */
	struct h2d_upstream_hash_vnode *vnode = NULL;
	int low = 0, high = conf->vnode_num - 1;
	while (low <= high) {
		int mid = (low + high) / 2;
		vnode = &conf->vnodes[mid];
		if (vnode->hash == hash) {
			break;
		}
		if (vnode->hash < hash) {
			low = mid + 1;
		} else {
			high = mid - 1;
		}
	}

	/* check if down */
	for (struct h2d_upstream_hash_vnode *i = vnode; i < conf->vnodes + conf->vnode_num; i++) {
		if (h2d_upstream_address_is_pickable(i->address)) {
			return i->address;
		}
	}
	for (struct h2d_upstream_hash_vnode *i = conf->vnodes; i < vnode; i++) {
		if (h2d_upstream_address_is_pickable(i->address)) {
			return i->address;
		}
	}

	return vnode->address;
}

static void h2d_upstream_hash_free(struct h2d_upstream_conf *upstream)
{
	struct h2d_upstream_hash_conf *conf = upstream->lb_confs[h2d_upstream_hash.index];
	free(conf->vnodes);
	free(conf);
}

static struct wuy_cflua_command h2d_upstream_hash_commands[] = {
	{	.type = WUY_CFLUA_TYPE_FUNCTION,
		.is_single_array = true,
		.offset = offsetof(struct h2d_upstream_hash_conf, key),
	},
	{	.name = "address_vnodes",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct h2d_upstream_hash_conf, address_vnodes),
		.default_value.n = 100,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{ NULL }
};

struct h2d_upstream_loadbalance h2d_upstream_hash = {
	.name = "hash",
	.command = {
		.name = "hash",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = 0, /* reset later */
		.u.table = &(struct wuy_cflua_table) {
			.commands = h2d_upstream_hash_commands,
			.size = sizeof(struct h2d_upstream_hash_conf),
		}
	},
	.update = h2d_upstream_hash_update,
	.pick = h2d_upstream_hash_pick,
	.free = h2d_upstream_hash_free,
};

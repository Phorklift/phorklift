#include "phl_main.h"

struct phl_upstream_hash_conf {
	wuy_cflua_function_t	key;
	int			address_vnodes;
};

struct phl_upstream_hash_ctx {
	int				vnode_num;
	struct phl_upstream_hash_vnode	*vnodes;
};

struct phl_upstream_hash_vnode {
	uint64_t			hash;
	struct phl_upstream_address	*address;
};

struct phl_upstream_loadbalance phl_upstream_hash;

static int phl_upstream_hash_vnode_cmp(const void *a, const void *b)
{
	const struct phl_upstream_hash_vnode *va = a;
	const struct phl_upstream_hash_vnode *vb = b;
	if (va->hash == vb->hash) {
		return 0;
	}
	return (va->hash > vb->hash) ? 1 : -1;
}

static void *phl_upstream_hash_ctx_new(void)
{
	return calloc(1, sizeof(struct phl_upstream_hash_ctx)); // TODO use pool
}

static void phl_upstream_hash_ctx_free(void *data)
{
	struct phl_upstream_hash_ctx *ctx = data;
	free(ctx->vnodes);
	free(ctx);
}

static int phl_upstream_hash_address_vnode_num(struct phl_upstream_address *address)
{
	struct phl_upstream_hash_conf *conf = address->upstream->lb_confs[phl_upstream_hash.index];
	if (address->weight == 0) {
		return conf->address_vnodes;
	}
	return (int)(address->weight * conf->address_vnodes + 0.5);
}
static void phl_upstream_hash_update(struct phl_upstream_conf *upstream)
{
	struct phl_upstream_hash_ctx *ctx = upstream->lb_ctx;

	ctx->vnode_num = 0;
	struct phl_upstream_address *address;
	wuy_list_iter_type(&upstream->address_head, address, upstream_node) {
		ctx->vnode_num += phl_upstream_hash_address_vnode_num(address);
	}

	ctx->vnodes = realloc(ctx->vnodes, sizeof(struct phl_upstream_hash_vnode) * ctx->vnode_num);

	struct phl_upstream_hash_vnode *vnode = ctx->vnodes;
	wuy_list_iter_type(&upstream->address_head, address, upstream_node) {
		uint64_t hash = wuy_vhash64(&address->sockaddr.s, wuy_sockaddr_size(&address->sockaddr.s));

		for (int i = 0; i < phl_upstream_hash_address_vnode_num(address); i++) {
			vnode->hash = hash ^ wuy_vhash64(&i, sizeof(int));
			vnode->address = address;
			vnode++;
		}
	}

	qsort(ctx->vnodes, ctx->vnode_num, sizeof(struct phl_upstream_hash_vnode),
			phl_upstream_hash_vnode_cmp);
}

static struct phl_upstream_address *phl_upstream_hash_pick(
		struct phl_upstream_conf *upstream, struct phl_request *r)
{
	struct phl_upstream_hash_conf *conf = upstream->lb_confs[phl_upstream_hash.index];
	struct phl_upstream_hash_ctx *ctx = upstream->lb_ctx;

	int key_len;
	const char *key_str = phl_lua_call_lstring(r, conf->key, &key_len);
	if (key_str == NULL) {
		return NULL;
	}
	uint64_t hash = wuy_vhash64(key_str, key_len);

	/* pick one address */
	struct phl_upstream_hash_vnode *vnode = NULL;
	int low = 0, high = ctx->vnode_num - 1;
	while (low <= high) {
		int mid = (low + high) / 2;
		vnode = &ctx->vnodes[mid];
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
	for (struct phl_upstream_hash_vnode *i = vnode; i < ctx->vnodes + ctx->vnode_num; i++) {
		if (phl_upstream_address_is_pickable(i->address, r)) {
			return i->address;
		}
	}
	for (struct phl_upstream_hash_vnode *i = ctx->vnodes; i < vnode; i++) {
		if (phl_upstream_address_is_pickable(i->address, r)) {
			return i->address;
		}
	}

	return vnode->address;
}

static struct wuy_cflua_command phl_upstream_hash_commands[] = {
	{	.type = WUY_CFLUA_TYPE_FUNCTION,
		.description = "Return string as hash key.",
		.is_single_array = true,
		.offset = offsetof(struct phl_upstream_hash_conf, key),
	},
	{	.name = "address_vnodes",
		.type = WUY_CFLUA_TYPE_INTEGER,
		.offset = offsetof(struct phl_upstream_hash_conf, address_vnodes),
		.default_value.n = 100,
		.limits.n = WUY_CFLUA_LIMITS_POSITIVE,
	},
	{ NULL }
};

struct phl_upstream_loadbalance phl_upstream_hash_loadbalance = {
	.name = "hash",
	.command = {
		.name = "hash",
		.description = "Hash upstream loadbalance. " \
				"Consistent hash is used. Weight is supported.",
		.type = WUY_CFLUA_TYPE_TABLE,
		.offset = 0, /* reset later */
		.u.table = &(struct wuy_cflua_table) {
			.commands = phl_upstream_hash_commands,
			.size = sizeof(struct phl_upstream_hash_conf),
		}
	},
	.ctx_new = phl_upstream_hash_ctx_new,
	.ctx_free = phl_upstream_hash_ctx_free,
	.update = phl_upstream_hash_update,
	.pick = phl_upstream_hash_pick,
};

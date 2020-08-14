#include "h2d_main.h"

#include <openssl/md5.h>
#include "libwuya/wuy_murmurhash.h"

#define H2D_UPSTREAM_HASH_ADDRESS_VNODES 100

struct h2d_upstream_hash_vnode {
	uint32_t			n;
	struct h2d_upstream_address	*address;
};

static uint32_t h2d_upstream_hash_vnode_hash(struct h2d_upstream_address *address, int i)
{
	union {
		unsigned char out[16];
		uint32_t ret;
	} u;

	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, &i, sizeof(int));
	MD5_Update(&ctx, &address->sockaddr.s, wuy_sockaddr_size(&address->sockaddr.s));
	MD5_Final(u.out, &ctx);
	return u.ret;
}

static int h2d_upstream_hash_vnode_cmp(const void *a, const void *b)
{
	const struct h2d_upstream_hash_vnode *va = a;
	const struct h2d_upstream_hash_vnode *vb = b;
	if (va->n == vb->n) {
		return 0;
	}
	return (va->n > vb->n) ? 1 : -1;
}

static void h2d_upstream_hash_update(struct h2d_upstream_conf *upstream)
{
	int vnode_num = upstream->address_num * H2D_UPSTREAM_HASH_ADDRESS_VNODES;
	upstream->lb_ctx = realloc(upstream->lb_ctx, sizeof(struct h2d_upstream_hash_vnode) * vnode_num);

	struct h2d_upstream_hash_vnode *vnode = upstream->lb_ctx;

	struct h2d_upstream_address *address;
	wuy_list_iter_type(&upstream->address_head, address, upstream_node) {
		for (int i = 0; i < H2D_UPSTREAM_HASH_ADDRESS_VNODES; i++) {
			vnode->n = h2d_upstream_hash_vnode_hash(address, i);
			vnode->address = address;
			vnode++;
		}
	}

	qsort(upstream->lb_ctx, vnode_num, sizeof(struct h2d_upstream_hash_vnode),
			h2d_upstream_hash_vnode_cmp);
}

extern struct h2d_request *h2d_lua_current_request;
static struct h2d_upstream_address *h2d_upstream_hash_pick(
		struct h2d_upstream_conf *upstream, struct h2d_request *r)
{
	/* get the hash key */
	h2d_lua_current_request = r;
	lua_rawgeti(h2d_L, LUA_REGISTRYINDEX, upstream->hash);
	if (lua_pcall(h2d_L, 0, 1, 0) != 0) {
		printf("lua_pcall fail: %s\n", lua_tostring(h2d_L, -1));
		lua_pop(h2d_L, 1);
		return NULL;
	}
	size_t key_len;
	const char *key_str = lua_tolstring(h2d_L, -1, &key_len);

	/* calculate hash value */
	union {
		unsigned char out[16];
		uint32_t ret;
	} u;
	wuy_murmurhash(key_str, key_len, u.out);
	uint32_t n = u.ret;

	/* pop after calculating, because the returned key_str maybe
	 * freed by Lua GC in lua_pop() */
	lua_pop(h2d_L, 1);

	/* pick one address */
	struct h2d_upstream_hash_vnode *vnodes = upstream->lb_ctx;
	struct h2d_upstream_hash_vnode *vnode = NULL;
	int low = 0, high = upstream->address_num * H2D_UPSTREAM_HASH_ADDRESS_VNODES - 1;
	while (low <= high) {
		int mid = (low + high) / 2;
		vnode = &vnodes[mid];
		if (vnode->n == n) {
			break;
		}
		if (vnode->n < n) {
			low = mid + 1;
		} else {
			high = mid - 1;
		}
	}

	return vnode->address;
}

struct h2d_upstream_loadbalance h2d_upstream_loadbalance_hash = {
	.name = "hash",
	.update = h2d_upstream_hash_update,
	.pick = h2d_upstream_hash_pick,
};

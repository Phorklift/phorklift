#include "h2d_main.h"

struct h2d_upstream_roundrobin_ctx {
	struct h2d_upstream_address	**addresses;
	int				index;
};

static void h2d_upstream_roundrobin_init(struct h2d_upstream_conf *upstream)
{
	upstream->lb_ctx = calloc(1, sizeof(struct h2d_upstream_roundrobin_ctx));
}

static void h2d_upstream_roundrobin_update(struct h2d_upstream_conf *upstream)
{
	struct h2d_upstream_roundrobin_ctx *ctx = upstream->lb_ctx;

	ctx->index = 0;
	ctx->addresses = realloc(ctx->addresses,
			sizeof(struct h2d_upstream_address *) * upstream->address_num);

	int i = 0;
	struct h2d_upstream_address *address;
	wuy_list_iter_type(&upstream->address_head, address, upstream_node) {
		ctx->addresses[i++] = address;
	}
}

static struct h2d_upstream_address *h2d_upstream_roundrobin_pick(
		struct h2d_upstream_conf *upstream, struct h2d_request *r)
{
	struct h2d_upstream_roundrobin_ctx *ctx = upstream->lb_ctx;

	if (ctx->index == upstream->address_num) {
		ctx->index = 0;
	}

	for (int i = ctx->index; i < upstream->address_num; i++) {
		struct h2d_upstream_address *address = ctx->addresses[i];
		if (!h2d_upstream_address_is_down(address)) {
			ctx->index = i + 1;
			return address;
		}
	}
	for (int i = 0; i < ctx->index; i++) {
		struct h2d_upstream_address *address = ctx->addresses[i];
		if (!h2d_upstream_address_is_down(address)) {
			ctx->index = i + 1;
			return address;
		}
	}

	return ctx->addresses[ctx->index++]; /* even if it's down */
}

struct h2d_upstream_loadbalance h2d_upstream_loadbalance_roundrobin = {
	.name = "roundrobin",
	.init = h2d_upstream_roundrobin_init,
	.update = h2d_upstream_roundrobin_update,
	.pick = h2d_upstream_roundrobin_pick,
};

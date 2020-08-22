#include "h2d_main.h"

struct h2d_upstream_roundrobin_ctx {
	int				index;
	struct h2d_upstream_address	*addresses[0];
};

static void h2d_upstream_roundrobin_update(struct h2d_upstream_conf *upstream)
{
	upstream->lb_ctx = realloc(upstream->lb_ctx,
			sizeof(struct h2d_upstream_roundrobin_ctx) +
			sizeof(struct h2d_upstream_address *) * upstream->address_num);

	struct h2d_upstream_roundrobin_ctx *ctx = upstream->lb_ctx;
	ctx->index = 0;

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
		if (h2d_upstream_address_is_pickable(address)) {
			ctx->index = i + 1;
			return address;
		}
	}
	for (int i = 0; i < ctx->index; i++) {
		struct h2d_upstream_address *address = ctx->addresses[i];
		if (h2d_upstream_address_is_pickable(address)) {
			ctx->index = i + 1;
			return address;
		}
	}

	return ctx->addresses[ctx->index++];
}

struct h2d_upstream_loadbalance h2d_upstream_loadbalance_roundrobin = {
	.name = "roundrobin",
	.update = h2d_upstream_roundrobin_update,
	.pick = h2d_upstream_roundrobin_pick,
};

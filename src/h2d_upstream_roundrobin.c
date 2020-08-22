#include "h2d_main.h"

struct h2d_upstream_roundrobin_address {
	int				count; /* compared agaist address->weight */
	int				left;
	struct h2d_upstream_address	*address;
};

struct h2d_upstream_roundrobin_ctx {
	int					index;
	struct h2d_upstream_roundrobin_address	rr_addresses[0];
};

static void h2d_upstream_roundrobin_update(struct h2d_upstream_conf *upstream)
{
	upstream->lb_ctx = realloc(upstream->lb_ctx, sizeof(struct h2d_upstream_roundrobin_ctx) +
			sizeof(struct h2d_upstream_roundrobin_address) * upstream->address_num);

	struct h2d_upstream_roundrobin_ctx *ctx = upstream->lb_ctx;
	ctx->index = 0;

	int i = 0;
	struct h2d_upstream_address *address;
	wuy_list_iter_type(&upstream->address_head, address, upstream_node) {
		struct h2d_upstream_roundrobin_address *rr_addr = &ctx->rr_addresses[i++];
		rr_addr->count = 0;
		rr_addr->left = 0;
		rr_addr->address = address;
	}
}

static bool h2d_upstream_roundrobin_count_weight(struct h2d_upstream_roundrobin_address *rr_addr)
{
	double weight = rr_addr->address->weight;

	if (weight == 0 || weight == 1.0) {
		return true;
	}

	if (weight > 1.0) {
		double left = weight - rr_addr->count;
		if (left > 1.0) {
			rr_addr->count++;
			return true;
		}
		if (left == 1.0) {
			rr_addr->count = 0;
			return true;
		}

		/* left < 1.0 */
		rr_addr->count = 0;
		if (++rr_addr->left == (int)(1.0 / left + 0.5)) {
			rr_addr->left = 0;
			return true;
		}
		return false;

	} else { /* weight < 1.0 */
		if (++rr_addr->count == (int)(1.0 / weight + 0.5)) {
			rr_addr->count = 0;
			return true;
		}
		return false;
	}
}

static struct h2d_upstream_address *h2d_upstream_roundrobin_check(
		struct h2d_upstream_roundrobin_ctx *ctx, int i)
{
	struct h2d_upstream_roundrobin_address *rr_addr = &ctx->rr_addresses[i];

	if (!h2d_upstream_address_is_pickable(rr_addr->address)) {
		return NULL;
	}

	if (!h2d_upstream_roundrobin_count_weight(rr_addr)) {
		return NULL;
	}
	ctx->index = (rr_addr->count != 0) ? i : i + 1;

	return rr_addr->address;
}

static struct h2d_upstream_address *h2d_upstream_roundrobin_pick(
		struct h2d_upstream_conf *upstream, struct h2d_request *r)
{
	struct h2d_upstream_roundrobin_ctx *ctx = upstream->lb_ctx;

	if (ctx->index == upstream->address_num) {
		ctx->index = 0;
	}

	for (int i = ctx->index; i < upstream->address_num; i++) {
		struct h2d_upstream_address *address = h2d_upstream_roundrobin_check(ctx, i);
		if (address != NULL) {
			return address;
		}
	}
	for (int i = 0; i < ctx->index; i++) {
		struct h2d_upstream_address *address = h2d_upstream_roundrobin_check(ctx, i);
		if (address != NULL) {
			return address;
		}
	}

	return ctx->rr_addresses[ctx->index++].address;
}

struct h2d_upstream_loadbalance h2d_upstream_loadbalance_roundrobin = {
	.name = "roundrobin",
	.update = h2d_upstream_roundrobin_update,
	.pick = h2d_upstream_roundrobin_pick,
};

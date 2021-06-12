#include "h2d_main.h"

struct h2d_upstream_random_address {
	double				hash;
	struct h2d_upstream_address	*address;
};

struct h2d_upstream_random_ctx {
	int				total_num;
	int				available_num;
	struct h2d_upstream_random_address	*addresses;
};

struct h2d_upstream_loadbalance h2d_upstream_random;

static void *h2d_upstream_random_ctx_new(void)
{
	return calloc(1, sizeof(struct h2d_upstream_random_ctx));
}

static void h2d_upstream_random_ctx_free(void *data)
{
	struct h2d_upstream_random_ctx *ctx = data;
	free(ctx->addresses);
	free(ctx);
}

static void h2d_upstream_random_update(struct h2d_upstream_conf *upstream)
{
	struct h2d_upstream_random_ctx *ctx = upstream->lb_ctx;

	ctx->total_num = upstream->address_num;
	ctx->available_num = upstream->address_num;

	ctx->addresses = realloc(ctx->addresses, sizeof(struct h2d_upstream_random_address)
			* (ctx->total_num + 1));

	double hash = 0.0;
	struct h2d_upstream_address *address;
	struct h2d_upstream_random_address *rr_addr = ctx->addresses;
	wuy_list_iter_type(&upstream->address_head, address, upstream_node) {
		rr_addr->address = address;
		rr_addr->hash = hash;
		rr_addr++;
		hash += address->weight;
	}

	/* sentinel */
	rr_addr->address = NULL;
	rr_addr->hash = hash;
}

static void h2d_upstream_random_exchange(struct h2d_upstream_random_ctx *ctx,
		int index1, int index2)
{
	if (index1 == index2) { /* no need exchange */
		return;
	}

	assert(index1 < index2);

	struct h2d_upstream_random_address *addr1 = &ctx->addresses[index1];
	struct h2d_upstream_random_address *addr2 = &ctx->addresses[index2];

	/* exchange address */
	struct h2d_upstream_address *tmp = addr1->address;
	addr1->address = addr2->address;
	addr2->address = tmp;

	/* update hash in [index1+1, index2] */
	double diff = addr1->address->weight - addr2->address->weight;
	if (diff != 0.0) {
		for (int i = index1 + 1; i <= index2; i++) {
			ctx->addresses[i].hash += diff;
		}
	}
}

/* exchange between @down and last-available address */
static void h2d_upstream_random_expire(struct h2d_upstream_random_ctx *ctx, int down)
{
	h2d_upstream_random_exchange(ctx, down, --ctx->available_num);
}

/* exchange between @recov and first-down address */
static void h2d_upstream_random_recover(struct h2d_upstream_random_ctx *ctx, int recov)
{
	h2d_upstream_random_exchange(ctx, ctx->available_num++, recov);
}

static int h2d_upstream_random_random(struct h2d_upstream_random_ctx *ctx, int limit)
{
	double hash = wuy_rand_double() * ctx->addresses[limit].hash;

	int low = 0, high = limit - 1, mid = -1;
	while (low <= high) {
		mid = (low + high) / 2;
		double lower = ctx->addresses[mid].hash;
		double upper = ctx->addresses[mid + 1].hash;

		if (hash >= upper) {
			low = mid + 1;
		} else if (hash < lower) {
			high = mid - 1;
		} else {
			break;
		}
	}
	assert(low <= high && mid >= 0);
	return mid;
}

static struct h2d_upstream_address *h2d_upstream_random_pick(
		struct h2d_upstream_conf *upstream, struct h2d_request *r)
{
	struct h2d_upstream_random_ctx *ctx = upstream->lb_ctx;

	/* pick one amount all addresses */
	int picked = h2d_upstream_random_random(ctx, ctx->total_num);
	struct h2d_upstream_address *address = ctx->addresses[picked].address;

	h2d_request_log_at(r, upstream->log, H2D_LOG_DEBUG, "random pick %d %s", picked, address->name);

	/* this one is not-available by now */
	if (picked >= ctx->available_num) {
		if (address->failure.down_time == 0 && address->healthcheck.down_time == 0) {
			h2d_request_log_at(r, upstream->log, H2D_LOG_INFO, "random recover %d %s",
					picked, address->name);
			h2d_upstream_random_recover(ctx, picked);
			return address;
		}
		if (h2d_upstream_address_is_pickable(address, r)) {
			h2d_request_log_at(r, upstream->log, H2D_LOG_DEBUG, "random try not-available");
			return address;
		}

retry:
		/* pick again amount available addresses only */
		if (ctx->available_num == 0) { /* no available */
			h2d_request_log_at(r, upstream->log, H2D_LOG_DEBUG, "random return not-available");
			return address;
		}

		picked = h2d_upstream_random_random(ctx, ctx->available_num);
		address = ctx->addresses[picked].address;

		h2d_request_log_at(r, upstream->log, H2D_LOG_DEBUG, "random pick again: %d %s",
				picked, address->name);
	}

	if (h2d_upstream_address_is_pickable(address, r)) {
		return address; /* done! this is the mostly case */
	}

	h2d_request_log_at(r, upstream->log, H2D_LOG_INFO, "random expire %d %s", picked, address->name);
	h2d_upstream_random_expire(ctx, picked);

	goto retry;
}

struct h2d_upstream_loadbalance h2d_upstream_random_loadbalance = {
	.name = "random",
	.ctx_new = h2d_upstream_random_ctx_new,
	.ctx_free = h2d_upstream_random_ctx_free,
	.update = h2d_upstream_random_update,
	.pick = h2d_upstream_random_pick,
};

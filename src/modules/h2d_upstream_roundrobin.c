#include "h2d_main.h"

struct h2d_upstream_roundrobin_address {
	double				hash;
	struct h2d_upstream_address	*address;
};

struct h2d_upstream_roundrobin_conf {
	int				total_num;
	int				available_num;
	struct h2d_upstream_roundrobin_address	*addresses;
};

struct h2d_upstream_loadbalance h2d_upstream_roundrobin;

static void h2d_upstream_roundrobin_update(struct h2d_upstream_conf *upstream)
{
	struct h2d_upstream_roundrobin_conf *conf = upstream->lb_confs[h2d_upstream_roundrobin.index];

	if (conf == NULL) {
		/* There is no command defined in h2d_upstream_loadbalance_roundrobin,
		 * so the conf was not allocated during loading configuration.
		 * We have to allocate it at first time. */
		conf = calloc(1, sizeof(struct h2d_upstream_roundrobin_conf));
		upstream->lb_confs[h2d_upstream_roundrobin.index] = conf;
	}

	conf->total_num = upstream->address_num;
	conf->available_num = upstream->address_num;

	free(conf->addresses);
	conf->addresses = malloc(sizeof(struct h2d_upstream_roundrobin_address) *
			(conf->total_num + 1));

	double hash = 0.0;
	struct h2d_upstream_address *address;
	struct h2d_upstream_roundrobin_address *rr_addr = conf->addresses;
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

static void h2d_upstream_roundrobin_exchange(struct h2d_upstream_roundrobin_conf *conf,
		int index1, int index2)
{
	printf("exchange %d %d\n", index1, index2);
	if (index1 == index2) { /* no need exchange */
		return;
	}

	assert(index1 < index2);

	struct h2d_upstream_roundrobin_address *addr1 = &conf->addresses[index1];
	struct h2d_upstream_roundrobin_address *addr2 = &conf->addresses[index2];

	/* exchange address */
	struct h2d_upstream_address *tmp = addr1->address;
	addr1->address = addr2->address;
	addr2->address = tmp;

	/* update hash in [index1+1, index2] */
	double diff = addr1->address->weight - addr2->address->weight;
	if (diff != 0.0) {
		for (int i = index1 + 1; i <= index2; i++) {
			conf->addresses[i].hash += diff;
		}
	}
}

/* exchange between @down and last-available address */
static void h2d_upstream_roundrobin_expire(struct h2d_upstream_roundrobin_conf *conf, int down)
{
	h2d_upstream_roundrobin_exchange(conf, down, --conf->available_num);
}

/* exchange between @recov and first-down address */
static void h2d_upstream_roundrobin_recover(struct h2d_upstream_roundrobin_conf *conf, int recov)
{
	h2d_upstream_roundrobin_exchange(conf, conf->available_num++, recov);
}

static int h2d_upstream_roundrobin_random(struct h2d_upstream_roundrobin_conf *conf, int limit)
{
	double hash = wuy_rand_double() * conf->addresses[limit].hash;

	int low = 0, high = limit - 1, mid = -1;
	while (low <= high) {
		mid = (low + high) / 2;
		double lower = conf->addresses[mid].hash;
		double upper = conf->addresses[mid + 1].hash;

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

static struct h2d_upstream_address *h2d_upstream_roundrobin_pick(
		struct h2d_upstream_conf *upstream, struct h2d_request *r)
{
	struct h2d_upstream_roundrobin_conf *conf = upstream->lb_confs[h2d_upstream_roundrobin.index];

	/* pick one amount all addresses */
	int picked = h2d_upstream_roundrobin_random(conf, conf->total_num);
	struct h2d_upstream_address *address = conf->addresses[picked].address;

	h2d_request_log(r, H2D_LOG_DEBUG, "roundrobin pick first: %d", picked);

	/* this one is not-available by now */
	if (picked >= conf->available_num) {
		if (address->down_time == 0) {
			h2d_request_log(r, H2D_LOG_DEBUG, "roundrobin recover: %d", picked);
			h2d_upstream_roundrobin_recover(conf, picked);
			return address;
		}
		if (h2d_upstream_address_is_pickable(address)) {
			h2d_request_log(r, H2D_LOG_DEBUG, "roundrobin try not-available: %d", picked);
			return address;
		}

retry:
		/* pick again amount available addresses only */
		if (conf->available_num == 0) { /* no available */
			h2d_request_log(r, H2D_LOG_DEBUG, "roundrobin return not-available");
			return address;
		}

		picked = h2d_upstream_roundrobin_random(conf, conf->available_num);
		address = conf->addresses[picked].address;

		h2d_request_log(r, H2D_LOG_DEBUG, "roundrobin pick again: %d", picked);
	}

	if (h2d_upstream_address_is_pickable(address)) {
		h2d_request_log(r, H2D_LOG_DEBUG, "roundrobin pick OK");
		return address; /* done! this is the mostly case */
	}

	h2d_upstream_roundrobin_expire(conf, picked);

	h2d_request_log(r, H2D_LOG_DEBUG, "roundrobin expire, retry...");
	goto retry;
}

static void h2d_upstream_roundrobin_free(struct h2d_upstream_conf *upstream)
{
	struct h2d_upstream_roundrobin_conf *conf = upstream->lb_confs[h2d_upstream_roundrobin.index];
	free(conf->addresses);
	free(conf);
}

struct h2d_upstream_loadbalance h2d_upstream_roundrobin = {
	.name = "roundrobin",
	.update = h2d_upstream_roundrobin_update,
	.pick = h2d_upstream_roundrobin_pick,
	.free = h2d_upstream_roundrobin_free,
};

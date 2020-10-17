#include "h2d_main.h"

struct h2d_upstream_roundrobin_conf {
	int				total_num;
	int				available_num;
	struct h2d_upstream_address	**addresses;
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

	conf->total_num = conf->available_num = upstream->address_num;
	conf->addresses = realloc(conf->addresses,
			sizeof(struct h2d_upstream_address *) * conf->total_num);

	int i = 0;
	struct h2d_upstream_address *address;
	wuy_list_iter_type(&upstream->address_head, address, upstream_node) {
		conf->addresses[i++] = address;
	}
}

static void h2d_upstream_roundrobin_expire(struct h2d_upstream_roundrobin_conf *conf, int index)
{
	assert(index < conf->available_num);

	struct h2d_upstream_address *address = conf->addresses[index];
	address->lb_data.d = 0.0;

	if (conf->available_num == 1) { /* begin new round */
		conf->available_num = conf->total_num;
		return;
	}

	conf->addresses[index] = conf->addresses[conf->available_num - 1];
	conf->addresses[conf->available_num - 1] = address;
	conf->available_num--;
}

static bool h2d_upstream_roundrobin_check(struct h2d_upstream_roundrobin_conf *conf, int index)
{
	struct h2d_upstream_address *address = conf->addresses[index];

	if (!h2d_upstream_address_is_pickable(address)) {
		h2d_upstream_roundrobin_expire(conf, index);
		return false;
	}

	double left = address->weight - address->lb_data.d;
	if (left == 1.0) {
		h2d_upstream_roundrobin_expire(conf, index);
		return true;
	}
	if (left > 1.0) {
		address->lb_data.d += 1.0;
		return true;
	}

	/* left < 1.0 */
	h2d_upstream_roundrobin_expire(conf, index);
	return wuy_rand_sample(left);
}

static struct h2d_upstream_address *h2d_upstream_roundrobin_try_pick(
		struct h2d_upstream_roundrobin_conf *conf, int index)
{
	while (1) {
		struct h2d_upstream_address *address = conf->addresses[index];
		if (h2d_upstream_roundrobin_check(conf, index)) {
			return address;
		}
		/* otherwise the address is expired and conf->addresses[index]
		 * is replaced if still any available */

		if (conf->addresses[index] == address) { /* no available */
			return NULL;
		}
	}
	return NULL; /* should not be here */
}

static struct h2d_upstream_address *h2d_upstream_roundrobin_pick(
		struct h2d_upstream_conf *upstream, struct h2d_request *r)
{
	struct h2d_upstream_roundrobin_conf *conf = upstream->lb_confs[h2d_upstream_roundrobin.index];

	int original_avail_num = conf->available_num;
	int picked = wuy_rand_range(conf->available_num);

	/* conf->addresses:
	 *
	 *    |=2=====|=1=======|-3----------------------|
	 *    ^       ^         ^                        ^
	 *    0       picked    original_avail_num       conf->total_num
	 */

	/* 1. try to find an available address between [picked, conf->available_num] */
	struct h2d_upstream_address *address = h2d_upstream_roundrobin_try_pick(conf, picked);
	if (address != NULL) {
		return address;
	}

	/* 2. try between [0, conf->available_num(=picked)]*/
	if (picked > 0) {
		address = h2d_upstream_roundrobin_try_pick(conf, 0);
		if (address != NULL) {
			return address;
		}
	}

	/* 3. new round begins, try between [original_avail_num, conf->available_num(=conf->total_num)]*/
	if (original_avail_num < conf->total_num) {
		address = h2d_upstream_roundrobin_try_pick(conf, original_avail_num);
		if (address != NULL) {
			return address;
		}
	}

	/* no available */
	return NULL;
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

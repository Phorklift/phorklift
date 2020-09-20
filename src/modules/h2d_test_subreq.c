#include "h2d_main.h"

struct h2d_test_subreq_conf {
	bool	enable;
};

extern struct h2d_module h2d_test_subreq_module;

static int h2d_test_subreq_filter_response_headers(struct h2d_request *r)
{
	struct h2d_test_subreq_conf *conf = r->conf_path->module_confs[h2d_test_subreq_module.index];
	if (!conf->enable) {
		return H2D_OK;
	}
	if (r->resp.status_code != WUY_HTTP_200) {
		return H2D_OK;
	}

	r->resp.content_length = H2D_CONTENT_LENGTH_INIT;
	return H2D_OK;
}
static int h2d_test_subreq_filter_response_body(struct h2d_request *r, uint8_t *data, int data_len, int buf_len)
{
	struct h2d_test_subreq_conf *conf = r->conf_path->module_confs[h2d_test_subreq_module.index];
	if (!conf->enable) {
		return data_len;
	}

	struct h2d_request *subr = r->module_ctxs[h2d_test_subreq_module.index];
	if (subr == NULL) {
		subr = h2d_request_subrequest(r);
		h2d_request_set_uri(subr, (char *)data, data_len - 1);
		printf("subr: %s\n", subr->req.uri.raw);

		r->module_ctxs[h2d_test_subreq_module.index] = subr;
		return H2D_AGAIN;
	} else if (subr != (void *)1) {
		int new_data_len = subr->c->send_buf_pos - subr->c->send_buffer;
		memcpy(data, subr->c->send_buffer, new_data_len);
		subr->c->send_buf_pos = subr->c->send_buffer;
		r->module_ctxs[h2d_test_subreq_module.index] = (void *)1;

		subr->father = NULL;
		h2d_request_close(subr);

		return new_data_len;
	} else {
		return H2D_OK;
	}
}

/* configuration */

static struct wuy_cflua_command h2d_test_subreq_conf_commands[] = {
	{	.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct h2d_test_subreq_conf, enable),
		.flags = WUY_CFLUA_FLAG_UNIQ_MEMBER,
	},
	{ NULL }
};

struct h2d_module h2d_test_subreq_module = {
	.name = "test_subreq",
	.command_path = {
		.name = "test_subreq",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) {
			.commands = h2d_test_subreq_conf_commands,
			.size = sizeof(struct h2d_test_subreq_conf),
		}
	},

	.filters = {
		.response_headers = h2d_test_subreq_filter_response_headers,
		.response_body = h2d_test_subreq_filter_response_body,
	},
};

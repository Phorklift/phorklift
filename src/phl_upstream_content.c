#include "phl_main.h"

static struct phl_upstream_conf *phl_upstream_content_conf(struct phl_request *r)
{
	/* `struct phl_upstream_conf *` must be at the top of content module's conf, as a pointer */
	struct phl_upstream_conf **p = r->conf_path->module_confs[r->conf_path->content->index];
	return *p;
}

static bool phl_upstream_content_status_code_retry(struct phl_request *r)
{
	struct phl_upstream_conf *upstream = phl_upstream_content_conf(r);
	if (upstream->retry_status_codes == NULL) {
		return false;
	}
	for (int *p = upstream->retry_status_codes; *p != 0; p++) {
		if (r->resp.status_code == *p) {
			phl_request_log_at(r, upstream->log, PHL_LOG_DEBUG,
					"retry for status_code=%d", r->resp.status_code);
			return true;
		}
	}
	return false;
}

static int phl_upstream_content_fail(struct phl_request *r);
int phl_upstream_content_generate_response_headers(struct phl_request *r)
{
	struct phl_upstream_conf *upstream = phl_upstream_content_conf(r);
	struct phl_upstream_content_ctx *ctx = r->module_ctxs[r->conf_path->content->index];
	struct phl_upstream_ops *ops = upstream->ops;

	if (ctx == NULL) {
		ctx = wuy_pool_alloc(r->pool, sizeof(struct phl_upstream_content_ctx));
		r->module_ctxs[r->conf_path->content->index] = ctx;

		int ret = ops->build_request(r);
		if (ret != PHL_OK) {
			return ret;
		}
	}

	if (ctx->upc == NULL) {
		void *upc = phl_upstream_get_connection(upstream, r);
		if (!PHL_PTR_IS_OK(upc)) {
			return PHL_PTR2RET(upc);
		}
		ctx->upc = upc;
	}

	if (!ctx->has_sent_request) {
		int ret = phl_upstream_connection_write(ctx->upc, ctx->req_buf, ctx->req_len);
		if (ret == PHL_AGAIN) {
			return PHL_AGAIN;
		}
		if (ret == PHL_ERROR) {
			return phl_upstream_content_fail(r);
		}
		ctx->has_sent_request = true;
	}

	if (ops->parse_response_headers == NULL) {
		r->resp.status_code = WUY_HTTP_200;
		return PHL_OK;
	}

	char buffer[4096];
	int read_len = phl_upstream_connection_read(ctx->upc, buffer, sizeof(buffer));
	if (read_len == PHL_AGAIN) {
		return PHL_AGAIN;
	}
	if (read_len == PHL_ERROR) {
		return phl_upstream_content_fail(r);
	}

	bool is_done;
	int proc_len = ops->parse_response_headers(r, buffer, read_len, &is_done);
	if (proc_len < 0) {
		return phl_upstream_content_fail(r);
	}

	phl_upstream_connection_read_notfinish(ctx->upc, buffer + proc_len, read_len - proc_len);

	if (!is_done) {
		return PHL_AGAIN;
	}

	if (phl_upstream_content_status_code_retry(r)) {
		return phl_upstream_content_fail(r);
	}

	return PHL_OK;
}

static int phl_upstream_content_fail(struct phl_request *r)
{
	struct phl_upstream_conf *upstream = phl_upstream_content_conf(r);
	struct phl_upstream_content_ctx *ctx = r->module_ctxs[r->conf_path->content->index];

	ctx->upc->error = true;

	/* retry */
	if (ctx->retries < 0 || ctx->retries++ >= upstream->max_retries) {
		phl_request_log_at(r, upstream->log, PHL_LOG_INFO, "no retry %d", ctx->retries);
		return r->resp.status_code != 0 ? PHL_OK : WUY_HTTP_502;
	}

	phl_request_reset_response(r);

	ctx->upc = phl_upstream_retry_connection(ctx->upc);
	if (ctx->upc == PHL_PTR_ERROR) {
		return WUY_HTTP_500;
	}
	ctx->has_sent_request = false;

	return phl_upstream_content_generate_response_headers(r);
}

int phl_upstream_content_generate_response_body(struct phl_request *r,
		uint8_t *buffer, int buf_len)
{
	struct phl_upstream_conf *upstream = phl_upstream_content_conf(r);
	struct phl_upstream_content_ctx *ctx = r->module_ctxs[r->conf_path->content->index];
	struct phl_upstream_ops *ops = upstream->ops;

	if (ops->is_response_body_done && ops->is_response_body_done(r)) {
		return 0;
	}

	int read_len = phl_upstream_connection_read(ctx->upc, buffer, buf_len);
	if (read_len < 0) {
		return read_len;
	}

	if (ops->build_response_body != NULL) {
		read_len = ops->build_response_body(r, buffer, read_len, buf_len);
	}

	return read_len;
}

void phl_upstream_content_ctx_free(struct phl_request *r)
{
	struct phl_upstream_content_ctx *ctx = r->module_ctxs[r->conf_path->content->index];
	if (ctx->upc != NULL) {
		phl_upstream_release_connection(ctx->upc, r->state == PHL_REQUEST_STATE_DONE);
	}
}

const char *phl_upstream_content_set_ops(struct phl_upstream_conf *conf,
		struct phl_upstream_ops *ops)
{
	if (conf == NULL) {
		return WUY_CFLUA_OK;
	}
	if (conf->ops != NULL) {
		if (conf->ops != ops) {
			return "different ops for one upstream";
		}
		return WUY_CFLUA_OK;
	}
	conf->ops = ops;
	return WUY_CFLUA_OK;
}

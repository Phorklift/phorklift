#include "h2d_main.h"

static struct h2d_upstream_conf *h2d_upstream_content_conf(struct h2d_request *r)
{
	/* `struct h2d_upstream_conf *` must be at the top of content module's conf */
	struct h2d_upstream_conf **p = r->conf_path->module_confs[r->conf_path->content->index];
	return *p;
}
static struct h2d_upstream_content_ctx *h2d_upstream_content_ctx(struct h2d_request *r)
{
	/* `struct h2d_upstream_content_ctx` must be at the top of content module's ctx */
	return r->module_ctxs[r->conf_path->content->index];
}

static bool h2d_upstream_content_status_code_retry(struct h2d_request *r)
{
	struct h2d_upstream_conf *upstream = h2d_upstream_content_conf(r);
	if (upstream->retry_status_codes == NULL) {
		return false;
	}
	for (int *p = upstream->retry_status_codes; *p != 0; p++) {
		if (r->resp.status_code == *p) {
			printf("debug retry_status_codes hit: %d\n", *p);
			return true;
		}
	}
	return false;
}

static int h2d_upstream_content_fail(struct h2d_request *r);
int h2d_upstream_content_generate_response_headers(struct h2d_request *r)
{
	struct h2d_upstream_conf *upstream = h2d_upstream_content_conf(r);
	struct h2d_upstream_content_ctx *ctx = h2d_upstream_content_ctx(r);
	if (ctx == NULL) {
		/* create ctx */
		ctx = upstream->ops->new_ctx(r);
		r->module_ctxs[r->conf_path->content->index] = ctx;

		/* get upstream connection */
		ctx->upc = h2d_upstream_get_connection(upstream, r);
		if (ctx->upc == NULL) {
			return WUY_HTTP_500;
		}

		ctx->req_buf = upstream->ops->build_request(r, &ctx->req_len);
	}

	if (!ctx->has_sent_request) {
		if (h2d_upstream_connection_write_blocked(ctx->upc)) {// remove this check if h2d_upstream_connection_write() can return H2D_AGAIN
			return H2D_AGAIN;
		}
		int ret = h2d_upstream_connection_write(ctx->upc, ctx->req_buf, ctx->req_len);
		if (ret == H2D_AGAIN) {
			return H2D_AGAIN;
		}
		if (ret == H2D_ERROR) {
			return h2d_upstream_content_fail(r);
		}
		ctx->has_sent_request = true;
	}

	char buffer[4096];
	int read_len = h2d_upstream_connection_read(ctx->upc, buffer, sizeof(buffer));
	if (read_len == H2D_AGAIN) {
		return H2D_AGAIN;
	}
	if (read_len == H2D_ERROR) {
		return h2d_upstream_content_fail(r);
	}

	bool is_done;
	int proc_len = upstream->ops->parse_response_headers(r, buffer, read_len, &is_done);
	if (proc_len < 0) {
		return h2d_upstream_content_fail(r);
	}
	if (!is_done) {
		// TODO read again
		printf("too long response header\n");
		return H2D_ERROR;
	}

	if (h2d_upstream_content_status_code_retry(r)) {
		return h2d_upstream_content_fail(r);
	}

	h2d_upstream_connection_read_notfinish(ctx->upc, buffer + proc_len, read_len - proc_len);
	return H2D_OK;
}

static int h2d_upstream_content_fail(struct h2d_request *r)
{
	struct h2d_upstream_conf *upstream = h2d_upstream_content_conf(r);
	struct h2d_upstream_content_ctx *ctx = h2d_upstream_content_ctx(r);

	/* increase connection's address fails */
	h2d_upstream_connection_fail(ctx->upc);

	/* retry */
	printf("retry %d %d\n", ctx->retries, upstream->max_retries);
	if (ctx->retries < 0 || ++ctx->retries >= upstream->max_retries) {
		return r->resp.status_code != 0 ? H2D_OK : WUY_HTTP_502;
	}

	h2d_request_reset_response(r);

	ctx->upc = h2d_upstream_retry_connection(ctx->upc);
	if (ctx->upc == NULL) {
		return WUY_HTTP_500;
	}
	ctx->has_sent_request = false;

	return h2d_upstream_content_generate_response_headers(r);
}

int h2d_upstream_content_generate_response_body(struct h2d_request *r,
		uint8_t *buffer, int buf_len)
{
	struct h2d_upstream_conf *upstream = h2d_upstream_content_conf(r);
	struct h2d_upstream_content_ctx *ctx = h2d_upstream_content_ctx(r);

	if (upstream->ops->is_response_body_done(r)) {
		return 0;
	}

	int read_len = h2d_upstream_connection_read(ctx->upc, buffer, buf_len);
	if (read_len < 0) {
		return read_len;
	}

	return upstream->ops->build_response_body(r, buffer, read_len, buf_len);
}

void h2d_upstream_content_ctx_free(struct h2d_request *r)
{
	struct h2d_upstream_content_ctx *ctx = h2d_upstream_content_ctx(r);
	if (ctx->upc != NULL) {
		h2d_upstream_release_connection(ctx->upc);
	}
	free(ctx->req_buf);
	free(ctx);
}

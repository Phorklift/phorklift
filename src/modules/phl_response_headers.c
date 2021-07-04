#include "phl_main.h"

struct phl_response_headers_conf {
	wuy_slist_t	*checks; /* arbitrary headers */
	bool		check_server_via;
	bool		check_date;
};

struct phl_module phl_response_headers_module;

static int phl_response_headers_response_headers(struct phl_request *r)
{
	struct phl_response_headers_conf *conf = r->conf_path->module_confs[phl_response_headers_module.index];
	wuy_slist_t *headers = &r->resp.headers;

	if (conf->check_server_via) {
		struct phl_header *h = phl_header_get(headers, "Server");
		if (h == NULL) {
			phl_header_add_lite(headers, "Server", "Phorklift", 9, r->pool);
		} else if ((h = phl_header_get(headers, "Via")) == NULL) {
			phl_header_add_lite(headers, "Via", "Phorklift", 9, r->pool);
		} else {
			// TODO append Phorklift to Via
		}
	}

	if (conf->check_date) {
		struct phl_header *h = phl_header_get(headers, "Date");
		if (h == NULL) {
			phl_header_add_lite(headers, "Date", wuy_http_date_make(time(NULL)),
					WUY_HTTP_DATE_LENGTH, r->pool);
		}
	}

	return PHL_OK;
}

/* configuration */

static const char *phl_response_headers_conf_arbitrary(lua_State *L, void *data)
{
	// TODO arbitrary headers
	return WUY_CFLUA_OK;
}

static struct wuy_cflua_command phl_response_headers_conf_commands[] = {
	{	.name = "check_server_via",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct phl_response_headers_conf, check_server_via),
		.default_value.b = true,
	},
	{	.name = "check_date",
		.type = WUY_CFLUA_TYPE_BOOLEAN,
		.offset = offsetof(struct phl_response_headers_conf, check_date),
		.default_value.b = true,
	},
	{ NULL }
};

struct phl_module phl_response_headers_module = {
	.name = "response_headers",
	.command_path = {
		.name = "response_headers",
		.description = "Set cookie ID in response header",
		.type = WUY_CFLUA_TYPE_TABLE,
		.u.table = &(struct wuy_cflua_table) {
			.commands = phl_response_headers_conf_commands,
			.size = sizeof(struct phl_response_headers_conf),
			.arbitrary = phl_response_headers_conf_arbitrary,
		}
	},

	.filters = {
		.response_headers = phl_response_headers_response_headers,
	},
};

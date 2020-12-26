#include "h2d_main.h"

void h2d_conf_doc(void)
{
	printf("# Format\n"
		"\n"
		"Command format in this document:\n"
		"\n"
		"    `name` _(type[: default_value] [min=] [max=])_\n"
		"\n"
		"Lua table supports array members and key-value map entries.\n"
		"For key-value map entries, the `name` is the key.\n"
		"And for array members, the `name` is `SINGLE_ARRAY_MEMBER` if only\n"
		"single member is accepted, or `MULTIPLE_ARRAY_MEMBER` if multiple\n"
		"members are accepted.\n"
		"\n"
		"Supported value types includes:\n"
		"\n"
		"  - table\n"
		"  - integer\n"
		"  - float\n"
		"  - string\n"
		"  - boolean\n"
		"  - function\n"
		"\n"
		"The `default_value` is showed only for non-zero value.\n"
		"\n"
		"The `min` and `max` limits are showed only if any.\n");

	printf("\n# Common component tables\n\n");

	printf("+ LOG _(table)_\n\n");
	wuy_cflua_dump_table_markdown(&h2d_log_conf_table, 1);

	printf("+ UPSTREAM _(table)_\n\n");
	printf("    Used by content modules such as proxy and redis.\n\n");
	wuy_cflua_dump_table_markdown(&h2d_upstream_conf_table, 1);

	printf("+ DYNAMIC _(table)_\n\n");
	printf("    Included by Path and UPSTREAM to enable dynamic configuration.\n\n");
	wuy_cflua_dump_table_markdown(&h2d_dynamic_conf_table, 1);

	printf("\n# Listen scope\n\n");
	printf("This is the top level scope. Accepts one or more addresses to listen on.\n\n");
	wuy_cflua_dump_table_markdown(&h2d_conf_listen_table, 0);

	printf("\n# Host scope\n\n");
	printf("Under Listen scope. Accepts one or more hostnames as virtual server.\n\n"
			"The hostname arguments may start or end with a wildcard `*`.\n"
			"Especial the \"*\" is the default Host under the Listen scope to match any request.\n"
			"Each request is matched in the order of longest match.\n\n");
	wuy_cflua_dump_table_markdown(&h2d_conf_host_table, 0);

	printf("\n# Path scope\n\n");
	printf("Under Host scope. Accepts one or more pathnames to route requests by URL.\n\n"
			"The pathname arguments may start with\n\n"
			"  - `/` means prefix-match;\n"
			"  - `=` means exact-match;\n"
			"  - `~` means regular expression match in Lua's rule.\n\n"
			"Each request is matched in the order of the Paths appearance in Host scope.\n\n");
	wuy_cflua_dump_table_markdown(&h2d_conf_path_table, 0);
}

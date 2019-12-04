extern struct h2d_module h2d_static_module;
extern struct h2d_module h2d_proxy_module;
extern struct h2d_module h2d_lua_module;
extern struct h2d_module h2d_acl_module;
extern struct h2d_module h2d_test_subreq_module;

static struct h2d_module *h2d_modules[] =
{
	&h2d_static_module,
	&h2d_proxy_module,
	&h2d_lua_module,
	&h2d_acl_module,
	&h2d_test_subreq_module,
};

#define H2D_MODULE_NUMBER (sizeof(h2d_modules) / sizeof(struct h2d_module *))

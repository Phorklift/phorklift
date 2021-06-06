#ifndef H2D_LUA_API_H
#define H2D_LUA_API_H

#include "h2d_request.h"

struct h2d_lua_api_reg_int {
	const char	*name;
	int		n;
};

struct h2d_lua_api_reg_func {
	const char	*name;
	lua_CFunction	f;
};

struct h2d_lua_api_package {
	const char		*name;
	int			*ref;
	void			(*init)(void);
	const struct h2d_lua_api_reg_int	*const_ints;
	const struct h2d_lua_api_reg_func	*funcs;
};

extern struct h2d_request *h2d_lua_api_current;

void h2d_lua_api_init(void);

#endif

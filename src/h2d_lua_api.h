#ifndef H2D_LUA_API_H
#define H2D_LUA_API_H

#include "h2d_request.h"

struct h2d_lua_api_reg {
	const char		*name;
	union {
		int		n; /* const int */
		lua_CFunction	f;
	} u;
};

struct h2d_lua_api_package {
	const char		*name;
	int			*ref;
	void			(*init)(void);
	const struct h2d_lua_api_reg	*const_ints;
	const struct h2d_lua_api_reg	*funcs;
};

extern struct h2d_request *h2d_lua_api_current;

void h2d_lua_api_init(void);

#endif

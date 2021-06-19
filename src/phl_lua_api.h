#ifndef H2D_LUA_API_H
#define H2D_LUA_API_H

#include "phl_request.h"

struct phl_lua_api_reg_int {
	const char	*name;
	int		n;
};

struct phl_lua_api_reg_func {
	const char	*name;
	lua_CFunction	f;
};

struct phl_lua_api_package {
	const char		*name;
	int			*ref;
	void			(*init)(void);
	const struct phl_lua_api_reg_int	*const_ints;
	const struct phl_lua_api_reg_func	*funcs;
};

extern struct phl_request *phl_lua_api_current;

void phl_lua_api_init(void);

#endif

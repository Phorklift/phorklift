auto_headers: h2d_conf_predefs_lua.h h2d_module_list.h h2d_loadbalance_list.h h2d_luapkg_list.h

h2d_conf_predefs_lua.h: h2d_conf_predefs.lua
	echo '/* read file h2d_conf_predefs.lua into string */' > $@
	@echo 'static const char *h2d_conf_predefs_lua_str = " \\n\\' >> $@
	@sed 's/"/\\"/g' $^ | awk '{print $$0" \\n\\"}' >> $@
	@echo '";' >> $@

h2d_module_list.h: $(wildcard modules/*.c)
	echo '#define H2D_MODULE_X_LIST \\' > $@
	@ls modules/*.c | sed 's@modules/@\tX(@' | sed 's/.c$$/_module) \\/' >> $@
	@echo >> $@

h2d_loadbalance_list.h: $(wildcard loadbalances/*.c)
	echo '#define H2D_UPSTREAM_LOADBALANCE_X_LIST \\' >> $@
	@ls loadbalances/*.c | sed 's@loadbalances/@\tX(@' | sed 's/.c$$/_loadbalance) \\/' >> $@
	@echo >> $@

h2d_luapkg_list.h: $(wildcard luaapis/*.c)
	echo '#define H2D_LUAAPI_X_LIST \\' > $@
	@ls luaapis/*.c | sed 's@luaapis/@\tX(@' | sed 's/.c$$/_package) \\/' >> $@
	@echo >> $@

clean_auto_headers:
	rm -f h2d_conf_predefs_lua.h h2d_module_list.h h2d_loadbalance_list.h h2d_luapkg_list.h

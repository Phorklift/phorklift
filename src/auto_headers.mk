phl_conf_predefs_lua.h: phl_conf_predefs.lua
	echo '/* read file phl_conf_predefs.lua into string */' > $@
	@echo 'static const char *phl_conf_predefs_lua_str = " \\n\\' >> $@
	@sed 's/"/\\"/g' $^ | awk '{print $$0" \\n\\"}' >> $@
	@echo '";' >> $@

phl_module_list.h: $(MOD_SRCS)
	echo '#define PHL_MODULE_X_LIST \\' > $@
	@ls modules/*.c | sed 's@modules/@\tX(@' | sed 's/.c$$/_module) \\/' >> $@
	@echo >> $@
	echo '#define PHL_UPSTREAM_LOADBALANCE_X_LIST \\' >> $@
	@ls loadbalances/*.c | sed 's@loadbalances/@\tX(@' | sed 's/.c$$/_loadbalance) \\/' >> $@
	@echo >> $@
	echo '#define PHL_LUAAPI_X_LIST \\' >> $@
	@ls luaapis/*.c | sed 's@luaapis/@\tX(@' | sed 's/.c$$/_package) \\/' >> $@
	@echo >> $@

clean_auto_headers:
	rm -f phl_conf_predefs_lua.h phl_module_list.h

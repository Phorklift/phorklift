CFLAGS = -g -Wall -O2
LDFLAGS = -Llibloop -Llibhttp2 -Llibwuya
LDFLAGS += -Wl,-export-dynamic # for dynamic modules
LDLIBS = -lloop -lhttp2 -lwuya -lpthread -ldl
LDLIBS += -lluajit-5.1 # use `-llua5.1` for original Lua
LDLIBS += -lssl -lcrypto

all: h2d_conf_parse_lua.h h2tpd

h2d_conf_parse_lua.h: h2d_conf_parse.lua
	echo '/* read file h2d_conf_parse.lua into string */' > $@
	@echo 'static const char *h2d_conf_parse_lua_str = " \\n\\' >> $@
	@sed 's/"/\\"/g' $^ | awk '{print $$0" \\n\\"}' >> $@
	@echo '";' >> $@

MODULES = modules/h2d_static.o modules/h2d_proxy.o modules/h2d_lua.o modules/h2d_acl.o \
	  modules/h2d_test_subreq.o modules/h2d_stats.o modules/h2d_cache.o \
	  modules/h2d_auth_basic.o modules/h2d_redis.o modules/h2d_rewrite.o \
	  modules/h2d_echo.o \
	  modules/h2d_upstream_roundrobin.o modules/h2d_upstream_hash.o

h2tpd: h2d_main.o h2d_conf.o h2d_conf_listen.o h2d_conf_host.o h2d_conf_path.o \
		h2d_ssl.o h2d_module.o h2d_http2.o h2d_http1.o h2d_connection.o \
		h2d_request.o h2d_resolver.o h2d_log.o h2d_dynamic.o \
		h2d_upstream.o h2d_upstream_resolve.o h2d_upstream_healthcheck.o \
		h2d_upstream_content.o \
		h2d_lua_api.o
	make -C modules
	$(CC) -o $@ $^ $(MODULES) $(LDFLAGS) $(LDLIBS)

clean:
	make -C modules clean
	rm -f *.o h2d_conf_parse_lua.h h2tpd

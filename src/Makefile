CFLAGS = -g -Wall -O2
LDFLAGS = -Llibloop -Llibhttp2 -Llibwuya
LDLIBS = -lloop -lhttp2 -lwuya -llua5.1 -lssl -lcrypto -lpthread

all: h2tpd

MODULES = modules/h2d_static.o modules/h2d_proxy.o modules/h2d_lua.o modules/h2d_acl.o \
	  modules/h2d_test_subreq.o modules/h2d_stats.o

h2tpd: h2d_main.o h2d_conf.o h2d_conf_listen.o h2d_conf_host.o h2d_conf_path.o \
		h2d_ssl.o h2d_module.o h2d_http2.o h2d_http1.o h2d_connection.o \
		h2d_request.o h2d_upstream.o h2d_resolver.o
	make -C modules
	$(CC) -o $@ $^ $(MODULES) $(LDFLAGS) $(LDLIBS)

clean:
	make -C modules clean
	rm -f *.o h2tpd

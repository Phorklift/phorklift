CFLAGS = -g -Wall -O2
CFLAGS += -I../ -I/usr/include/lua5.1

all: h2d_static.o h2d_proxy.o h2d_lua.o h2d_acl.o \
	h2d_stats.o h2d_file_cache.o h2d_auth_basic.o h2d_redis.o \
	h2d_rewrite.o h2d_echo.o h2d_limit_req.o h2d_gzip.o \
	h2d_auth_request.o h2d_save_to.o h2d_jump_if.o \
	h2d_upstream_roundrobin.o h2d_upstream_hash.o

clean:
	rm -f *.o

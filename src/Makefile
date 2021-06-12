CFLAGS = -g -Wall -Werror -O2
LDFLAGS = -Llibloop -Llibhttp2 -Llibwuya
LDFLAGS += -Wl,-export-dynamic # for dynamic modules
LDLIBS = -lloop -lhttp2 -lwuya -lpthread -ldl -lrt
LDLIBS += -lluajit-5.1 # use `-llua5.1` for original Lua
LDLIBS += -lssl -lcrypto
LDLIBS += -lz

all: h2d_conf_predefs_lua.h h2tpd

h2d_conf_predefs_lua.h: h2d_conf_predefs.lua
	echo '/* read file h2d_conf_predefs.lua into string */' > $@
	@echo 'static const char *h2d_conf_predefs_lua_str = " \\n\\' >> $@
	@sed 's/"/\\"/g' $^ | awk '{print $$0" \\n\\"}' >> $@
	@echo '";' >> $@

SOURCES = $(wildcard *.c)
OBJECTS = $(patsubst %.c,%.o,$(SOURCES))

MOD_SRCS = $(wildcard modules/*.c luaapis/*.c)
MOD_OBJS = $(patsubst %.c,%.o,$(MOD_SRCS))

h2tpd: $(OBJECTS)
	make -C modules
	make -C luaapis
	$(CC) -o $@ $^ $(MOD_OBJS) $(LDFLAGS) $(LDLIBS)

clean:
	make -C modules clean
	make -C luaapis clean
	rm -f *.o h2d_conf_parse_lua.h h2tpd depends

depends:
	$(CC) -MM *.c > depends

include depends

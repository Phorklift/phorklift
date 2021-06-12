CFLAGS = -g -Wall -Werror -O2
LDFLAGS = -Llibloop -Llibhttp2 -Llibwuya
LDFLAGS += -Wl,-export-dynamic # for dynamic modules
LDLIBS = -lloop -lhttp2 -lwuya -lpthread -ldl -lrt
LDLIBS += -lluajit-5.1 # use `-llua5.1` for original Lua
LDLIBS += -lssl -lcrypto
LDLIBS += -lz

SOURCES = $(wildcard *.c)
OBJECTS = $(patsubst %.c,%.o,$(SOURCES))

MOD_SRCS = $(wildcard modules/*.c luaapis/*.c)
MOD_OBJS = $(patsubst %.c,%.o,$(MOD_SRCS))

all: auto_headers h2tpd

include auto_headers.mk

h2tpd: $(OBJECTS)
	make -C modules
	make -C luaapis
	$(CC) -o $@ $^ $(MOD_OBJS) $(LDFLAGS) $(LDLIBS)

clean:
	make -C modules clean
	make -C luaapis clean
	make clean_auto_headers
	rm -f *.o h2tpd

# Because some header files are automaticly generated,
# `$(CC) -MM *.c` can not be used to generate dependence.
# If you change some header files, remember to run `make clean`.

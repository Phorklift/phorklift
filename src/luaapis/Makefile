CFLAGS = -g -Wall -O2
CFLAGS += -I../ -I/usr/include/lua5.1

SOURCES = $(wildcard *.c)
OBJECTS = $(patsubst %.c,%.o,$(SOURCES))

all: $(OBJECTS)

clean:
	rm -f *.o

depends:
	$(CC) $(CFLAGS) -MM *.c > depends

include depends

.PHONY: all
all: driver

CC       := gcc
# _GNU_SOURCE is required to make libpcap work with -std=c99
# and for strndup(3)
CFLAGS   := -std=c99 -Wall -Wextra -g -O0 -D_GNU_SOURCE
SOFLAGS  := -fPIC
CINCLUDE := 
CLIBS    := -lnl -lnl-genl -lnl-route

LIBBASE = libairpcap-nl.so
LIBVERSHORT = 4
LIBVERLONG  = 4.1.1.0
LIB = $(LIBBASE).$(LIBVERLONG)
LIBSHORT = $(LIBBASE).$(LIBVERSHORT)

driver: driver.c $(LIBSHORT)
	$(CC) $(CFLAGS) -I/usr/include/pcap driver.c $(LIBSHORT) -o driver -lpcap

.PHONY: library
library: $(LIB)

$(LIB) $(LIBSHORT): airpcap-nl.o
	$(CC) -shared $(SOFLAGS) -Wl,-soname,$(LIBSHORT) \
		-o $(LIB) $(CLIBS) airpcap-nl.o
	ln -sf $(LIB) $(LIBSHORT)

# util.o: util.c
# 	$(CC) -c $(CFLAGS) $(SOFLAGS) -o util.o util.c

airpcap-nl.o: airpcap-nl.c airpcap.h airpcap-nl.h airpcap-types.h
	$(CC) -c $(CFLAGS) $(SOFLAGS) -o airpcap-nl.o airpcap-nl.c

.PHONY: clean
clean:
	rm -vf driver *.o *.so *.so*

PREFIX ?= /usr/local

# I'm assuming most Linux systems have the "new" statx call now,
# https://www.man7.org/linux/man-pages/man2/statx.2.html
# but if you're compiling on Linux and get errors about statx
# set HAVE_STATX = 0
HAVE_STATX = 1

all: libsfakeroot.so sfakeroot

CC=gcc
CFLAGS=-Wall -Wextra -pedantic -std=c99 -D_DEFAULT_SOURCE -DSFAKEROOT_LIBDIR=\"$(DESTDIR)$(PREFIX)/lib\" -D_GNU_SOURCE -DHAVE_STATX=$(HAVE_STATX) -g
LDFLAGS=-L .

libsfakeroot.o: libsfakeroot.c
	$(CC) -c -fPIC $(CFLAGS) -o $@ libsfakeroot.c

strlcpy.o: strlcpy.c
	$(CC) -c -fPIC $(CFLAGS) -o $@ strlcpy.c

libsfakeroot.so: libsfakeroot.o strlcpy.o
	$(CC) -fPIC $(CFLAGS) $(LDFLAGS) -shared -o $@ libsfakeroot.o strlcpy.o

sfakeroot: sfakeroot.o strlcpy.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ sfakeroot.o strlcpy.o

sfakeroot.o: sfakeroot.c sfakeroot.h

install:
	install sfakeroot $(DESTDIR)$(PREFIX)/bin
	install libsfakeroot.so $(DESTDIR)$(PREFIX)/lib
	install *.1 $(DESTDIR)$(PREFIX)/man/man1/

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/sfakeroot
	rm -f $(DESTDIR)$(PREFIX)/lib/libsfakeroot.so
	rm -f $(DESTDIR)$(PREFIX)/man/man1/sfakeroot.1

clean:
	rm -f *.o *.so sfakeroot

.PHONY: all clean install uninstall

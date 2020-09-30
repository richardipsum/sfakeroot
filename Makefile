PREFIX ?= /usr/local

all: libsfakeroot.so sfakeroot

CFLAGS=-Wall -Wextra -Werror -pedantic -std=c99 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -D_BSD_SOURCE -DSFAKEROOT_LIBDIR=\"$(DESTDIR)$(PREFIX)/lib\"
LDFLAGS=-L .

libsfakeroot.o: libsfakeroot.c
	$(CC) -c -fPIC $(CFLAGS) -o $@ libsfakeroot.c

strlcpy.o: strlcpy.c
	$(CC) -c -fPIC $(CFLAGS) -o $@ strlcpy.c

libsfakeroot.so: libsfakeroot.o strlcpy.o
	$(CC) -fPIC $(CFLAGS) $(LDFLAGS) -shared -o $@ libsfakeroot.o strlcpy.o

sfakeroot: sfakeroot.o strlcpy.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ sfakeroot.o strlcpy.o -l sfakeroot

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

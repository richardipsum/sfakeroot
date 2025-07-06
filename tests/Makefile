# I'm assuming most Linux systems have the "new" statx call now,
# https://www.man7.org/linux/man-pages/man2/statx.2.html
# but if you're compiling on Linux and get errors about statx
# set HAVE_STATX = 0
HAVE_STATX = 1

CFLAGS=-Wall -Wextra -pedantic -std=c99 -D_POSIX_C_SOURCE=200809L -DHAVE_STATX=$(HAVE_STATX) -D_GNU_SOURCE

BIN=chown lchown chmod stat lstat fstat fstatat fchown fchownat statx

all: $(BIN)

clean:
	rm -f $(BIN)
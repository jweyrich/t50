# __HAVE_TURBO__ - turbo mode enable --turbo option. This makes
# T50 create a child process to improve performance.
#
# __HAVE_DEBUG__ - debug mode makes T50 print the source filename
# and line when an error occurs. This is a good idea if you're
# experiencing problems.
	
PREFIX=/usr
MANDIR=/usr/share/man/man8
SRCDIR=./src
DOCDIR=./doc

# NOTE: Now llvm's clang 3.x works fine!
CC=gcc
#CC=clang

# If you want to use SSE instructions on x86 architecture, remove the comment below.
# There is no need to enable SSE for x86-64 architecture.
#USE_SSE=-msse -mfpmath=sse

STRIP=-s
CFLAGS=-W -std=gnu99 -Wall -Wextra -mtune=native -O3 $(USE_SSE) -ffast-math $(STRIP)
INCLUDES=-I$(SRCDIR)/include
DFLAGS=-D__HAVE_TURBO__ -DVERSION=\"5.5\"

# If you want debug info on executable, remove the comment below (and comment NDEBUG definition)
#DFLAGS+=-D__HAVE_DEBUG__
DFLAGS+=-DNDEBUG

SRC=$(shell find $(SRCDIR) -type f -name '*.c')
	
all:
	$(CC) $(CFLAGS) $(INCLUDES) $(DFLAGS) $(SRC) -o t50
	gzip -c -9 $(DOCDIR)/t50.1 > $(DOCDIR)/t50.8.gz

#debug:
#	$(CC) $(CFLAGS) $(INCLUDES) $(DFLAGS) -masm=intel -fverbose-asm -S $(SRC)
	
clean:
	rm -f t50 doc/t50.8.gz
	
install: 
	install t50 $(PREFIX)/sbin
	install $(DOCDIR)/t50.8.gz $(MANDIR)/t50.8.gz
	
uninstall:
	rm -f $(PREFIX)/sbin/t50 $(MANDIR)/t50.8.gz

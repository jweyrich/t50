#
# Variables that can be defined in DFLAGS, below.
#
# __HAVE_TURBO__ - turbo mode enable --turbo option. This makes
# T50 create a child process to improve performance.
#
# __HAVE_DEBUG__ - debug mode makes T50 print the source filename
# and line when an error occurs. This is a good idea if you're
# experiencing problems. It is proper to undefine NDEBUG.
#

SRC_DIR=./src
OBJ_DIR=./build
RELEASE_DIR=./release
MAN_DIR=/usr/share/man/man8
INCLUDE_DIR=$(SRC_DIR)/include

TARGET=$(RELEASE_DIR)/t50

OBJS=$(OBJ_DIR)/modules/ip.o \
$(OBJ_DIR)/modules/igmpv3.o \
$(OBJ_DIR)/modules/dccp.o \
$(OBJ_DIR)/modules/ripv2.o \
$(OBJ_DIR)/modules/udp.o \
$(OBJ_DIR)/modules/tcp.o \
$(OBJ_DIR)/modules/ospf.o \
$(OBJ_DIR)/modules/ripv1.o \
$(OBJ_DIR)/modules/egp.o \
$(OBJ_DIR)/modules/rsvp.o \
$(OBJ_DIR)/modules/ipsec.o \
$(OBJ_DIR)/modules/eigrp.o \
$(OBJ_DIR)/modules/gre.o \
$(OBJ_DIR)/modules/igmpv1.o \
$(OBJ_DIR)/modules/icmp.o \
$(OBJ_DIR)/common.o \
$(OBJ_DIR)/cksum.o \
$(OBJ_DIR)/cidr.o \
$(OBJ_DIR)/t50.o \
$(OBJ_DIR)/resolv.o \
$(OBJ_DIR)/sock.o \
$(OBJ_DIR)/usage.o \
$(OBJ_DIR)/config.o \
$(OBJ_DIR)/check.o

# Get architecture
ARCH=$(shell arch)
ifeq ($(ARCH),x86_64)
	ADDITIONAL_COPTS=
else
	ADDITIONAL_COPTS=-msse
endif

# OBS: Using Linker Time Optiomizer!
#      -O3 and -fuse-linker-plugin needed on link time to use lto.
CC=gcc
DFLAGS=-D__HAVE_TURBO__ -DVERSION=\"5.5\" -DNDEBUG
COPTS=-Wall -Wextra -mtune=native -flto $(ADDITIONAL_COPTS) -O3 -ffast-math -I$(INCLUDE_DIR) $(DFLAGS)
LDOPTS=-s -O3 -fuse-linker-plugin -flto

.PHONY: clean install

# link

$(TARGET): $(OBJS)
	$(CC) $(LDOPTS) $^ -o $@

# Compile main
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(COPTS) $(DFLAGS) -c -o $@ $<

# Compile modules
$(OBJ_DIR)/modules/%.o: $(SRC_DIR)/modules/%.c
	$(CC) $(COPTS) $(DFLAGS) -c -o $@ $<

clean:
	@rm -rf $(RELEASE_DIR)/* $(OBJ_DIR)/*.o $(OBJ_DIR)/modules/*.o
	@echo Binary executable, temporary files and packed manual file deleted.

install:
	gzip -9 $(RELEASE_DIR)/t50.8.gz ./doc/t50.1
	install $(RELEASE_DIR)/t50 /usr/sbin/
	install $(RELEASE_DIR)/t50.8.gz $(MAN_DIR)/

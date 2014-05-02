#
# if DEBUG is defined on make call (ex: make DEBUG=1), then compile with
# __HAVE_DEBUG__ defined, asserts and debug information.
#
# Delete __HAVE_TURBO__ definition, below, if you don't need it.
#
# The final executable will be created at release/ sub-directory.
#

define checkroot()
	@test $$(id -u) -ne 0 && ( echo 'Need root priviledge'; exit 1 )
endef

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
$(OBJ_DIR)/check.o \
$(OBJ_DIR)/modules.o \
$(OBJ_DIR)/help/general_help.o \
$(OBJ_DIR)/help/gre_help.o \
$(OBJ_DIR)/help/tcp_udp_dccp_help.o \
$(OBJ_DIR)/help/ip_help.o \
$(OBJ_DIR)/help/icmp_help.o \
$(OBJ_DIR)/help/egp_help.o \
$(OBJ_DIR)/help/rip_help.o \
$(OBJ_DIR)/help/rsvp_help.o \
$(OBJ_DIR)/help/ipsec_help.o \
$(OBJ_DIR)/help/eigrp_help.o \
$(OBJ_DIR)/help/ospf_help.o

# OBS: Using Linker Time Optiomizer!
#      -O3 and -fuse-linker-plugin needed on link time to use lto.
CC=gcc
DFLAGS=-DVERSION=\"5.5\"

#
# You can define DEBUG if you want to use GDB. 
#
CFLAGS=-Wall -Wextra -I$(INCLUDE_DIR) -std=gnu99
LDFLAGS=-lpthread
ifdef DEBUG
	CFLAGS+=-O0
	DFLAGS+=-D__HAVE_DEBUG__ -g
else
	CFLAGS+=-O3 -mtune=native -flto -ffast-math -fomit-frame-pointer

	# Get architecture
	ARCH=$(shell arch)
	ifneq ($(ARCH),x86_64)
		CFLAGS+=-msse -mfpmath=sse		
	endif

  DFLAGS+=-DNDEBUG
	LDFLAGS+=-s -O3 -fuse-linker-plugin -flto
endif
CFLAGS+=$(DFLAGS)

.PHONY: all clean install uninstall

all: $(TARGET)

# link
$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $^ -o $@

# Compile main
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Compile Help
$(OBJ_DIR)/help/%.o: $(SRC_DIR)/help/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Compile modules
$(OBJ_DIR)/modules/%.o: $(SRC_DIR)/modules/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	@rm -rf $(RELEASE_DIR)/t50 $(OBJ_DIR)/*.o $(OBJ_DIR)/modules/*.o $(OBJ_DIR)/help/*.o
	@echo Binary executable, temporary files and packed manual file deleted.

install:
	$(checkroot)
	gzip -9c ./doc/t50.8 > $(RELEASE_DIR)/t50.8.gz
	install $(RELEASE_DIR)/t50 /usr/sbin/
	install -m 0644 $(RELEASE_DIR)/t50.8.gz $(MAN_DIR)/

uninstall:
	$(checkroot)
	rm -f $(MAN_DIR)/t50.8.gz /usr/sbin/t50

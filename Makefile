#
# if DEBUG is defined on make call (ex: make DEBUG=1), then compile with
# __HAVE_DEBUG__ defined, asserts and debug information.
#
# Delete __HAVE_TURBO__ definition, below, if you don't need it.
#
# The final executable will be created at release/ sub-directory.
#

.PHONY: all doxygen distclean clean install uninstall

INSTALLPROG = /usr/bin/install

# Define this variable if you really want to use RDRAND instruction, if present.
# This can make T50 to be SLOW... But the RNG is accurate...
#USE_RDRAND=1

#
# T50 directories structure:
# .
# ├── build
# │   ├── help
# │   └── modules
# ├── doc
# ├── release
# └── src
#     ├── help
#     ├── include
#     │   └── protocol
#     └── modules
#
SRC_DIR = ./src
OBJ_DIR = ./build
RELEASE_DIR = ./release
MAN_DIR = /usr/share/man/man8
INCLUDE_DIR = $(SRC_DIR)/include
SBIN_DIR = /usr/sbin

# 't50' executable is our target!
TARGET = $(RELEASE_DIR)/t50

OBJS = $(OBJ_DIR)/modules/ip.o \
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
$(OBJ_DIR)/main.o \
$(OBJ_DIR)/resolv.o \
$(OBJ_DIR)/sock.o \
$(OBJ_DIR)/usage.o \
$(OBJ_DIR)/config.o \
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

DEPS = $(SRC_DIR)/include/config.h \
$(SRC_DIR)/include/common.h \
$(SRC_DIR)/include/protocol/eigrp.h \
$(SRC_DIR)/include/protocol/gre.h \
$(SRC_DIR)/include/protocol/egp.h \
$(SRC_DIR)/include/protocol/ip.h \
$(SRC_DIR)/include/protocol/igmp.h \
$(SRC_DIR)/include/protocol/tcp_options.h \
$(SRC_DIR)/include/protocol/rsvp.h \
$(SRC_DIR)/include/protocol/rip.h \
$(SRC_DIR)/include/protocol/ospf.h \
$(SRC_DIR)/include/typedefs.h \
$(SRC_DIR)/include/help.h \
$(SRC_DIR)/include/defines.h \
$(SRC_DIR)/include/modules.h

#--- This will give us a lot of warnings. Useful to check if the code is alright (not quite!). Use carefully!
#--- As seen on OWASP cheat sheet!
#EXTRA_WARNINGS=-Wsign-conversion -Wcast-align -Wformat=2 -Wformat-security -fno-common -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes -Wstrict-overflow -Wtrampolines

CFLAGS = -I$(INCLUDE_DIR) -std=gnu99 -Wall -Wextra $(EXTRA_WARNINGS) 
LDFLAGS = 

#
# You can define DEBUG if you want to use GDB. 
#
ifdef DEBUG
  CFLAGS += -g -O0 -D__HAVE_DEBUG__
#
# Define DUMP_DATA if you want to view a big log file...
#

# CFLAGS +=  -DDUMP_DATA -g
else
  CFLAGS += -O2 -mtune=native -flto -fomit-frame-pointer -ffast-math -DNDEBUG -D__HAVE_TURBO__

	# Get architecture
  ARCH = $(shell arch)
  ifneq ($(ARCH),x86_64)
    CFLAGS += -msse -mfpmath=sse
  endif

  LDFLAGS += -s -O3 -fuse-linker-plugin -flto

  # FIX: BMI2 isn't very useful for us, but MOVBE is!
  ifeq ($(shell grep movbe /proc/cpuinfo 2>&1 > /dev/null; echo $$?), 0)
    CFLAGS += -mmovbe
  endif
endif

all: $(TARGET)

# link
$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

# Compile main
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

# Compile Help
$(OBJ_DIR)/help/%.o: $(SRC_DIR)/help/%.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

# Compile modules
$(OBJ_DIR)/modules/%.o: $(SRC_DIR)/modules/%.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

doxygen:
	doxygen

distclean: clean
	-if [ -f $(RELEASE_DIR)/t50.8.gz ]; then rm $(RELEASE_DIR)/t50.8.gz; fi
	-if [ -f $(RELEASE_DIR)/t50 ]; then rm $(RELEASE_DIR)/t50; fi
	-if [ -d doc/html ]; then rm -rf doc/html; fi
	-if [ -d doc/latex ]; then rm -rf doc/latex; fi
	-if [ -f doc/doxy*.db ]; then rm -f doc/doxy*.db; fi

clean:
	-rm $(OBJS)

install:
	@[ "`id -u`" -ne 0 ] && ( echo "Need root privilege"; exit 1 )
	@gzip -9c doc/t50.8 > $(RELEASE_DIR)/t50.8.gz
	$(INSTALLPROG) $(RELEASE_DIR)/t50 $(SBIN_DIR)/
	$(INSTALLPROG) -m 0644 $(RELEASE_DIR)/t50.8.gz $(MAN_DIR)/

uninstall:
	@[ "`id -u`" -ne 0 ] && ( echo "Need root privilege"; exit 1 )
	-rm -f $(MAN_DIR)/t50.8.gz $(SBIN_DIR)/t50

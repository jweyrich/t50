#
# T50 Build System Configuration File.
#
AC_PREREQ([2.69])

define([VERSION_MAJOR], [5])
define([VERSION_MINOR], [7])
define([VERSION_FIX],   [0])
define([VERSION_NUMBER], VERSION_MAJOR[.]VERSION_MINOR[.]VERSION_FIX) 
define([T50_GROUP], [t50-dev@googlegroups.com])

AC_INIT([t50],[VERSION_NUMBER],[T50_GROUP],[],[https://github.com/fredericopissarra/t50.git])

AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_AUX_DIR([build])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([src/include/configuration.h])
AM_INIT_AUTOMAKE([foreign subdir-objects])

#AC_CANONICAL_HOST

# define default CFLAGS
AC_SUBST([CFLAGS],[])

# Use specific compilation flags for debug or release mode.
AC_ARG_ENABLE([debug],
  AS_HELP_STRING([--enable-debug], [Enable T50 debug information]),
  [AM_CFLAGS="-O0 -g -D__HAVE_DEBUG__"],
  [AM_CFLAGS="-O2 -s -DNDEBUG -fno-stack-protector"])

# Use -march=native only if is safe.
AX_GCC_ARCHFLAG([yes],
                [AM_CFLAGS+=" -march=native"],
                [AM_CFLAGS+=" -mtune=native"])

AC_ARG_ENABLE([ansi],
  AS_HELP_STRING([--enable-ansi], [Enable ANSI codes on T50 messages]),
  [AM_CFLAGS+=" -DUSE_ANSI"],[])

AC_PROG_CC
AC_PROG_CC_C_O
AC_C_STRINGIZE
AC_C_INLINE
AC_C_RESTRICT
AX_C___ATTRIBUTE__

AX_CHECK_COMPILE_FLAG([-std=gnu11],[AM_CFLAGS+="-std=gnu11"],[
	echo "GNU C11 standard not supported? Aborting..."
	exit 1
])

AC_PROG_INSTALL

# Define T50 compiler definitions
AC_DEFINE([__HAVE_TURBO__],[1],[Use fork to spawn extra process])

AC_CHECK_HEADERS(
  [arpa/inet.h 
   fcntl.h 
   inttypes.h 
   limits.h 
   netdb.h 
   netinet/in.h 
   stddef.h 
   stdint.h 
   stdlib.h 
   string.h 
   sys/socket.h 
   sys/time.h 
   unistd.h])

AC_CHECK_HEADER_STDBOOL

AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_REALLOC
# FIXME: regcomp() will vanish, later!
AC_CHECK_FUNCS([alarm regcomp socket strcasecmp strchr strdup strerror strpbrk strtoul])

AC_CONFIG_FILES([Makefile src/Makefile])

AC_SUBST([AM_CFLAGS])

AC_OUTPUT

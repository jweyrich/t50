/*
 *  T50 - Experimental Mixed Packet Injector
 *
 *  Copyright (C) 2010 - 2014 - T50 developers
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __DEFINES_INCLUDED__
#define __DEFINES_INCLUDED__

/** @def PACKAGE Defines the project name. */
#define PACKAGE "T50"

/** @def VERSION Defines the T50 current version. */
#define VERSION "5.5"
#define SITE    "http://github.com/fredericopissarra/t50"

/* NOTE: Used to set/reset individual bits */
#define TRUE  1
#define FALSE 0
#define ON    1
#define OFF   0

/* Initial packet buffer preallocated size (2 kB).
   This size should be sufficient for all packets since MTU
   is 1500 bytes maximum, over ethernet! */
#define INITIAL_PACKET_SIZE 2048

/* #define RAND_MAX 2147483647 */ /* NOTE: Already defined @ stdlib.h */
#define CIDR_MINIMUM 8
#define CIDR_MAXIMUM 32 // fix #7

/** @def MAXIMUM_IP_ADDRESSES
 *  MAXIMUM_IP_ADDRESSES defines the maximum number of iterations on
    main loop, for multiple targets (defined by cidr). */
/* 24 bits?! */
/* FIX: Changed to hexadecimal 'cause is easier to debug. */
#define MAXIMUM_IP_ADDRESSES  0xffffffU

/* #define INADDR_ANY 0 */ /* NOTE: Already defined @ linux/in.h */
#define IPPORT_ANY 0

/* Global common protocol definitions used by code */
#define AUTH_TYPE_HMACNUL 0x0000
#define AUTH_TYPE_HMACMD5 0x0002
#define AUTH_TLEN_HMACMD5 16

#define auth_hmac_md5_len(foo) ((foo) ? AUTH_TLEN_HMACMD5 : 0)

/** @def IPPROTO_T50 This is our new ficticious protocol. */
#define IPPROTO_T50        69
#define FIELD_MUST_BE_NULL NULL
#define FIELD_MUST_BE_ZERO 0

/** @def TEST_BITS Macro used to isolate bits from a value. */
#define TEST_BITS(x,bits) ((x) & (bits))

/** 
 * @def RANDOM Macro used to get random value.
 * @def SRANDOM Macro used to initialize random seed on LCPNG. */
#ifdef __HAVE_RDRAND__
#define RANDOM() readrand()
#define SRANDOM(x) {}
#else
#define RANDOM() random()
#define SRANDOM(x) { srandom((x)); }
#endif

/** @def __RND Macro used to conditionally generate a random value. */
#define __RND(foo) (((foo) == 0) ? RANDOM() : (foo))
#define INADDR_RND(foo) __RND((foo))
#define IPPORT_RND(foo) __RND((foo))

/* Used to test if "pid" from fork() is from a child process. */
#define IS_CHILD_PID(p) ((p) == 0)

#endif

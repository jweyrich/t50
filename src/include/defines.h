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

#define PACKAGE "T50"
#define SITE "http://github.com/fredericopissarra/t50"

/* NOTE: Used to set/reset individual bits */
#define TRUE  1
#define FALSE 0
#define ON    1
#define OFF   0

/* #define RAND_MAX 2147483647 */ /* NOTE: Already defined @ stdlib.h */
#define CIDR_MINIMUM 8
#define CIDR_MAXIMUM 32 // fix #7

/* 24 bits?! */
#define MAXIMUM_IP_ADDRESSES  16777215

/* #define INADDR_ANY 0 */ /* NOTE: Already defined @ linux/in.h */
#define IPPORT_ANY 0

/* Global common protocol definitions used by code */
#define AUTH_TYPE_HMACNUL 0x0000
#define AUTH_TYPE_HMACMD5 0x0002
#define AUTH_TLEN_HMACMD5 16
#define AUTH_TLEN_HMACMD5 16
#define auth_hmac_md5_len(foo) ((foo) ? AUTH_TLEN_HMACMD5 : 0)

/* #define IPVERSION 4 */ /* NOTE: Already defined in netinet/in.h. */

/* NOTE: Both IP_MF & IP_DF are defined in netinet/ip.h. 
         But, since we are using linux/ip.h, they are needed here. */
#define IP_MF 0x2000
#define IP_DF 0x4000

/* T50 DEFINITIONS. */
#define IPPROTO_T50        69
#define FIELD_MUST_BE_NULL NULL
#define FIELD_MUST_BE_ZERO 0

/* NOTE: This will do nothing. Used only to prevent warnings. */
#define UNUSED_PARAM(x) { (x) = (x); }

/* NOTE: Macro used to test bitmasks */
#define TEST_BITS(x,bits) ((x) & (bits))

/* Randomizer macros and function */
#define __RND(foo) (((foo) == 0) ? random() : (foo))
#define INADDR_RND(foo) __RND((foo))
#define IPPORT_RND(foo) __RND((foo))

/* ERROR macro */
#ifdef __HAVE_DEBUG__
#define ERROR(s) fprintf(stderr, "%s: %s at %s, line %d\n", PACKAGE, s, __FILE__, __LINE__);
#else
#define ERROR(s) fprintf(stderr, "%s: %s\n", PACKAGE, s);
#endif

/* Used to test if "pid" from fork() is from a child process. */
#define IS_CHILD_PID(p) ((p) == 0)

#endif


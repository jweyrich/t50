/* vim: set ts=2 et sw=2 : */
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

#ifndef __NETIO_H__
#define __NETIO_H__

#include <stddef.h>
#include <netinet/in.h>
#include <t50_typedefs.h>
#include <t50_config.h>

typedef int socket_t;

/* Common routines used by code */
in_addr_t    resolv(char *);         /* Resolve name to ip address. */
void         create_socket(void);    /* Creates the sending socket */
void         close_socket(void);     /* Close the previously created socket */

/* Send the actual packet from buffer, with size bytes, using config options. */
_Bool send_packet(const void *const,
                  size_t,
                  const struct config_options *const __restrict__);

#endif

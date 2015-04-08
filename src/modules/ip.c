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

#include <common.h>

#ifdef DUMP_DATA
  extern FILE *fdebug;
#endif

struct iphdr *ip_header(void *buffer, size_t packet_size, const struct config_options *co)
{
  struct iphdr *ip;

  assert(buffer != NULL);
  assert(co != NULL);

  ip = buffer;
  ip->version  = IPVERSION;
  ip->ihl      = sizeof(struct iphdr) / 4;
  ip->tos      = co->ip.tos;
  ip->frag_off = htons(co->ip.frag_off ? (co->ip.frag_off >> 3) | IP_MF : co->ip.frag_off | IP_DF);
  ip->tot_len  = htons(packet_size);
  ip->id       = htons(__RND(co->ip.id));
  ip->ttl      = co->ip.ttl;
  ip->protocol = co->encapsulated ? IPPROTO_GRE : co->ip.protocol;
  ip->saddr    = INADDR_RND(co->ip.saddr);
  ip->daddr    = co->ip.daddr;
  /* The code does not have to handle the checksum. Kernel will do */
  ip->check    = 0;

#ifdef DUMP_DATA
  dump_ip(fdebug, ip);
#endif

  return ip;
}

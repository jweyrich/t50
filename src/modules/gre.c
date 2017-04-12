/* vim: set ts=2 et sw=2 : */
/** @file gre.c */
/*
 *  T50 - Experimental Mixed Packet Injector
 *
 *  Copyright (C) 2010 - 2015 - T50 developers
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

#include <assert.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <t50_defines.h>
#include <t50_config.h>
#include <t50_cksum.h>
#include <t50_modules.h>
#include <t50_randomizer.h>

/**
 * GRE encapsulation routine.
 *
 * @param buffer Pointer to the begining of the packet buffer.
 * @param co Pointer to T50 configuration structure.
 * @param total_len Length of the buffer.
 * @return Pointer to IP header (the begining of the buffer).
 */
struct iphdr *gre_encapsulation(void *buffer,
                                const struct config_options *const __restrict__ co,
                                uint32_t total_len)
{
  struct iphdr   *ip, *gre_ip;
  struct gre_hdr *gre;
  void           *ptr;

  assert(buffer != NULL);
  assert(co != NULL);

  if (!co->encapsulated)
    return NULL;

  ip = buffer;

  /* GRE Header structure. */
  /*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |C|R|K|S|s|Recur|  Flags  | Ver |         Protocol Type         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Checksum (optional)      |       Offset (optional)       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Key (optional)                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Sequence Number (optional)                 |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Routing (optional)
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  */

  gre          = (struct gre_hdr *)(ip + 1);
  gre->C       = co->gre.C;
  gre->K       = co->gre.K;
  gre->R       = FIELD_MUST_BE_ZERO;
  gre->S       = co->gre.S;
  gre->s       = FIELD_MUST_BE_ZERO;
  gre->recur   = FIELD_MUST_BE_ZERO;
  gre->version = GREVERSION;
  gre->flags   = FIELD_MUST_BE_ZERO;
  gre->proto   = htons(ETH_P_IP);

  /* Computing the GRE offset. */
  ptr  = gre + 1;

  /* GRE CHECKSUM? */
  if (co->gre.C)
  {
    /* GRE CHECKSUM Header structure making a pointer to IP Header structure. */
    struct gre_sum_hdr *gre_sum = ptr;

    gre_sum->offset = FIELD_MUST_BE_ZERO;
    gre_sum->check  = 0;

    ptr = gre_sum + 1;
  }

  /* GRE KEY? */
  if (co->gre.K)
  {
    /* GRE KEY Header structure making a pointer to IP Header structure. */
    struct gre_key_hdr *gre_key = ptr;

    gre_key->key = htonl(__RND(co->gre.key));

    ptr = gre_key + 1;
  }

  /* GRE SEQUENCE? */
  if (co->gre.S)
  {
    /* GRE SEQUENCE Header structure making a pointer to IP Header structure. */
    struct gre_seq_hdr *gre_seq = ptr;

    gre_seq->sequence = htonl(__RND(co->gre.sequence));

    ptr = gre_seq + 1;
  }

  /*
   * Generic Routing Encapsulation over IPv4 networks (RFC 1702)
   *
   * IP as both delivery and payload protocol
   *
   * When IP is encapsulated in IP,  the TTL, TOS,  and IP security options
   * MAY  be  copied from the payload packet into the same  fields  in  the
   * delivery packet. The payload packet's TTL MUST be decremented when the
   * packet is decapsulated to insure that no packet lives forever.
   */
  /* GRE Encapsulated IP Header structure making a pointer to to IP Header structure. */
  gre_ip           = ptr;
  gre_ip->version  = ip->version;
  gre_ip->ihl      = ip->ihl;
  gre_ip->tos      = ip->tos;
  gre_ip->frag_off = ip->frag_off;
  gre_ip->tot_len  = htons(total_len);
  gre_ip->id       = ip->id;
  gre_ip->ttl      = ip->ttl;
  gre_ip->protocol = co->ip.protocol;
  gre_ip->saddr    = co->gre.saddr ? co->gre.saddr : ip->saddr;
  gre_ip->daddr    = co->gre.daddr ? co->gre.daddr : ip->daddr;

  /* Computing the checksum. */
  gre_ip->check    = co->bogus_csum ? RANDOM() :
                     cksum(gre_ip, sizeof(struct iphdr));

  return gre_ip;
}

/**
 * Calculates GRE checksum.
 *
 * @param buffer Pointer to the begining of packet buffer.
 * @param co Pointer to T50 configuration structure.
 * @packet_size Size of the packet.
 */
void gre_checksum(void *buffer,
                  const struct config_options *__restrict__ co,
                  size_t packet_size)
{
  struct gre_hdr     *gre;
  struct gre_sum_hdr *gre_sum;

  assert(buffer != NULL);
  assert(co != NULL);

  /* GRE Encapsulation takes place. */
  if (co->encapsulated && co->gre.C)
  {
    gre = (struct gre_hdr *)((struct iphdr *)buffer + 1);
    gre_sum = (struct gre_sum_hdr *)(gre + 1);

    /* Computing the checksum. */
    gre_sum->check  = co->bogus_csum ?
                      RANDOM() :
                      cksum(gre, packet_size - sizeof(struct iphdr)); // All packet, except the main IP header.
  }
}

/* GRE header size calculation. */
size_t gre_opt_len(const struct config_options *const __restrict__ co)
{
  size_t size;

  /*
   * The code starts with size '0' and it accumulates all the required
   * size if the conditionals match. Otherwise, it returns size '0'.
   */
  size = 0;

  /*
   * Returns the size of the entire  GRE  packet  only in the case  of
   * encapsulation has been defined ('--encapsulated').
   */
  if (co->encapsulated)
  {
    /*
     * First thing is to accumulate GRE Header size.
     * And the extra IP header size.
     */
    size = sizeof(struct gre_hdr) + sizeof(struct iphdr);

    /*
     * Checking whether add OPTIONAL header size.
     *
     * CHECKSUM HEADER?
     */
    if (co->gre.C)
      size += GRE_OPTLEN_CHECKSUM;

    /* KEY HEADER? */
    if (co->gre.K)
      size += GRE_OPTLEN_KEY;

    /* SEQUENCE HEADER? */
    if (co->gre.S)
      size += GRE_OPTLEN_SEQUENCE;
  }

  return size;
}


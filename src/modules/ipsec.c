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

/* Function Name: IPSec packet header configuration.

Description:   This function configures and sends the IPSec packet header.

Targets:       N/A */
int ipsec(const socket_t fd, const struct config_options *o)
{
  size_t greoptlen,   /* GRE options size. */
         ip_ah_icv,   /* IPSec AH Integrity Check Value (ICV). */
         esp_data,    /* IPSec ESP Data Encrypted (RANDOM). */
         packet_size,
         offset,
         counter;

  /* Packet. */
  mptr_t buffer;

  /* Socket address, IP header and IPSec AH header. */
  struct sockaddr_in sin;
  struct iphdr * ip;

  /* IPSec AH header and IPSec ESP Header. */
  struct ip_auth_hdr * ip_auth;
  struct ip_esp_hdr * ip_esp;

  assert(o != NULL);

  greoptlen = gre_opt_len(o->gre.options, o->encapsulated);
  ip_ah_icv = sizeof(uint32_t) * 3;
  esp_data  = auth_hmac_md5_len(1);
  packet_size = sizeof(struct iphdr) + 
    greoptlen                  + 
    sizeof(struct ip_auth_hdr) + 
    ip_ah_icv                  +
    sizeof(struct ip_esp_hdr)  + 
    esp_data;

  /* Try to reallocate packet, if necessary */
  alloc_packet(packet_size);

  ip = ip_header(packet, packet_size, o);

  /* GRE Encapsulation takes place. */
  gre_encapsulation(packet, o,
        sizeof(struct iphdr) + 
        sizeof(struct ip_auth_hdr) + 
        ip_ah_icv                  +
        sizeof(struct ip_esp_hdr)  + 
        esp_data);

  /*
   * IP Authentication Header (RFC 2402)
   *
   * 2.  Authentication Header Format
   *
   *  0                   1                   2                   3
   *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * | Next Header   |  Payload Len  |          RESERVED             |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |                 Security Parameters Index (SPI)               |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |                    Sequence Number Field                      |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |                                                               |
   * +                Authentication Data (variable)                 |
   * |                                                               |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   */

  /* IPSec AH Header structure making a pointer to IP Header structure. */
  ip_auth          = (struct ip_auth_hdr *)((void *)ip + sizeof(struct iphdr) + greoptlen);
  ip_auth->nexthdr = IPPROTO_ESP;
  ip_auth->hdrlen  = o->ipsec.ah_length ? 
    o->ipsec.ah_length : 
    (sizeof(struct ip_auth_hdr)/4) + (ip_ah_icv/ip_ah_icv);
  ip_auth->spi     = htonl(__RND(o->ipsec.ah_spi));
  ip_auth->seq_no  = htonl(__RND(o->ipsec.ah_sequence));

  offset = sizeof(struct ip_auth_hdr);

  buffer.ptr = (void *)ip_auth + offset;

  /* Setting a fake encrypted content. */
  for (counter = 0; counter < ip_ah_icv; counter++)
    *buffer.byte_ptr++ = random();

  /* IPSec ESP Header structure making a pointer to Checksum. */
  ip_esp         = (struct ip_esp_hdr *)buffer.ptr;
  ip_esp->spi    = htonl(__RND(o->ipsec.esp_spi));
  ip_esp->seq_no = htonl(__RND(o->ipsec.esp_sequence));

  offset += sizeof(struct ip_esp_hdr);
  buffer.ptr += sizeof(struct ip_esp_hdr);

  /* Setting a fake encrypted content. */
  for (counter = 0; counter < esp_data; counter++)
    *buffer.byte_ptr++ = random();

	/* FIXME: Is this correct?! */
  /* GRE Encapsulation takes place. */
  gre_checksum(packet, o, packet_size);

  /* Setting SOCKADDR structure. */
  sin.sin_family      = AF_INET;
  sin.sin_port        = htons(IPPORT_RND(o->dest));
  sin.sin_addr.s_addr = o->ip.daddr;

  /* Sending packet. */
  if (sendto(fd, packet, packet_size, MSG_NOSIGNAL, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1 && errno != EPERM)
    return 1;

  return 0;
}

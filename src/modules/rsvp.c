/* vim: set ts=2 et sw=2 : */
/** @file rsvp.c */
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
#include <t50_defines.h>
#include <t50_config.h>
#include <t50_cksum.h>
#include <t50_memalloc.h>
#include <t50_modules.h>
#include <t50_randomizer.h>

static  size_t rsvp_objects_len(const uint8_t, const uint8_t, const uint8_t, const uint8_t);

/**
 * RSVP packet header configuration.
 *
 * This function configures and sends the RSVP packet header.
 *
 * @param co Pointer to T50 configuration structure.
 * @param size Pointer to packet size (updated by the function).
 */
void rsvp(const struct config_options *const __restrict__ co, size_t *size)
{
  size_t greoptlen,       /* GRE options size. */
         objects_length,  /* RSVP objects length. */
         counter;

  /* Packet and Checksum. */
  memptr_t buffer;

  struct iphdr *ip;

  /* RSVP Common header. */
  struct rsvp_common_hdr *rsvp;

  assert(co != NULL);

  greoptlen = gre_opt_len(co);
  objects_length = rsvp_objects_len(co->rsvp.type, co->rsvp.scope, co->rsvp.adspec, co->rsvp.tspec);

  *size = sizeof(struct iphdr)           +
          sizeof(struct rsvp_common_hdr) +
          greoptlen                      +
          objects_length;

  /* Try to reallocate the packet, if necessary */
  alloc_packet(*size);

  /* IP Header structure making a pointer to Packet. */
  ip = ip_header(packet, *size, co);

  /* GRE Encapsulation takes place. */
  gre_encapsulation(packet, co,
                    sizeof(struct iphdr)           +
                    sizeof(struct rsvp_common_hdr) +
                    objects_length);

  /* RSVP Header structure making a pointer to IP Header structure. */
  rsvp           = (struct rsvp_common_hdr *)((unsigned char *)(ip + 1) + greoptlen);
  rsvp->flags    = __RND(co->rsvp.flags);
  rsvp->version  = RSVPVERSION;
  rsvp->type     = co->rsvp.type;
  rsvp->ttl      = __RND(co->rsvp.ttl);
  rsvp->length   = htons(sizeof(struct rsvp_common_hdr) + objects_length);
  rsvp->reserved = FIELD_MUST_BE_ZERO;
  rsvp->check    = 0;

  buffer.ptr = rsvp + 1;

  /*
   * The SESSION Object Class is present for all RSVP Messages.
   *
   * Resource ReSerVation Protocol (RSVP) (RFC 2205)
   *
   * A.1 SESSION Class
   *
   * SESSION Class = 1.
   *
   * o    IPv4/UDP SESSION object: Class = 1, C-Type = 1
   *
   * +-------------+-------------+-------------+-------------+
   * |             IPv4 DestAddress (4 bytes)                |
   * +-------------+-------------+-------------+-------------+
   * | Protocol Id |    Flags    |          DstPort          |
   * +-------------+-------------+-------------+-------------+
   */
  *buffer.word_ptr++ = htons(RSVP_LENGTH_SESSION);
  *buffer.byte_ptr++ = RSVP_OBJECT_SESSION;
  *buffer.byte_ptr++ = 1;
  *buffer.inaddr_ptr++ = htonl(INADDR_RND(co->rsvp.session_addr));
  *buffer.byte_ptr++ = __RND(co->rsvp.session_proto);
  *buffer.byte_ptr++ = __RND(co->rsvp.session_flags);
  *buffer.word_ptr++ = htons(__RND(co->rsvp.session_port));

  /*
   * The RESV_HOP Object Class is present for the following:
   * 3.1.3 Path Messages
   * 3.1.4 Resv Messages
   * 3.1.5 Path Teardown Messages
   * 3.1.6 Resv Teardown Messages
   * 3.1.8 Resv Error Messages
   */
  if (co->rsvp.type == RSVP_MESSAGE_TYPE_PATH ||
      co->rsvp.type == RSVP_MESSAGE_TYPE_RESV ||
      co->rsvp.type == RSVP_MESSAGE_TYPE_PATHTEAR ||
      co->rsvp.type == RSVP_MESSAGE_TYPE_RESVTEAR ||
      co->rsvp.type == RSVP_MESSAGE_TYPE_RESVERR)
  {
    /*
     * Resource ReSerVation Protocol (RSVP) (RFC 2205)
     *
     * A.2 RSVP_HOP Class
     *
     * RSVP_HOP class = 3.
     *
     * o    IPv4 RSVP_HOP object: Class = 3, C-Type = 1
     *
     * +-------------+-------------+-------------+-------------+
     * |             IPv4 Next/Previous Hop Address            |
     * +-------------+-------------+-------------+-------------+
     * |                 Logical Interface Handle              |
     * +-------------+-------------+-------------+-------------+
     */
    *buffer.word_ptr++ = htons(RSVP_LENGTH_RESV_HOP);
    *buffer.byte_ptr++ = RSVP_OBJECT_RESV_HOP;
    *buffer.byte_ptr++ = 1;
    *buffer.inaddr_ptr++ = htonl(INADDR_RND(co->rsvp.hop_addr));
    *buffer.dword_ptr++ = htonl(__RND(co->rsvp.hop_iface));
  }

  /*
   * The TIME_VALUES Object Class is present for the following:
   * 3.1.3 Path Messages
   * 3.1.4 Resv Messages
   */
  if (co->rsvp.type == RSVP_MESSAGE_TYPE_PATH ||
      co->rsvp.type == RSVP_MESSAGE_TYPE_RESV)
  {
    /*
     * Resource ReSerVation Protocol (RSVP) (RFC 2205)
     *
     * A.4 TIME_VALUES Class
     *
     * TIME_VALUES class = 5.
     *
     * o    TIME_VALUES Object: Class = 5, C-Type = 1
     *
     * +-------------+-------------+-------------+-------------+
     * |                   Refresh Period R                    |
     * +-------------+-------------+-------------+-------------+
     */
    *buffer.word_ptr++ = htons(RSVP_LENGTH_TIME_VALUES);
    *buffer.byte_ptr++ = RSVP_OBJECT_TIME_VALUES;
    *buffer.byte_ptr++ = 1;
    *buffer.dword_ptr++ = htonl(__RND(co->rsvp.time_refresh));
  }

  /*
   * The ERROR_SPEC Object Class is present for the following:
   * 3.1.5 Path Teardown Messages
   * 3.1.8 Resv Error Messages
   * 3.1.9 Confirmation Messages
   */
  if (co->rsvp.type == RSVP_MESSAGE_TYPE_PATHERR ||
      co->rsvp.type == RSVP_MESSAGE_TYPE_RESVERR ||
      co->rsvp.type == RSVP_MESSAGE_TYPE_RESVCONF)
  {
    /*
     * Resource ReSerVation Protocol (RSVP) (RFC 2205)
     *
     * A.5 ERROR_SPEC Class
     *
     * ERROR_SPEC class = 6.
     *
     * o    IPv4 ERROR_SPEC object: Class = 6, C-Type = 1
     *
     * +-------------+-------------+-------------+-------------+
     * |            IPv4 Error Node Address (4 bytes)          |
     * +-------------+-------------+-------------+-------------+
     * |    Flags    |  Error Code |        Error Value        |
     * +-------------+-------------+-------------+-------------+
     */
    *buffer.word_ptr++ = htons(RSVP_LENGTH_ERROR_SPEC);
    *buffer.byte_ptr++ = RSVP_OBJECT_ERROR_SPEC;
    *buffer.byte_ptr++ = 1;
    *buffer.inaddr_ptr++ = htonl(INADDR_RND(co->rsvp.error_addr));
    *buffer.byte_ptr++ = __RND(co->rsvp.error_flags);
    *buffer.byte_ptr++ = __RND(co->rsvp.error_code);
    *buffer.word_ptr++ = htons(__RND(co->rsvp.error_value));
  }

  /*
   * The SENDER_TEMPLATE,  SENDER_TSPEC and  ADSPEC Object Classes are
   * present for the following:
   * 3.1.3 Path Messages
   * 3.1.5 Path Teardown Messages
   * 3.1.7 Path Error Messages
   */
  if (co->rsvp.type == RSVP_MESSAGE_TYPE_PATH     ||
      co->rsvp.type == RSVP_MESSAGE_TYPE_PATHTEAR ||
      co->rsvp.type == RSVP_MESSAGE_TYPE_PATHERR)
  {
    /*
     * Resource ReSerVation Protocol (RSVP) (RFC 2205)
     *
     * A.10 SENDER_TEMPLATE Class
     *
     * SENDER_TEMPLATE class = 11.
     *
     * o    IPv4 SENDER_TEMPLATE object: Class = 11, C-Type = 1
     *
     * Definition same as IPv4/UDP FILTER_SPEC object.
     *
     * RSVP Extensions for IPSEC (RFC 2207)
     *
     * 3.3  SENDER_TEMPLATE Class
     *
     * SENDER_TEMPLATE class = 11.
     *
     * o    IPv4/GPI SENDER_TEMPLATE object: Class = 11, C-Type = 4
     *
     * Definition same as IPv4/GPI FILTER_SPEC object.
     */
    *buffer.word_ptr++ = htons(RSVP_LENGTH_SENDER_TEMPLATE);
    *buffer.byte_ptr++ = RSVP_OBJECT_SENDER_TEMPLATE;
    *buffer.byte_ptr++ = 1;
    *buffer.inaddr_ptr++ = htonl(INADDR_RND(co->rsvp.sender_addr));
    *buffer.word_ptr++ = FIELD_MUST_BE_ZERO;
    *buffer.word_ptr++ = htons(__RND(co->rsvp.sender_port));

    /*
     * Resource ReSerVation Protocol (RSVP) (RFC 2205)
     *
     * A.11 SENDER_TSPEC Class
     *
     * SENDER_TSPEC class = 12.
     *
     * o    Intserv SENDER_TSPEC object: Class = 12, C-Type = 2
     *
     * The contents and encoding rules for this object are specified
     * in documents prepared by the int-serv working group.
     */
    *buffer.word_ptr++ = htons(RSVP_LENGTH_SENDER_TSPEC +
                               TSPEC_SERVICES(co->rsvp.tspec));
    *buffer.byte_ptr++ = RSVP_OBJECT_SENDER_TSPEC;
    *buffer.byte_ptr++ = 2;

    /*
     * The Use of RSVP with IETF Integrated Services (RFC 2210)
     *
     * 3.1. RSVP SENDER_TSPEC Object
     *
     *       31           24 23           16 15            8 7             0
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 1   | 0 (a) |    reserved           |             7 (b)             |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 2   |    1  (c)     |0| reserved    |             6 (d)             |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 3   |   127 (e)     |    0 (f)      |             5 (g)             |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 4   |  Token Bucket Rate [r] (32-bit IEEE floating point number)    |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 5   |  Token Bucket Size [b] (32-bit IEEE floating point number)    |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 6   |  Peak Data Rate [p] (32-bit IEEE floating point number)       |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 7   |  Minimum Policed Unit [m] (32-bit integer)                    |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 8   |  Maximum Packet Size [M]  (32-bit integer)                    |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    *buffer.word_ptr++ = FIELD_MUST_BE_ZERO;
    *buffer.word_ptr++ = htons((TSPEC_SERVICES(co->rsvp.tspec) -
                                RSVP_LENGTH_SENDER_TSPEC) / 4);
    *buffer.byte_ptr++ = co->rsvp.tspec;
    *buffer.byte_ptr++ = FIELD_MUST_BE_ZERO;
    *buffer.word_ptr++ = htons(TSPEC_SERVICES(co->rsvp.tspec) / 4);

    /* Identifying the RSVP TSPEC and building it. */
    switch (co->rsvp.tspec)
    {
    case TSPEC_TRAFFIC_SERVICE:
    case TSPEC_GUARANTEED_SERVICE:
      *buffer.byte_ptr++ = TSPECT_TOKEN_BUCKET_SERVICE;
      *buffer.byte_ptr++ = FIELD_MUST_BE_ZERO;
      *buffer.word_ptr++ = htons((TSPEC_SERVICES(co->rsvp.tspec) -
                                  TSPEC_MESSAGE_HEADER) / 4);
      *buffer.dword_ptr++ = htonl(__RND(co->rsvp.tspec_r));
      *buffer.dword_ptr++ = htonl(__RND(co->rsvp.tspec_b));
      *buffer.dword_ptr++ = htonl(__RND(co->rsvp.tspec_p));
      *buffer.dword_ptr++ = htonl(__RND(co->rsvp.tspec_m));
      *buffer.dword_ptr++ = htonl(__RND(co->rsvp.tspec_M));
    }

    /*
     * Resource ReSerVation Protocol (RSVP) (RFC 2205)
     *
     * A.12 ADSPEC Class
     *
     * ADSPEC class = 13.
     *
     * o    Intserv ADSPEC object: Class = 13, C-Type = 2
     *
     * The contents and format for this object are specified in
     * documents prepared by the int-serv working group.
     */
    *buffer.word_ptr++ = htons(RSVP_LENGTH_ADSPEC +
                               ADSPEC_SERVICES(co->rsvp.adspec));
    *buffer.byte_ptr++ = RSVP_OBJECT_ADSPEC;
    *buffer.byte_ptr++ = 2;

    /*
     * The Use of RSVP with IETF Integrated Services (RFC 2210)
     *
     * 3.3.1. RSVP ADSPEC format
     *
     *      31           24 23            16 15            8 7             0
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *     | 0 (a) |      reserved         |  Msg length - 1 (b)           |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *     |                                                               |
     *     |    Default General Parameters fragment (Service 1)  (c)       |
     *     |    (Always Present)                                           |
     *     |                                                               |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *     |                                                               |
     *     |    Guaranteed Service Fragment (Service 2)    (d)             |
     *     |    (Present if application might use Guaranteed Service)      |
     *     |                                                               |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *     |                                                               |
     *     |    Controlled-Load Service Fragment (Service 5)  (e)          |
     *     |    (Present if application might use Controlled-Load Service) |
     *     |                                                               |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    *buffer.word_ptr++ = FIELD_MUST_BE_ZERO;
    *buffer.word_ptr++ = htons((ADSPEC_SERVICES(co->rsvp.adspec) -
                                ADSPEC_MESSAGE_HEADER) / 4);

    /*
     * The Use of RSVP with IETF Integrated Services (RFC 2210)
     *
     * 3.3.2. Default General Characterization Parameters ADSPEC data fragment
     *
     *      31            24 23           16 15            8 7             0
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 1   |    1  (c)     |x| reserved    |           8 (d)               |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 2   |    4 (e)      |    (f)        |           1 (g)               |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 3   |        IS hop cnt (32-bit unsigned integer)                   |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 4   |    6 (h)      |    (i)        |           1 (j)               |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 5   |  Path b/w estimate  (32-bit IEEE floating point number)       |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 6   |     8 (k)     |    (l)        |           1 (m)               |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 7   |        Minimum path latency (32-bit integer)                  |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 8   |     10 (n)    |      (o)      |           1 (p)               |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * 9   |      Composed MTU (32-bit unsigned integer)                   |
     *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    *buffer.byte_ptr++ = ADSPEC_PARAMETER_SERVICE;
    *buffer.byte_ptr++ = FIELD_MUST_BE_ZERO;
    *buffer.word_ptr++ = htons((ADSPEC_PARAMETER_LENGTH - ADSPEC_MESSAGE_HEADER) / 4);
    *buffer.byte_ptr++ = ADSPEC_PARAMETER_ISHOPCNT;
    *buffer.byte_ptr++ = FIELD_MUST_BE_ZERO;
    *buffer.word_ptr++ = htons(ADSPEC_SERVDATA_HEADER / 4);
    *buffer.dword_ptr++ = htonl(__RND(co->rsvp.adspec_hop));
    *buffer.byte_ptr++ = ADSPEC_PARAMETER_BANDWIDTH;
    *buffer.byte_ptr++ = FIELD_MUST_BE_ZERO;
    *buffer.word_ptr++ = htons(ADSPEC_SERVDATA_HEADER / 4);
    *buffer.dword_ptr++ = htonl(__RND(co->rsvp.adspec_path));
    *buffer.byte_ptr++ = ADSPEC_PARAMETER_LATENCY;
    *buffer.byte_ptr++ = FIELD_MUST_BE_ZERO;
    *buffer.word_ptr++ = htons(ADSPEC_SERVDATA_HEADER / 4);
    *buffer.dword_ptr++ = htonl(__RND(co->rsvp.adspec_minimum));
    *buffer.byte_ptr++ = ADSPEC_PARAMETER_COMPMTU;
    *buffer.byte_ptr++ = FIELD_MUST_BE_ZERO;
    *buffer.word_ptr++ = htons(ADSPEC_SERVDATA_HEADER / 4);
    *buffer.dword_ptr++ = htonl(__RND(co->rsvp.adspec_mtu));

    /* Identifying the ADSPEC and building it. */
    switch (co->rsvp.adspec)
    {
    case ADSPEC_GUARANTEED_SERVICE:
    case ADSPEC_CONTROLLED_SERVICE:
      /*
       * The Use of RSVP with IETF Integrated Services (RFC 2210)
       *
       * 3.3.3. Guaranteed Service ADSPEC data fragment
       *
       *      31            24 23           16 15            8 7             0
       *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * 1   |     2 (a)     |x|  reserved   |             N-1 (b)           |
       *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * 2   |    133 (c)    |     0 (d)     |             1 (e)             |
       *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * 3   |   End-to-end composed value for C [Ctot] (32-bit integer)     |
       *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * 4   |     134 (f)   |       (g)     |             1 (h)             |
       *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * 5   |   End-to-end composed value for D [Dtot] (32-bit integer)     |
       *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * 6   |     135 (i)   |       (j)     |             1 (k)             |
       *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * 7   | Since-last-reshaping point composed C [Csum] (32-bit integer) |
       *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * 8   |     136 (l)   |       (m)     |             1 (n)             |
       *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * 9   | Since-last-reshaping point composed D [Dsum] (32-bit integer) |
       *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       * 10  | Service-specific general parameter headers/values, if present |
       *  .  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *  .
       * N   |                                                               |
       *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       */
      *buffer.byte_ptr++ = ADSPEC_GUARANTEED_SERVICE;
      *buffer.byte_ptr++ = FIELD_MUST_BE_ZERO;
      *buffer.word_ptr++ = htons((ADSPEC_GUARANTEED_LENGTH - ADSPEC_MESSAGE_HEADER) / 4);
      *buffer.byte_ptr++ = 133;
      *buffer.byte_ptr++ = FIELD_MUST_BE_ZERO;
      *buffer.word_ptr++ = htons(ADSPEC_SERVDATA_HEADER / 4);
      *buffer.dword_ptr++ = htonl(__RND(co->rsvp.adspec_Ctot));
      *buffer.byte_ptr++ = 134;
      *buffer.byte_ptr++ = FIELD_MUST_BE_ZERO;
      *buffer.word_ptr++ = htons(ADSPEC_SERVDATA_HEADER / 4);
      *buffer.dword_ptr++ = htonl(__RND(co->rsvp.adspec_Dtot));
      *buffer.byte_ptr++ = 135;
      *buffer.byte_ptr++ = FIELD_MUST_BE_ZERO;
      *buffer.word_ptr++ = htons(ADSPEC_SERVDATA_HEADER / 4);
      *buffer.dword_ptr++ = htonl(__RND(co->rsvp.adspec_Csum));
      *buffer.byte_ptr++ = 136;
      *buffer.byte_ptr++ = FIELD_MUST_BE_ZERO;
      *buffer.word_ptr++ = htons(ADSPEC_SERVDATA_HEADER / 4);
      *buffer.dword_ptr++ = htonl(__RND(co->rsvp.adspec_Dsum));

      /* Going to the next ADSPEC, if it needs to do sco-> */
      if (co->rsvp.adspec == ADSPEC_CONTROLLED_SERVICE)
      {
        /*
         * The Use of RSVP with IETF Integrated Services (RFC 2210)
         *
         * 3.3.4. Controlled-Load Service ADSPEC data fragment
         *
         *      31            24 23           16 15            8 7             0
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * 1   |     5 (a)     |x|  (b)        |            N-1 (c)            |
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * 2   | Service-specific general parameter headers/values, if present |
         *  .  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  .
         * N   |                                                               |
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
        *buffer.byte_ptr++ = ADSPEC_CONTROLLED_SERVICE;
        *buffer.byte_ptr++ = FIELD_MUST_BE_ZERO;
        *buffer.word_ptr++ = htons(ADSPEC_CONTROLLED_LENGTH - ADSPEC_MESSAGE_HEADER);
      }
    }
  }

  /*
   * The RESV_CONFIRM Object Class is present for the following:
   * 3.1.4 Resv Messages
   * 3.1.9 Confirmation Messages
   */
  if (co->rsvp.type == RSVP_MESSAGE_TYPE_RESV ||
      co->rsvp.type == RSVP_MESSAGE_TYPE_RESVCONF)
  {
    /*
     * Resource ReSerVation Protocol (RSVP) (RFC 2205)
     *
     * A.14 Resv_CONFIRM Class
     *
     * RESV_CONFIRM class = 15.
     *
     * o    IPv4 RESV_CONFIRM object: Class = 15, C-Type = 1
     *
     * +-------------+-------------+-------------+-------------+
     * |            IPv4 Receiver Address (4 bytes)            |
     * +-------------+-------------+-------------+-------------+
     */
    *buffer.word_ptr++ = htons(RSVP_LENGTH_RESV_CONFIRM);
    *buffer.byte_ptr++ = RSVP_OBJECT_RESV_CONFIRM;
    *buffer.byte_ptr++ = 1;
    *buffer.inaddr_ptr++ = htonl(INADDR_RND(co->rsvp.confirm_addr));
  }

  /*
   * The STYLE Object Classes is present for the following:
   * 3.1.4 Resv Messages
   * 3.1.6 Resv Teardown Messages
   * 3.1.8 Resv Error Messages
   * 3.1.9 Confirmation Messages
   */
  if (co->rsvp.type == RSVP_MESSAGE_TYPE_RESV     ||
      co->rsvp.type == RSVP_MESSAGE_TYPE_RESVTEAR ||
      co->rsvp.type == RSVP_MESSAGE_TYPE_RESVERR  ||
      co->rsvp.type == RSVP_MESSAGE_TYPE_RESVCONF)
  {
    /*
     * The SCOPE Object Classes is present for the following:
     * 3.1.4 Resv Messages
     * 3.1.6 Resv Teardown Messages
     * 3.1.8 Resv Error Messages
     */
    if (co->rsvp.type == RSVP_MESSAGE_TYPE_RESV     ||
        co->rsvp.type == RSVP_MESSAGE_TYPE_RESVTEAR ||
        co->rsvp.type == RSVP_MESSAGE_TYPE_RESVERR)
    {
      /*
       * Resource ReSerVation Protocol (RSVP) (RFC 2205)
       *
       * A.6 SCOPE Class
       *
       * SCOPE class = 7.
       *
       * o    IPv4 SCOPE List object: Class = 7, C-Type = 1
       *
       * +-------------+-------------+-------------+-------------+
       * |                IPv4 Src Address (4 bytes)             |
       * +-------------+-------------+-------------+-------------+
       * //                                                      //
       * +-------------+-------------+-------------+-------------+
       * |                IPv4 Src Address (4 bytes)             |
       * +-------------+-------------+-------------+-------------+
       */
      *buffer.word_ptr++ = htons(RSVP_LENGTH_SCOPE(co->rsvp.scope));
      *buffer.byte_ptr++ = RSVP_OBJECT_SCOPE;
      *buffer.byte_ptr++ = 1;

      /* Dealing with scope address(es). */
      /* NOTE: Assume co->rsvp.scope > 0. */
      for (counter = 0; likely(counter < co->rsvp.scope) ; counter++)
        *buffer.inaddr_ptr++ = htonl(INADDR_RND(co->rsvp.address[counter]));
    }

    /*
     * Resource ReSerVation Protocol (RSVP) (RFC 2205)
     *
     * A.7 STYLE Class
     *
     * STYLE class = 8.
     *
     * o    STYLE object: Class = 8, C-Type = 1
     *
     * +-------------+-------------+-------------+-------------+
     * |   Flags     |              Option Vector              |
     * +-------------+-------------+-------------+-------------+
     */
    *buffer.word_ptr++ = htons(RSVP_LENGTH_STYLE);
    *buffer.byte_ptr++ = RSVP_OBJECT_STYLE;
    *buffer.byte_ptr++ = 1;
    *buffer.byte_ptr++ = FIELD_MUST_BE_ZERO;
    *buffer.dword_ptr++ = htonl(__RND(co->rsvp.style_opt) << 8);
  }

  /* FIX: buffer.ptr alrealy points past the last byte writen on
          the buffer. So, it is simple to calculate the size used
          by cksum() function.

          This is easier than accumulate the "length" through
          various conditionals above! */

  /* Computing the checksum. */
  rsvp->check   = co->bogus_csum ?
                  RANDOM() :
                  cksum(rsvp, buffer.ptr - (void *)rsvp);

  /* GRE Encapsulation takes place. */
  gre_checksum(packet, co, *size);
}

/* RSVP objects size claculation. */
size_t rsvp_objects_len(const uint8_t type, const uint8_t scope, const uint8_t adspec, const uint8_t tspec)
{
  size_t size;

  /*
   * The code starts with the size of SESSION Object Class  (according
   * to the RFC 2205, this is required in every RSVP message), and, if
   * the appropriate RSVP Message type matches,  size  accumulates the
   * corresponded Object Class(s)  size  to build the appropriate RSVP
   * message.  Otherwise,   it just returns the size of SESSION Object
   * Class.
   */
  size = RSVP_LENGTH_SESSION;

  /*
   * The RESV_HOP Object Class is present for the following:
   * 3.1.3 Path Messages
   * 3.1.4 Resv Messages
   * 3.1.5 Path Teardown Messages
   * 3.1.6 Resv Teardown Messages
   * 3.1.8 Resv Error Messages
   */
  if (type == RSVP_MESSAGE_TYPE_PATH     ||
      type == RSVP_MESSAGE_TYPE_RESV     ||
      type == RSVP_MESSAGE_TYPE_PATHTEAR ||
      type == RSVP_MESSAGE_TYPE_RESVTEAR ||
      type == RSVP_MESSAGE_TYPE_RESVERR)
    size += RSVP_LENGTH_RESV_HOP;

  /*
   * The TIME_VALUES Object Class is present for the following:
   * 3.1.3 Path Messages
   * 3.1.4 Resv Messages
   */
  if (type == RSVP_MESSAGE_TYPE_PATH ||
      type == RSVP_MESSAGE_TYPE_RESV)
    size += RSVP_LENGTH_TIME_VALUES;

  /*
   * The ERROR_SPEC Object Class is present for the following:
   * 3.1.5 Path Teardown Messages
   * 3.1.8 Resv Error Messages
   * 3.1.9 Confirmation Messages
   */
  if (type == RSVP_MESSAGE_TYPE_PATHERR ||
      type == RSVP_MESSAGE_TYPE_RESVERR ||
      type == RSVP_MESSAGE_TYPE_RESVCONF)
    size += RSVP_LENGTH_ERROR_SPEC;

  /*
   * The SENDER_TEMPLATE,  SENDER_TSPEC and  ADSPEC Object Classes are
   * present for the following:
   * 3.1.3 Path Messages
   * 3.1.5 Path Teardown Messages
   * 3.1.7 Path Error Messages
   */
  if (type == RSVP_MESSAGE_TYPE_PATH     ||
      type == RSVP_MESSAGE_TYPE_PATHTEAR ||
      type == RSVP_MESSAGE_TYPE_PATHERR)
  {
    size += RSVP_LENGTH_SENDER_TEMPLATE;
    size += RSVP_LENGTH_SENDER_TSPEC;
    size += TSPEC_SERVICES(tspec);
    size += RSVP_LENGTH_ADSPEC;
    size += ADSPEC_SERVICES(adspec);
  }

  /*
   * The RESV_CONFIRM Object Class is present for the following:
   * 3.1.4 Resv Messages
   * 3.1.9 Confirmation Messages
   */
  if (type == RSVP_MESSAGE_TYPE_RESV ||
      type == RSVP_MESSAGE_TYPE_RESVCONF)
    size += RSVP_LENGTH_RESV_CONFIRM;

  /*
   * The STYLE Object Classes is present for the following:
   * 3.1.4 Resv Messages
   * 3.1.6 Resv Teardown Messages
   * 3.1.8 Resv Error Messages
   * 3.1.9 Confirmation Messages
   */
  if (type == RSVP_MESSAGE_TYPE_RESV     ||
      type == RSVP_MESSAGE_TYPE_RESVTEAR ||
      type == RSVP_MESSAGE_TYPE_RESVERR  ||
      type == RSVP_MESSAGE_TYPE_RESVCONF)
  {
    /*
     * The SCOPE Object Classes is present for the following:
     * 3.1.4 Resv Messages
     * 3.1.6 Resv Teardown Messages
     * 3.1.8 Resv Error Messages
     */
    if (type == RSVP_MESSAGE_TYPE_RESV     ||
        type == RSVP_MESSAGE_TYPE_RESVTEAR ||
        type == RSVP_MESSAGE_TYPE_RESVERR)
      size += RSVP_LENGTH_SCOPE(scope);

    size += RSVP_LENGTH_STYLE;
  }

  return size;
}

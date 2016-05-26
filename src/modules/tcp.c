/* vim: set ts=2 et sw=2 : */
/** @file tcp.c */
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

#include <common.h>

/*
 * prototypes.
 */
static size_t tcp_options_len(const uint8_t, int, int);

/**
 * TCP packet header configuration.
 *
 * Configures the TCP packet header.
 * A pointer to this function will be on modules table.
 *
 * @param co Pointer to T50 configuration structure.
 * @param size Pointer to size of the packet (updated by the function).
 */
void tcp(const struct config_options *const __restrict__ co, size_t *size)
{
  size_t greoptlen,   /* GRE options size. */
         tcpolen,     /* TCP options size. */
         tcpopt,      /* TCP options total size. */
         length,
         counter;

  memptr_t buffer;

  struct iphdr *ip;

  /* GRE Encapsulated IP Header. */
  struct iphdr *gre_ip;

  /* TCP header and PSEUDO header. */
  struct tcphdr *tcp;
  struct psdhdr *pseudo;

  assert(co != NULL);

  greoptlen = gre_opt_len(co);
  tcpolen = tcp_options_len(co->tcp.options, co->tcp.md5, co->tcp.auth);
  tcpopt = tcpolen + TCPOLEN_PADDING(tcpolen);

  *size = sizeof(struct iphdr)  +
          sizeof(struct tcphdr) +
          sizeof(struct psdhdr) +
          tcpopt                +
          greoptlen;

  /* Try to reallocate packet, if necessary */
  alloc_packet(*size);

  /* IP Header structure making a pointer to Packet. */
  ip = ip_header(packet, *size, co);

  gre_ip = gre_encapsulation(packet, co,
                             sizeof(struct iphdr)  +
                             sizeof(struct tcphdr) +
                             tcpopt);

  /*
   * The RFC 793 has defined a 4-bit field in the TCP header which encodes the size
   * of the header in 4-byte words.  Thus the maximum header size is 15*4=60 bytes.
   * Of this, 20 bytes are taken up by non-options fields of the TCP header,  which
   * leaves 40 bytes (TCP header * 2) for options.
   */
  if (unlikely(tcpopt > (sizeof(struct tcphdr) * 2)))
    fatal_error("%s() - TCP option size (%zu bytes) is bigger than two times the TCP header size.",
                __FUNCTION__, tcpopt);

  /* TCP Header structure making a pointer to IP Header structure. */
  tcp          = (struct tcphdr *)((unsigned char *)(ip + 1) + greoptlen);
  tcp->source  = htons(IPPORT_RND(co->source));
  tcp->dest    = htons(IPPORT_RND(co->dest));
  tcp->res1    = TCP_RESERVED_BITS;
  tcp->doff    = co->tcp.doff ? co->tcp.doff : ((sizeof(struct tcphdr) + tcpopt) / 4);
  tcp->fin     = (co->tcp.fin != 0);
  tcp->syn     = (co->tcp.syn != 0);
  tcp->seq     = co->tcp.syn ? htonl(__RND(co->tcp.sequence)) : 0;
  tcp->rst     = (co->tcp.rst != 0);
  tcp->psh     = (co->tcp.psh != 0);
  tcp->ack     = (co->tcp.ack != 0);
  tcp->ack_seq = co->tcp.ack ? htonl(__RND(co->tcp.acknowledge)) : 0;
  tcp->urg     = (co->tcp.urg != 0);
  tcp->urg_ptr = co->tcp.urg ? htons(__RND(co->tcp.urg_ptr)) : 0;
  tcp->ece     = (co->tcp.ece != 0);
  tcp->cwr     = (co->tcp.cwr != 0);
  tcp->window  = htons(__RND(co->tcp.window));
  tcp->check   = 0; /* Needed 'cause of cksum() call */

  buffer.ptr = tcp + 1;

  /*
   * Transmission Control Protocol (TCP) (RFC 793)
   *
   *    TCP Maximum Segment Size
   *
   *    Kind: 2
   *
   *    Length: 4 bytes
   *
   *    +--------+--------+---------+--------+
   *    |00000010|00000100|   max seg size   |
   *    +--------+--------+---------+--------+
   */
  if (TEST_BITS(co->tcp.options, TCP_OPTION_MSS))
  {
    *buffer.byte_ptr++ = TCPOPT_MSS;
    *buffer.byte_ptr++ = TCPOLEN_MSS;
    *buffer.word_ptr++ = htons(__RND(co->tcp.mss));
  }

  /*
   * TCP Extensions for High Performance (RFC 1323)
   *
   *    TCP Window Scale Option (WSopt):
   *
   *    Kind: 3
   *
   *    Length: 3 bytes
   *
   *    +--------+--------+--------+
   *    |00000011|00000011| shift  |
   *    +--------+--------+--------+
   */
  if (TEST_BITS(co->tcp.options, TCP_OPTION_WSOPT))
  {
    *buffer.byte_ptr++ = TCPOPT_WSOPT;
    *buffer.byte_ptr++ = TCPOLEN_WSOPT;
    *buffer.byte_ptr++ = __RND(co->tcp.wsopt);
  }

  /*
   * TCP Extensions for High Performance (RFC 1323)
   *
   *    TCP Timestamps Option (TSopt):
   *
   *    Kind: 8
   *
   *    Length: 10 bytes
   *
   *                      +--------+--------+
   *                      |00001000|00001010|
   *    +--------+--------+--------+--------+
   *    |         TS Value (TSval)          |
   *    +--------+--------+--------+--------+
   *    |       TS Echo Reply (TSecr)       |
   *    +--------+--------+--------+--------+
   */
  if (TEST_BITS(co->tcp.options, TCP_OPTION_TSOPT))
  {
    /*
     * TCP Extensions for High Performance (RFC 1323)
     *
     * APPENDIX A:  IMPLEMENTATION SUGGESTIONS
     *
     *   The following layouts are recommended for sending options on non-SYN
     *   segments, to achieve maximum feasible alignment of 32-bit and 64-bit
     *   machines.
     *
     *
     *       +--------+--------+--------+--------+
     *       |   NOP  |  NOP   |  TSopt |   10   |
     *       +--------+--------+--------+--------+
     *       |          TSval   timestamp        |
     *       +--------+--------+--------+--------+
     *       |          TSecr   timestamp        |
     *       +--------+--------+--------+--------+
     */
    if (!co->tcp.syn)
      for (; tcpolen & 3; tcpolen++)  /* NOTE: Cannot assume anything about tcpolen. */
        *buffer.byte_ptr++ = TCPOPT_NOP;

    *buffer.byte_ptr++ = TCPOPT_TSOPT;
    *buffer.byte_ptr++ = TCPOLEN_TSOPT;
    *buffer.dword_ptr++ = htonl(__RND(co->tcp.tsval));
    *buffer.dword_ptr++ = htonl(__RND(co->tcp.tsecr));
  }

  /*
   * TCP Extensions for Transactions Functional Specification (RFC 1644)
   *
   *    CC Option:
   *
   *    Kind: 11
   *
   *    Length: 6 bytes
   *
   *                      +--------+--------+
   *                      |00001011|00000110|
   *    +--------+--------+--------+--------+
   *    |     Connection Count:  SEG.CC     |
   *    +--------+--------+--------+--------+
   */
  if (TEST_BITS(co->tcp.options, TCP_OPTION_CC))
  {
    *buffer.byte_ptr++ = TCPOPT_CC;
    *buffer.byte_ptr++ = TCPOLEN_CC;
    *buffer.dword_ptr++ = htonl(__RND(co->tcp.cc));

    /*
     * TCP Extensions for Transactions Functional Specification (RFC 1644)
     *
     * 3.1  Data Structures
     *
     * This option may be sent in an initial SYN segment,  and it may be sent
     * in other segments if a  CC or CC.NEW option has been received for this
     * incarnation of the connection.  Its  SEG.CC  value  is  the TCB.CCsend
     *  value from the sender's TCB.
     */
    tcp->syn     = 1;
    tcp->seq     = htonl(__RND(co->tcp.sequence));
  }

  /*
   * TCP Extensions for Transactions Functional Specification (RFC 1644)
   *
   *    CC.NEW Option:
   *
   *    Kind: 12
   *
   *    Length: 6 bytes
   *
   *                      +--------+--------+
   *                      |00001100|00000110|
   *    +--------+--------+--------+--------+
   *    |     Connection Count:  SEG.CC     |
   *    +--------+--------+--------+--------+
   *
   *    CC.ECHO Option:
   *
   *    Kind: 13
   *
   *    Length: 6 bytes
   *
   *                      +--------+--------+
   *                      |00001101|00000110|
   *    +--------+--------+--------+--------+
   *    |     Connection Count:  SEG.CC     |
   *    +--------+--------+--------+--------+
   */
  if (TEST_BITS(co->tcp.options, TCP_OPTION_CC_NEXT))
  {
    *buffer.byte_ptr++  = co->tcp.cc_new ? TCPOPT_CC_NEW : TCPOPT_CC_ECHO;
    *buffer.byte_ptr++  = TCPOLEN_CC;
    *buffer.dword_ptr++ = htonl(co->tcp.cc_new ?
                                __RND(co->tcp.cc_new) :
                                __RND(co->tcp.cc_echo));

    tcp->syn = 1;
    tcp->seq = htonl(__RND(co->tcp.sequence));

    /*
     * TCP Extensions for Transactions Functional Specification (RFC 1644)
     *
     * 3.1  Data Structures
     *
     * This  option  may be sent instead of a CC option in an  initial  <SYN>
     * segment (i.e., SYN but not ACK bit), to indicate that the SEG.CC value
     * may not be larger than the previous value.   Its  SEG.CC  value is the
     * TCB.CCsend value from the sender's TCB.
     */
    if (!co->tcp.cc_new)
    {
      /*
       * TCP Extensions for Transactions Functional Specification (RFC 1644)
       *
       * 3.1  Data Structures
       *
       * This  option  may be sent instead of a CC option in an  initial  <SYN>
       * This  option must be sent  (in addition to a CC option)  in a  segment
       * containing both a  SYN and an  ACK bit,  if  the initial  SYN  segment
       * contained a CC or CC.NEW option.  Its SEG.CC value is the SEG.CC value
       * from the initial SYN.
       */
      tcp->ack     = 1;
      tcp->ack_seq = htonl(__RND(co->tcp.acknowledge));
    }
  }

  /*
   * TCP Selective Acknowledgement Options (SACK) (RFC 2018)
   *
   *    TCP Sack-Permitted Option:
   *
   *    Kind: 4
   *
   *    Length: 2 bytes
   *
   *    +--------+--------+
   *    |00000100|00000010|
   *    +--------+--------+
   */
  if (TEST_BITS(co->tcp.options, TCP_OPTION_SACK_OK))
  {
    *buffer.byte_ptr++ = TCPOPT_SACK_OK;
    *buffer.byte_ptr++ = TCPOLEN_SACK_OK;
  }

  /*
   * TCP Selective Acknowledgement Options (SACK) (RFC 2018)
   *
   *    TCP SACK Option:
   *
   *    Kind: 5
   *
   *    Length: Variable
   *
   *                      +--------+--------+
   *                      |00000101| Length |
   *    +--------+--------+--------+--------+
   *    |      Left Edge of 1st Block       |
   *    +--------+--------+--------+--------+
   *    |      Right Edge of 1st Block      |
   *    +--------+--------+--------+--------+
   *    |                                   |
   *    /            . . .                  /
   *    |                                   |
   *    +--------+--------+--------+--------+
   *    |      Left Edge of nth Block       |
   *    +--------+--------+--------+--------+
   *    |      Right Edge of nth Block      |
   *    +--------+--------+--------+--------+
   */
  if (TEST_BITS(co->tcp.options, TCP_OPTION_SACK_EDGE))
  {
    *buffer.byte_ptr++  = TCPOPT_SACK_EDGE;
    *buffer.byte_ptr++  = TCPOLEN_SACK_EDGE(1);
    *buffer.dword_ptr++ = htonl(__RND(co->tcp.sack_left));
    *buffer.dword_ptr++ = htonl(__RND(co->tcp.sack_right));
  }

  /*
   *  Protection of BGP Sessions via the TCP MD5 Signature Option (RFC 2385)
   *
   *    TCP MD5 Option:
   *
   *    Kind: 19
   *
   *    Length: 18 bytes
   *
   *    +--------+--------+--------+--------+
   *    |00010011|00010010|   MD5 digest... |
   *    +--------+--------+--------+--------+
   *    |        ...digest (con't)...       |
   *    +-----------------------------------+
   *    |                ...                |
   *    +-----------------------------------+
   *    |                ...                |
   *    +-----------------+-----------------+
   *    |...digest (con't)|
   *    +-----------------+
   */
  if (co->tcp.md5)
  {
    size_t stemp; /* Used to do just one call to auth_hmac_md5_len(). */

    *buffer.byte_ptr++ = TCPOPT_MD5;
    *buffer.byte_ptr++ = TCPOLEN_MD5;
    /*
     * The Authentication key uses HMAC-MD5 digest.
     */
    stemp = auth_hmac_md5_len(co->tcp.md5);

    /* NOTE: Assume stemp > 0. */
    for (counter = 0; likely(counter < stemp); counter++)
      *buffer.byte_ptr++ = RANDOM();
  }

  /*
   *  The TCP Authentication Option (RFC 5925)
   *
   *    TCP-AO Option:
   *
   *    Kind: 29
   *
   *    Length: 20 bytes
   *
   *    +--------+--------+--------+--------+
   *    |00011101|00010100| Key ID |Next Key|
   *    +--------+--------+--------+--------+
   *    |              MAC ...              |
   *    +-----------------------------------+
   *    |                ...                |
   *    +-----------------------------------+
   *    |                ...                |
   *    +-----------------+-----------------+
   *    |    ... MAC      |
   *    +-----------------+
   */
  if (co->tcp.auth)
  {
    size_t stemp; /* Used to do just one call to auth_hmac_md5_len(). */

    *buffer.byte_ptr++ = TCPOPT_AO;
    *buffer.byte_ptr++ = TCPOLEN_AO;
    *buffer.byte_ptr++ = __RND(co->tcp.key_id);
    *buffer.byte_ptr++ = __RND(co->tcp.next_key);
    /*
     * The Authentication key uses HMAC-MD5 digest.
     */
    stemp = auth_hmac_md5_len(co->tcp.auth);

    /* NOTE: Assume stemp > 0. */
    for (counter = 0; likely(counter < stemp); counter++)
      *buffer.byte_ptr++ = RANDOM();
  }

  /* Padding the TCP Options. */
  for (; tcpolen & 3; tcpolen++)
    *buffer.byte_ptr++ = co->tcp.nop;

  /* Needed here 'cause we'll need to initialize pseudo->len. */
  length = sizeof(struct tcphdr) + tcpolen;

  /* Fill PSEUDO Header structure. */
  pseudo           = buffer.ptr;

  if (co->encapsulated)
  {
    pseudo->saddr    = gre_ip->saddr;
    pseudo->daddr    = gre_ip->daddr;
  }
  else
  {
    pseudo->saddr    = ip->saddr;
    pseudo->daddr    = ip->daddr;
  }

  pseudo->zero     = 0;
  pseudo->protocol = co->ip.protocol;
  pseudo->len      = htons(length);

  length += sizeof(struct psdhdr);

  /* Computing the checksum. */
  tcp->check   = co->bogus_csum ? RANDOM() : cksum(tcp, length);

  gre_checksum(packet, co, *size);
}

/* TCP options size calculation. */
size_t tcp_options_len(const uint8_t tcp_options, int useMD5, int useAuth)
{
  size_t size;

  /*
   * The code starts with size '0' and it accumulates all the required
   * size if the conditionals match. Otherwise, it returns size '0'.
   */
  size = 0;

  /*
   * TCP Options has Maximum Segment Size (MSS) Option defined.
   */
  if (TEST_BITS(tcp_options, TCP_OPTION_MSS))
    size += TCPOLEN_MSS;

  /*
   * TCP Options has Window Scale (WSopt) Option defined.
   */
  if (TEST_BITS(tcp_options, TCP_OPTION_WSOPT))
    size += TCPOLEN_WSOPT;

  /*
   * TCP Options has Timestamp (TSopt) Option defined.
   */
  if (TEST_BITS(tcp_options, TCP_OPTION_TSOPT))
    size += TCPOLEN_TSOPT;

  /*
   * TCP Options has Selective Acknowledgement (SACK-Permitted) Option
   * defined.
   */
  if (TEST_BITS(tcp_options, TCP_OPTION_SACK_OK))
    size += TCPOLEN_SACK_OK;

  /*
   * TCP Options has Connection Count (CC) Option defined.
   */
  if (TEST_BITS(tcp_options, TCP_OPTION_CC))
    size += TCPOLEN_CC;

  /*
   * TCP Options has CC.NEW or CC.ECHO Option defined.
   */
  if (TEST_BITS(tcp_options, TCP_OPTION_CC_NEXT))
    size += TCPOLEN_CC;

  /*
   * TCP Options has Selective Acknowledgement (SACK) Option defined.
   */
  if (TEST_BITS(tcp_options, TCP_OPTION_SACK_EDGE))
    size += TCPOLEN_SACK_EDGE(1);

  /*
   * Defining it the size should use MD5 Signature Option or the brand
   * new TCP Authentication Option (TCP-AO).
   */
  if (useMD5)
    size += TCPOLEN_MD5;

  if (useAuth)
    size += TCPOLEN_AO;

  return size;
}


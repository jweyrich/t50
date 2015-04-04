#include <common.h>

void dump_buffer(FILE *f, void *buffer, size_t size)
{
  unsigned char *p = buffer, *q = buffer;
  size_t i;
  size_t count;

  fprintf(f, "--- HEXDUMP --- (%zu bytes)", size);
  for (count = 0; count < size; count++)
  {
    if ((count % 16) == 0)
      fprintf(f, "\n%08zx: ", count);

    fprintf(f, "%02x ", *p++);
  }
  fprintf(f, "\n--- END HEXDUMP ---\n");
}

void dump_ip(FILE *f, void *buffer)
{
  struct iphdr *ip = buffer;

  fprintf(f, "--- IP DUMP ---\n"
             "  version = %u\n"
             "  ihl = %u\n"
             "  tos = 0x%02x\n"
             "  tot_len = 0x%04x\n"
             "  id = 0x%04x\n"
             "  frag_off = 0x%04x\n"
             "  ttl = 0x%02x\n"
             "  protocol = 0x%02x\n"
             "  checksum = 0x%04x\n"
             "  source address = 0x%08x\n"
             "  destination address = 0x%08x\n"
             "--- END IP DUMP ---\n",
             ip->version & 0x0f,
             ip->ihl & 0x0f,
             ip->tos,
             ntohs(ip->tot_len),
             ntohs(ip->id),
             ntohs(ip->frag_off),
             ip->ttl,
             ip->protocol,
             ntohs(ip->check),
             ntohl(ip->saddr),
             ntohl(ip->daddr));
}

void dump_psdhdr(FILE *f, void *buffer)
{
  struct psdhdr *psd = buffer;

  fprintf(f, "--- PSEUDO HEADER DUMP ---\n"
             "  source address = 0x%08x\n"
             "  destination address = 0x%08x\n"
             "  zero = 0x%02x\n"
             "  protocol = 0x%02x\n"
             "  length = 0x%04x\n"
             "--- END PSEUDO HEADER DUMP ---\n",
             ntohl(psd->saddr),
             ntohl(psd->daddr),
             psd->zero,
             psd->protocol,
             ntohs(psd->len));
}

void dump_udp(FILE *f, void *buffer)
{
  struct udphdr *udp = buffer;

  fprintf(f, "--- UDP DUMP ---\n"
             "  source port = 0x%04x\n"
             "  destination port = 0x%04x\n"
             "  length = 0x%04x\n"
             "  checksum = 0x%04x\n"
             "--- END UDP DUMP ---\n",
             ntohs(udp->source),
             ntohs(udp->dest),
             ntohs(udp->len),
             ntohs(udp->check));
}

void dump_tcp(FILE *f, void *buffer)
{
  struct tcphdr *tcp = buffer;

  fprintf(f, "--- TCP DUMP ---\n"
             "  source port = 0x%04x\n"
             "  destination port = 0x%04x\n"
             "  sequence = 0x%08x\n"
             "  acknowledge sequence = 0x%08x\n"
             "  flags (doff,fin,syn,rst,psh,ack,urg,ece,cwr) = (%u,%u,%u,%u,%u,%u,%u,%u,%u)\n"
             "  window = 0x%04x\n"
             "  checksum = 0x%04x\n"
             "  urgent pointer = 0x%04x\n"
             "--- END TCP DUMP ---\n",
             ntohs(tcp->source),
             ntohs(tcp->dest),
             ntohl(tcp->seq),
             ntohl(tcp->ack_seq),
             tcp->doff, tcp->fin, tcp->syn, tcp->rst, tcp->psh, tcp->ack, tcp->urg, tcp->ece, tcp->cwr,
             ntohs(tcp->window),
             ntohs(tcp->check),
             ntohs(tcp->urg_ptr));
}

void dump_grehdr(FILE *f, void *buffer)
{
  struct gre_hdr *gre = buffer;

  fprintf(f, "--- GRE HEADER DUMP ---\n"
             "  recursive control (3 bits) = %u\n"
             "  strict source route (s bit) = %u\n"
             "  sequence number present (S bit) = %u\n"
             "  key present (K bit) = %u\n"
             "  routing present (R bit) = %u\n"
             "  checksum present (C bit) = %u\n"
             "  version (3 bits) = %u\n"
             "  flags (5 bits) = %u\n"
             "  protocol = 0x%04x\n"
             "--- END GRE HEADER DUMP ---\n",
             gre->recur,
             gre->s,
             gre->S,
             gre->K,
             gre->R,
             gre->C,
             gre->version,
             gre->flags,
             ntohs(gre->proto));
}

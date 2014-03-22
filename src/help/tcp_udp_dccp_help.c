#include <common.h>

void tcp_udp_dccp_help(void)
{
	puts("DCCP/TCP/UDP Options:\n"
       "    --sport NUM               DCCP|TCP|UDP source port         (default RANDOM)\n"
       "    --dport NUM               DCCP|TCP|UDP destination port    (default RANDOM)\n");

}

void tcp_help(void)
{
  printf("TCP Options:\n"
         "    --acknowledge NUM         TCP ACK sequence #               (default RANDOM)\n"
         "    --sequence NUM            TCP SYN sequence #               (default RANDOM)\n"
         "    --data-offset NUM         TCP data offset                  (default %d)\n"
         " -F,--fin                     TCP FIN flag                     (default OFF)\n"
         " -S,--syn                     TCP SYN flag                     (default OFF)\n"
         " -R,--rst                     TCP RST flag                     (default OFF)\n"
         " -P,--psh                     TCP PSH flag                     (default OFF)\n"
         " -A,--ack                     TCP ACK flag                     (default OFF)\n"
         " -U,--urg                     TCP URG flag                     (default OFF)\n"
         " -E,--ece                     TCP ECE flag                     (default OFF)\n"
         " -C,--cwr                     TCP CWR flag                     (default OFF)\n"
         " -W,--window NUM              TCP Window size                  (default NONE)\n"
         "    --urg-pointer NUM         TCP URG pointer                  (default NONE)\n"
         "    --mss NUM                 TCP Maximum Segment Size         (default NONE)\n"
         "    --wscale NUM              TCP Window Scale                 (default NONE)\n"
         "    --tstamp NUM:NUM          TCP Timestamp (TSval:TSecr)      (default NONE)\n"
         "    --sack-ok                 TCP SACK-Permitted               (default OFF)\n"
         "    --ttcp-cc NUM             T/TCP Connection Count (CC)      (default NONE)\n"
         "    --ccnew NUM               T/TCP Connection Count (CC.NEW)  (default NONE)\n"
         "    --ccecho NUM              T/TCP Connection Count (CC.ECHO) (default NONE)\n"
         "    --sack NUM:NUM            TCP SACK Edges (Left:Right)      (default NONE)\n"
         "    --md5-signature           TCP MD5 signature included       (default OFF)\n"
         "    --authentication          TCP-AO authentication included   (default OFF)\n"
         "    --auth-key-id NUM         TCP-AO authentication key ID     (default 1)\n"
         "    --auth-next-key NUM       TCP-AO authentication next key   (default 1)\n"
         "    --nop                     TCP No-Operation                 (default EOL)\n\n",
         (int)(sizeof(struct tcphdr) / 4));
}

void dccp_help(void)
{
  printf("DCCP Options:\n"
         "    --dccp-data-offset NUM    DCCP data offset                 (default VARY)\n"
         "    --dccp-cscov NUM          DCCP checksum coverage           (default 0)\n"
         "    --dccp-ccval NUM          DCCP HC-Sender CCID              (default RANDOM)\n"
         "    --dccp-type NUM           DCCP type                        (default %d)\n"
         "    --dccp-extended           DCCP extend for sequence #       (default OFF)\n"
         "    --dccp-sequence-1 NUM     DCCP sequence #                  (default RANDOM)\n"
         "    --dccp-sequence-2 NUM     DCCP extended sequence #         (default RANDOM)\n"
         "    --dccp-sequence-3 NUM     DCCP sequence # low              (default RANDOM)\n"
         "    --dccp-service NUM        DCCP service code                (default RANDOM)\n"
         "    --dccp-acknowledge-1 NUM  DCCP acknowledgment # high       (default RANDOM)\n"
         "    --dccp-acknowledge-2 NUM  DCCP acknowledgment # low        (default RANDOM)\n"
         "    --dccp-reset-code NUM     DCCP reset code                  (default RANDOM)\n\n",
         DCCP_PKT_REQUEST);
}

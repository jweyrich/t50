#include <common.h>

void eigrp_help(void)
{
  printf("EIGRP Options:\n"
         "    --eigrp-opcode NUM        EIGRP opcode                     (default %d)\n"
         "    --eigrp-flags NUM         EIGRP flags                      (default RANDOM)\n"
         "    --eigrp-sequence NUM      EIGRP sequence #                 (default RANDOM)\n"
         "    --eigrp-acknowledge NUM   EIGRP acknowledgment #           (default RANDOM)\n"
         "    --eigrp-as NUM            EIGRP autonomous system          (default RANDOM)\n"
         "    --eigrp-type NUM          EIGRP type                       (default %d)\n"
         "    --eigrp-length NUM        EIGRP length                     (default NONE)\n"
         "    --eigrp-k1 NUM            EIGRP parameter K1 value         (default 1)\n"
         "    --eigrp-k2 NUM            EIGRP parameter K2 value         (default 0)\n"
         "    --eigrp-k3 NUM            EIGRP parameter K3 value         (default 1)\n"
         "    --eigrp-k4 NUM            EIGRP parameter K4 value         (default 0)\n"
         "    --eigrp-k5 NUM            EIGRP parameter K5 value         (default 0)\n"
         "    --eigrp-hold NUM          EIGRP parameter hold time        (default 360)\n"
         "    --eigrp-ios-ver NUM.NUM   EIGRP IOS release version        (default 12.4)\n"
         "    --eigrp-rel-ver NUM.NUM   EIGRP PROTO release version      (default 1.2)\n"
         "    --eigrp-next-hop ADDR     EIGRP [in|ex]ternal next-hop     (default RANDOM)\n"
         "    --eigrp-delay NUM         EIGRP [in|ex]ternal delay        (default RANDOM)\n"
         "    --eigrp-bandwidth NUM     EIGRP [in|ex]ternal bandwidth    (default RANDOM)\n"
         "    --eigrp-mtu NUM           EIGRP [in|ex]ternal MTU          (default 1500)\n"
         "    --eigrp-hop-count NUM     EIGRP [in|ex]ternal hop count    (default RANDOM)\n"
         "    --eigrp-load NUM          EIGRP [in|ex]ternal load         (default RANDOM)\n"
         "    --eigrp-reliability NUM   EIGRP [in|ex]ternal reliability  (default RANDOM)\n"
         "    --eigrp-daddr ADDR/CIDR   EIGRP [in|ex]ternal address(es)  (default RANDOM)\n"
         "    --eigrp-src-router ADDR   EIGRP external source router     (default RANDOM)\n"
         "    --eigrp-src-as NUM        EIGRP external autonomous system (default RANDOM)\n"
         "    --eigrp-tag NUM           EIGRP external arbitrary tag     (default RANDOM)\n"
         "    --eigrp-proto-metric NUM  EIGRP external protocol metric   (default RANDOM)\n"
         "    --eigrp-proto-id NUM      EIGRP external protocol ID       (default 2)\n"
         "    --eigrp-ext-flags NUM     EIGRP external flags             (default RANDOM)\n"
         "    --eigrp-address ADDR      EIGRP multicast sequence address (default RANDOM)\n"
         "    --eigrp-multicast NUM     EIGRP multicast sequence #       (default RANDOM)\n"
         "    --eigrp-authentication    EIGRP authentication included    (default OFF)\n"
         "    --eigrp-auth-key-id NUM   EIGRP authentication key ID      (default 1)\n\n",
         EIGRP_OPCODE_UPDATE,
         EIGRP_TYPE_INTERNAL);
}

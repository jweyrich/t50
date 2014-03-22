#include <common.h>

void egp_help(void)
{
  printf("EGP Options:\n"
         "    --egp-type NUM            EGP type                         (default %d)\n"
         "    --egp-code NUM            EGP code                         (default %d)\n"
         "    --egp-status NUM          EGP status                       (default %d)\n"
         "    --egp-as NUM              EGP autonomous system            (default RANDOM)\n"
         "    --egp-sequence NUM        EGP sequence #                   (default RANDOM)\n"
         "    --egp-hello NUM           EGP hello interval               (default RANDOM)\n"
         "    --egp-poll NUM            EGP poll interval                (default RANDOM)\n\n",
         EGP_NEIGHBOR_ACQUISITION,
         EGP_ACQ_CODE_CEASE_CMD,
         EGP_ACQ_STAT_ACTIVE_MODE);
}

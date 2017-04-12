/* vim: set ts=2 et sw=2 : */
/** @file ospf_help.c */
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

#include <stdio.h>
#include <t50_modules.h>

/** OSPF options help. */
void ospf_help(void)
{
  printf("OSPF Options:\n"
         "    --ospf-type NUM           OSPF type                        (default %d)\n"
         "    --ospf-length NUM         OSPF length                      (default NONE)\n"
         "    --ospf-router-id ADDR     OSPF router ID                   (default RANDOM)\n"
         "    --ospf-area-id ADDR       OSPF area ID                     (default 0.0.0.0)\n"
         " -1,--ospf-option-MT          OSPF multi-topology / TOS-based  (default RANDOM)\n"
         " -2,--ospf-option-E           OSPF external routing capability (default RANDOM)\n"
         " -3,--ospf-option-MC          OSPF multicast capable           (default RANDOM)\n"
         " -4,--ospf-option-NP          OSPF NSSA supported              (default RANDOM)\n"
         " -5,--ospf-option-L           OSPF LLS data block contained    (default RANDOM)\n"
         " -6,--ospf-option-DC          OSPF demand circuits supported   (default RANDOM)\n"
         " -7,--ospf-option-O           OSPF Opaque-LSA                  (default RANDOM)\n"
         " -8,--ospf-option-DN          OSPF DOWN bit                    (default RANDOM)\n"
         "    --ospf-netmask ADDR       OSPF router subnet mask          (default RANDOM)\n"
         "    --ospf-hello-interval NUM OSPF HELLO interval              (default RANDOM)\n"
         "    --ospf-hello-priority NUM OSPF HELLO router priority       (default 1)\n"
         "    --ospf-hello-dead NUM     OSPF HELLO router dead interval  (default 360)\n"
         "    --ospf-hello-design ADDR  OSPF HELLO designated router     (default RANDOM)\n"
         "    --ospf-hello-backup ADDR  OSPF HELLO backup designated     (default RANDOM)\n"
         "    --ospf-neighbor NUM       OSPF HELLO # of neighbor(s)      (default NONE)\n"
         "    --ospf-address ADDR,...   OSPF HELLO neighbor address(es)  (default RANDOM)\n"
         "    --ospf-dd-mtu NUM         OSPF DD MTU                      (default 1500)\n"
         "    --ospf-dd-dbdesc-MS       OSPF DD master/slave bit option  (default RANDOM)\n"
         "    --ospf-dd-dbdesc-M        OSPF DD more bit option          (default RANDOM)\n"
         "    --ospf-dd-dbdesc-I        OSPF DD init bit option          (default RANDOM)\n"
         "    --ospf-dd-dbdesc-R        OSPF DD out-of-band resync       (default RANDOM)\n"
         "    --ospf-dd-sequence NUM    OSPF DD sequence #               (default RANDOM)\n"
         "    --ospf-dd-include-lsa     OSPF DD include LSA header       (default OFF)\n"
         "    --ospf-lsa-age NUM        OSPF LSA age                     (default 360)\n"
         "    --ospf-lsa-do-not-age     OSPF LSA do not age              (default OFF)\n"
         "    --ospf-lsa-type NUM       OSPF LSA type                    (default %d)\n"
         "    --ospf-lsa-id ADDR        OSPF LSA ID address              (default RANDOM)\n"
         "    --ospf-lsa-router ADDR    OSPF LSA advertising router      (default RANDOM)\n"
         "    --ospf-lsa-sequence NUM   OSPF LSA sequence #              (default RANDOM)\n"
         "    --ospf-lsa-metric NUM     OSPF LSA metric                  (default RANDOM)\n"
         "    --ospf-lsa-flag-B         OSPF Router-LSA border router    (default RANDOM)\n"
         "    --ospf-lsa-flag-E         OSPF Router-LSA external router  (default RANDOM)\n"
         "    --ospf-lsa-flag-V         OSPF Router-LSA virtual router   (default RANDOM)\n"
         "    --ospf-lsa-flag-W         OSPF Router-LSA wild router      (default RANDOM)\n"
         "    --ospf-lsa-flag-NT        OSPF Router-LSA NSSA translation (default RANDOM)\n"
         "    --ospf-lsa-link-id ADDR   OSPF Router-LSA link ID          (default RANDOM)\n"
         "    --ospf-lsa-link-data ADDR OSPF Router-LSA link data        (default RANDOM)\n"
         "    --ospf-lsa-link-type NUM  OSPF Router-LSA link type        (default %d)\n"
         "    --ospf-lsa-attached ADDR  OSPF Network-LSA attached router (default RANDOM)\n"
         "    --ospf-lsa-larger         OSPF ASBR/NSSA-LSA ext. larger   (default OFF)\n"
         "    --ospf-lsa-forward ADDR   OSPF ASBR/NSSA-LSA forward       (default RANDOM)\n"
         "    --ospf-lsa-external ADDR  OSPF ASBR/NSSA-LSA external      (default RANDOM)\n"
         "    --ospf-vertex-router      OSPF Group-LSA type router       (default RANDOM)\n"
         "    --ospf-vertex-network     OSPF Group-LSA type network      (default RANDOM)\n"
         "    --ospf-vertex-id ADDR     OSPF Group-LSA vertex ID         (default RANDOM)\n"
         "    --ospf-lls-extended-LR    OSPF LLS Extended option LR      (default OFF)\n"
         "    --ospf-lls-extended-RS    OSPF LLS Extended option RS      (default OFF)\n"
         "    --ospf-authentication     OSPF authentication included     (default OFF)\n"
         "    --ospf-auth-key-id NUM    OSPF authentication key ID       (default 1)\n"
         "    --ospf-auth-sequence NUM  OSPF authentication sequence #   (default RANDOM)\n\n",
         OSPF_TYPE_HELLO,
         LSA_TYPE_ROUTER,
         LINK_TYPE_PTP);
}


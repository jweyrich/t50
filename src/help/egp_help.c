/* vim: set ts=2 et sw=2 : */
/** @file egp_help.c */
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

/** EGP help */
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


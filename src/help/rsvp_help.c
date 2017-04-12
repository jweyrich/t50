/* vim: set ts=2 et sw=2 : */
/** @file rsvp_help.c */
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

/** RSVP options help. */
void rsvp_help(void)
{
  puts("RSVP Options:\n"
       "    --rsvp-flags NUM          RSVP flags                       (default 1)\n"
       "    --rsvp-type NUM           RSVP message type                (default 1)\n"
       "    --rsvp-ttl NUM            RSVP time to live                (default 254)\n"
       "    --rsvp-session-addr ADDR  RSVP SESSION destination address (default RANDOM)\n"
       "    --rsvp-session-proto NUM  RSVP SESSION protocol ID         (default 1)\n"
       "    --rsvp-session-flags NUM  RSVP SESSION flags               (default 1)\n"
       "    --rsvp-session-port NUM   RSVP SESSION destination port    (default RANDOM)\n"
       "    --rsvp-hop-addr ADDR      RSVP HOP neighbor address        (default RANDOM)\n"
       "    --rsvp-hop-iface NUM      RSVP HOP logical interface       (default RANDOM)\n"
       "    --rsvp-time-refresh NUM   RSVP TIME refresh interval       (default 360)\n"
       "    --rsvp-error-addr ADDR    RSVP ERROR node address          (default RANDOM)\n"
       "    --rsvp-error-flags NUM    RSVP ERROR flags                 (default 2)\n"
       "    --rsvp-error-code NUM     RSVP ERROR code                  (default 2)\n"
       "    --rsvp-error-value NUM    RSVP ERROR value                 (default 8)\n"
       "    --rsvp-scope NUM          RSVP SCOPE # of address(es)      (default 1)\n"
       "    --rsvp-address ADDR,...   RSVP SCOPE address(es)           (default RANDOM)\n"
       "    --rsvp-style-option NUM   RSVP STYLE option vector         (default 18)\n"
       "    --rsvp-sender-addr ADDR   RSVP SENDER TEMPLATE address     (default RANDOM)\n"
       "    --rsvp-sender-port NUM    RSVP SENDER TEMPLATE port        (default RANDOM)\n"
       "    --rsvp-tspec-traffic      RSVP TSPEC service traffic       (default OFF)\n"
       "    --rsvp-tspec-guaranteed   RSVP TSPEC service guaranteed    (default OFF)\n"
       "    --rsvp-tspec-r NUM        RSVP TSPEC token bucket rate     (default RANDOM)\n"
       "    --rsvp-tspec-b NUM        RSVP TSPEC token bucket size     (default RANDOM)\n"
       "    --rsvp-tspec-p NUM        RSVP TSPEC peak data rate        (default RANDOM)\n"
       "    --rsvp-tspec-m NUM        RSVP TSPEC minimum policed unit  (default RANDOM)\n"
       "    --rsvp-tspec-M NUM        RSVP TSPEC maximum packet size   (default RANDOM)\n"
       "    --rsvp-adspec-ishop NUM   RSVP ADSPEC IS HOP count         (default RANDOM)\n"
       "    --rsvp-adspec-path NUM    RSVP ADSPEC path b/w estimate    (default RANDOM)\n"
       "    --rsvp-adspec-m NUM       RSVP ADSPEC minimum path latency (default RANDOM)\n"
       "    --rsvp-adspec-mtu NUM     RSVP ADSPEC composed MTU         (default RANDOM)\n"
       "    --rsvp-adspec-guaranteed  RSVP ADSPEC service guaranteed   (default OFF)\n"
       "    --rsvp-adspec-Ctot NUM    RSVP ADSPEC ETE composed value C (default RANDOM)\n"
       "    --rsvp-adspec-Dtot NUM    RSVP ADSPEC ETE composed value D (default RANDOM)\n"
       "    --rsvp-adspec-Csum NUM    RSVP ADSPEC SLR point composed C (default RANDOM)\n"
       "    --rsvp-adspec-Dsum NUM    RSVP ADSPEC SLR point composed D (default RANDOM)\n"
       "    --rsvp-adspec-controlled  RSVP ADSPEC service controlled   (default OFF)\n"
       "    --rsvp-confirm-addr ADDR  RSVP CONFIRM receiver address    (default RANDOM)\n");
}

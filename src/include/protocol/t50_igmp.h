/* vim: set ts=2 et sw=2 : */
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

#ifndef __IGMP_H__
#define __IGMP_H__

/** IGMP Header DEFINITIONS. */
#define IGMPV3_TLEN_NSRCS(foo) ((foo) * sizeof(in_addr_t))

/** Calculating IGMPv3 Header length */
#define igmpv3_hdr_len(foo, bar) \
  ((((foo) == IGMPV3_HOST_MEMBERSHIP_REPORT) ? \
    sizeof(struct igmpv3_report) + sizeof(struct igmpv3_grec) : \
    sizeof(struct igmpv3_query)) + IGMPV3_TLEN_NSRCS((bar)))

#endif  /* __IGMP_H */

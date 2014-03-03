#include <common.h>

/* NOTE: A simple way to define the protocols table! 

	To add a procotol, insert the proper header file on common.h (ex: protocol/xpto.h),
  change the Makefile, add a MODULE_ENTRY and compile. That's it! */
BEGIN_MODULES_TABLE
           /* ( proto,        acronym,  description,                                  function ) */
  MODULE_ENTRY(IPPROTO_ICMP,  "ICMP", 	"Internet Control Message Protocol", 					icmp)
  MODULE_ENTRY(IPPROTO_IGMP,  "IGMPv1", "Internet Group Message Protocol v1", 				igmpv1)
  MODULE_ENTRY(IPPROTO_IGMP,  "IGMPv3", "Internet Group Message Protocol v3", 				igmpv3)
  MODULE_ENTRY(IPPROTO_TCP,   "TCP", 		"Transmission Control Protocol", 							tcp)
  MODULE_ENTRY(IPPROTO_EGP,   "EGP", 		"Exterior Gateway Protocol", 									egp)
  MODULE_ENTRY(IPPROTO_UDP,   "UDP", 		"User Datagram Protocol", 										udp)
  MODULE_ENTRY(IPPROTO_UDP,   "RIPv1", 	"Routing Internet Protocol v1", 							ripv1)
  MODULE_ENTRY(IPPROTO_UDP,   "RIPv2", 	"Routing Internet Protocol v2", 							ripv2)
  MODULE_ENTRY(IPPROTO_DCCP,  "DCCP", 	"Datagram Congestion Control Protocol", 			dccp)
  MODULE_ENTRY(IPPROTO_RSVP,  "RSVP", 	"Resource Reservation Protocol", 							rsvp)
  MODULE_ENTRY(IPPROTO_AH,    "IPSEC", 	"Internet Security Protocl (AH/ESP)", 				ipsec)
  MODULE_ENTRY(IPPROTO_EIGRP, "EIGRP", 	"Enhanced Interior Gateway Routing Protocol", eigrp)
  MODULE_ENTRY(IPPROTO_OSPF,  "OSPF", 	"Open Shortest Path First", 									ospf)
END_MODULES_TABLE

#ifndef __HELP_INCLUDED__
#define __HELP_INCLUDED__

/* Add usage function interface here.
   Add usage function definition for protocol at src/help/ directory.
   Change Makefile and src/usage.c. */
extern void general_help(void);
extern void gre_help(void);
extern void tcp_udp_dccp_help(void);
extern void ip_help(void);
extern void icmp_help(void);
extern void egp_help(void);
extern void rip_help(void);
extern void dccp_help(void);
extern void rsvp_help(void);
extern void ipsec_help(void);
extern void eigrp_help(void);
extern void ospf_help(void);

#endif

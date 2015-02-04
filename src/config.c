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

#include <common.h>
#include <regex.h>    /* there is regex in libc6! */


/* Default command line interface options. */
/* NOTE: Using GCC structure initialization extension to
         make sure that all fields are initialized correctly. */
/* NOTE: As C standandard goes, any field not explicitly initialized
         will be filled with zero. */
static struct config_options co = {
  /* XXX COMMON OPTIONS                                                         */
  .threshold = 1000,                  /* default threshold                      */

  /* XXX IP HEADER OPTIONS  (IPPROTO_IP = 0)                                    */
  .ip = {
    .tos = IPTOS_PREC_IMMEDIATE,      /* default type of service                */
    .ttl = 255                        /* default time to live                   */
  },

  /* XXX ICMP HEADER OPTIONS (IPPROTO_ICMP = 1)                                 */
  .icmp = { .type = ICMP_ECHO },     /* default type                           */

  /* XXX IGMP HEADER OPTIONS (IPPROTO_IGMP = 2)                                 */
  .igmp = {
    .type = IGMP_HOST_MEMBERSHIP_QUERY, /* default type                           */
    .grec_type = 1,                     /* default group record type              */
    .sources = 2                        /* default number of sources              */
  },

  /* XXX TCP HEADER OPTIONS (IPPROTO_TCP = 6)                                   */
  .tcp = {
    .key_id = 1,                     /* default AO key ID         (RFC5925)    */
    .next_key = 1,                   /* default AO next key ID    (RFC5925)    */
    .nop = TCPOPT_EOL                /* default NOP option        (RFC793)     */
  },

  /* XXX EGP HEADER OPTIONS (IPPROTO_EGP = 8)                                   */
  .egp = {
    .type = EGP_NEIGHBOR_ACQUISITION,     /* default type                           */
    .code = EGP_ACQ_CODE_CEASE_CMD,       /* default code                           */
    .status = EGP_ACQ_STAT_ACTIVE_MODE    /* default status                         */
  },

  /* XXX RIP HEADER OPTIONS (IPPROTO_UDP = 17)                                  */
  .rip = {
    .command = 2,                    /* default command                        */
    .family = AF_INET,               /* default address family identifier      */
    .key_id = 1                      /* default authentication key ID          */
  },

  /* XXX DCCP HEADER OPTIONS (IPPROTO_DCCP = 33)                                */
  .dccp = { .type = DCCP_PKT_REQUEST }, /* default type                           */

  /* XXX RSVP HEADER OPTIONS (IPPROTO_RSVP = 46)                                */
  .rsvp = {
    .flags = 1,                      /* default flags                          */
    .type = RSVP_MESSAGE_TYPE_PATH,  /* default message type                   */
    .ttl = 254,                      /* default time to live                   */
    .session_proto = 1,              /* default SESSION protocol ID            */
    .session_flags = 1,              /* default SESSION flags                  */
    .time_refresh = 360,             /* default TIME refresh interval          */
    .error_flags = 2,                /* default ERROR flags                    */
    .error_code = 2,                 /* default ERROR code                     */
    .error_value = 8,                /* default ERROR value                    */
    .scope = 1,                      /* default number of SCOPE(s)             */
    .style_opt = 18,                 /* default STYLE option vector            */
    .tspec = 6                       /* default TSPEC service                  */
  },

  /* XXX EIGRP HEADER OPTIONS (IPPROTO_EIGRP = 88)                              */
  .eigrp = {
    .opcode = EIGRP_OPCODE_UPDATE,   /* default opcode                         */
    .type = EIGRP_TYPE_INTERNAL,     /* default type                           */
    .k1 = 1,                         /* default K1 value                       */
    .k3 = 1,                         /* default K3 value                       */
    .hold = 360,                     /* default hold time                      */
    .ios_major = 12,                 /* default IOS Major Version              */
    .ios_minor = 4,                  /* default IOS Minor Version              */
    .ver_major = 1,                  /* default EIGRP Major Version            */
    .ver_minor = 2,                  /* default EIGRP Minor Version            */
    .mtu = 1500,                     /* default maximum transmission unit      */
    .proto_id = 2,                   /* default external protocol ID           */
    .key_id = 1                      /* default authentication key ID          */
  },

  /* XXX OSPF HEADER OPTIONS (IPPROTO_OSPF = 89)                                */
  .ospf = {
    .type = OSPF_TYPE_HELLO,         /* default type                           */
    .hello_priority = 1,             /* default HELLO router priority          */
    .hello_dead = 360,               /* default HELLO router dead interval     */
    .dd_mtu = 1500,                  /* default DD MTU                         */
    .lsa_age = 360,                  /* default LSA age                        */
    .lsa_type = LSA_TYPE_ROUTER,     /* default LSA header type                */
    .lsa_link_type = LINK_TYPE_PTP,  /* default Router-LSA link type           */
    .key_id = 1                       /* default authentication key ID          */
  }

    /* NOTE: Add configuration structured values for new protocols here! */
};

/* NOTE: Declare long_opt[] here as static makes sense! */
static const struct option long_opt[] = {
  /* XXX COMMON OPTIONS                                                             */
  { "threshold",              required_argument, NULL, OPTION_THRESHOLD              },
  { "flood",                  no_argument,       NULL, OPTION_FLOOD                  },
  { "encapsulated",           no_argument,       NULL, OPTION_ENCAPSULATED           },
  { "bogus-csum",             no_argument,       NULL, 'B'                           },
#ifdef  __HAVE_TURBO__
  { "turbo",                  no_argument,       NULL, OPTION_TURBO                  },
#endif  /* __HAVE_TURBO__ */
  { "version",                no_argument,       NULL, 'v'                           },
  { "help",                   no_argument,       NULL, 'h'                           },

  /* XXX GRE HEADER OPTIONS (IPPROTO_GRE = 47)                                       */
  { "gre-seq-present",        no_argument,       NULL, OPTION_GRE_SEQUENCE_PRESENT   },
  { "gre-key-present",        no_argument,       NULL, OPTION_GRE_KEY_PRESENT        },
  { "gre-sum-present",        no_argument,       NULL, OPTION_GRE_CHECKSUM_PRESENT   },
  { "gre-key",                required_argument, NULL, OPTION_GRE_KEY                },
  { "gre-sequence",           required_argument, NULL, OPTION_GRE_SEQUENCE           },
  { "gre-saddr",              required_argument, NULL, OPTION_GRE_SADDR              },
  { "gre-daddr",              required_argument, NULL, OPTION_GRE_DADDR              },

  /* XXX DCCP, TCP & UDP HEADER OPTIONS                                              */
  { "sport",                  required_argument, NULL, OPTION_SOURCE                 },
  { "dport",                  required_argument, NULL, OPTION_DESTINATION            },

  /* XXX IP HEADER OPTIONS  (IPPROTO_IP = 0)                                         */
  { "saddr",                  required_argument, NULL, 's'                           },
  { "tos",                    required_argument, NULL, OPTION_IP_TOS                 },
  { "id",                     required_argument, NULL, OPTION_IP_ID                  },
  { "frag-offset",            required_argument, NULL, OPTION_IP_OFFSET              },
  { "ttl",                    required_argument, NULL, OPTION_IP_TTL                 },
  { "protocol",               required_argument, NULL, OPTION_IP_PROTOCOL            },

  /* XXX ICMP HEADER OPTIONS (IPPROTO_ICMP = 1)                                      */
  { "icmp-type",              required_argument, NULL, OPTION_ICMP_TYPE              },
  { "icmp-code",              required_argument, NULL, OPTION_ICMP_CODE              },
  { "icmp-gateway",           required_argument, NULL, OPTION_ICMP_GATEWAY           },
  { "icmp-id",                required_argument, NULL, OPTION_ICMP_ID                },
  { "icmp-sequence",          required_argument, NULL, OPTION_ICMP_SEQUENCE          },

  /* XXX IGMP HEADER OPTIONS (IPPROTO_IGMP = 2)                                      */
  { "igmp-type",              required_argument, NULL, OPTION_IGMP_TYPE              },
  { "igmp-code",              required_argument, NULL, OPTION_IGMP_CODE              },
  { "igmp-group",             required_argument, NULL, OPTION_IGMP_GROUP             },
  { "igmp-qrv",               required_argument, NULL, OPTION_IGMP_QRV               },
  { "igmp-suppress",          no_argument,       NULL, OPTION_IGMP_SUPPRESS          },
  { "igmp-qqic",              required_argument, NULL, OPTION_IGMP_QQIC              },
  { "igmp-grec-type",         required_argument, NULL, OPTION_IGMP_GREC_TYPE         },
  { "igmp-sources",           required_argument, NULL, OPTION_IGMP_SOURCES           },
  { "igmp-multicast",         required_argument, NULL, OPTION_IGMP_GREC_MULTICAST    },
  { "igmp-address",           required_argument, NULL, OPTION_IGMP_ADDRESS           },

  /* XXX TCP HEADER OPTIONS (IPPROTO_TCP = 6)                                        */
  { "acknowledge",            required_argument, NULL, OPTION_TCP_ACKNOWLEDGE        },
  { "sequence",               required_argument, NULL, OPTION_TCP_SEQUENCE           },
  { "data-offset",            required_argument, NULL, OPTION_TCP_OFFSET             },
  { "fin",                    no_argument,       NULL, 'F'                           },
  { "syn",                    no_argument,       NULL, 'S'                           },
  { "rst",                    no_argument,       NULL, 'R'                           },
  { "psh",                    no_argument,       NULL, 'P'                           },
  { "ack",                    no_argument,       NULL, 'A'                           },
  { "urg",                    no_argument,       NULL, 'U'                           },
  { "ece",                    no_argument,       NULL, 'E'                           },
  { "cwr",                    no_argument,       NULL, 'C'                           },
  { "window",                 required_argument, NULL, 'W'                           },
  { "urg-pointer",            required_argument, NULL, OPTION_TCP_URGENT_POINTER     },
  { "mss",                    required_argument, NULL, OPTION_TCP_MSS                },
  { "wscale",                 required_argument, NULL, OPTION_TCP_WSOPT              },
  { "tstamp",                 required_argument, NULL, OPTION_TCP_TSOPT              },
  { "sack-ok",                no_argument,       NULL, OPTION_TCP_SACK_OK            },
  { "cc",                     required_argument, NULL, OPTION_TCP_CC                 },
  { "ccnew",                  required_argument, NULL, OPTION_TCP_CC_NEW             },
  { "ccecho",                 required_argument, NULL, OPTION_TCP_CC_ECHO            },
  { "sack",                   required_argument, NULL, OPTION_TCP_SACK_EDGE          },
  { "md5-signature",          no_argument,       NULL, OPTION_TCP_MD5_SIGNATURE      },
  { "authentication",         no_argument,       NULL, OPTION_TCP_AUTHENTICATION     },
  { "auth-key-id",            required_argument, NULL, OPTION_TCP_AUTH_KEY_ID        },
  { "auth-next-key",          required_argument, NULL, OPTION_TCP_AUTH_NEXT_KEY      },
  { "nop",                    no_argument,       NULL, OPTION_TCP_NOP                },

  /* XXX EGP HEADER OPTIONS (IPPROTO_EGP = 8)                                        */
  { "egp-type",               required_argument, NULL, OPTION_EGP_TYPE               },
  { "egp-code",               required_argument, NULL, OPTION_EGP_CODE               },
  { "egp-status",             required_argument, NULL, OPTION_EGP_STATUS             },
  { "egp-as",                 required_argument, NULL, OPTION_EGP_AS                 },
  { "egp-sequence",           required_argument, NULL, OPTION_EGP_SEQUENCE           },
  { "egp-hello",              required_argument, NULL, OPTION_EGP_HELLO              },
  { "egp-poll",               required_argument, NULL, OPTION_EGP_POLL               },

  /* XXX RIP HEADER OPTIONS (IPPROTO_UDP = 17)                                       */
  { "rip-command",            required_argument, NULL, OPTION_RIP_COMMAND            },
  { "rip-family",             required_argument, NULL, OPTION_RIP_FAMILY             },
  { "rip-address",            required_argument, NULL, OPTION_RIP_ADDRESS            },
  { "rip-metric",             required_argument, NULL, OPTION_RIP_METRIC             },
  { "rip-domain",             required_argument, NULL, OPTION_RIP_DOMAIN             },
  { "rip-tag",                required_argument, NULL, OPTION_RIP_TAG                },
  { "rip-netmask",            required_argument, NULL, OPTION_RIP_NETMASK            },
  { "rip-next-hop",           required_argument, NULL, OPTION_RIP_NEXTHOP            },
  { "rip-authentication",     no_argument,       NULL, OPTION_RIP_AUTHENTICATION     },
  { "rip-auth-key-id",        required_argument, NULL, OPTION_RIP_AUTH_KEY_ID        },
  { "rip-auth-sequence",      required_argument, NULL, OPTION_RIP_AUTH_SEQUENCE      },

  /* XXX DCCP HEADER OPTIONS (IPPROTO_DCCP = 33)                                     */
  { "dccp-data-offset",       required_argument, NULL, OPTION_DCCP_OFFSET            },
  { "dccp-cscov",             required_argument, NULL, OPTION_DCCP_CSCOV             },
  { "dccp-ccval",             required_argument, NULL, OPTION_DCCP_CCVAL             },
  { "dccp-type",              required_argument, NULL, OPTION_DCCP_TYPE              },
  { "dccp-extended",          no_argument,       NULL, OPTION_DCCP_EXTEND            },
  { "dccp-sequence-1",        required_argument, NULL, OPTION_DCCP_SEQUENCE_01       },
  { "dccp-sequence-2",        required_argument, NULL, OPTION_DCCP_SEQUENCE_02       },
  { "dccp-sequence-3",        required_argument, NULL, OPTION_DCCP_SEQUENCE_03       },
  { "dccp-service",           required_argument, NULL, OPTION_DCCP_SERVICE           },
  { "dccp-acknowledge-1",     required_argument, NULL, OPTION_DCCP_ACKNOWLEDGE_01    },
  { "dccp-acknowledge-2",     required_argument, NULL, OPTION_DCCP_ACKNOWLEDGE_02    },
  { "dccp-reset-code",        required_argument, NULL, OPTION_DCCP_RESET_CODE        },

  /* XXX RSVP HEADER OPTIONS (IPPROTO_RSVP = 46)                                     */
  { "rsvp-flags",             required_argument, NULL, OPTION_RSVP_FLAGS             },
  { "rsvp-type",              required_argument, NULL, OPTION_RSVP_TYPE              },
  { "rsvp-ttl",               required_argument, NULL, OPTION_RSVP_TTL               },
  { "rsvp-session-addr",      required_argument, NULL, OPTION_RSVP_SESSION_ADDRESS   },
  { "rsvp-session-proto",     required_argument, NULL, OPTION_RSVP_SESSION_PROTOCOL  },
  { "rsvp-session-flags",     required_argument, NULL, OPTION_RSVP_SESSION_FLAGS     },
  { "rsvp-session-port",      required_argument, NULL, OPTION_RSVP_SESSION_PORT      },
  { "rsvp-hop-addr",          required_argument, NULL, OPTION_RSVP_HOP_ADDRESS       },
  { "rsvp-hop-iface",         required_argument, NULL, OPTION_RSVP_HOP_IFACE         },
  { "rsvp-time-refresh",      required_argument, NULL, OPTION_RSVP_TIME_REFRESH      },
  { "rsvp-error-addr",        required_argument, NULL, OPTION_RSVP_ERROR_ADDRESS     },
  { "rsvp-error-flags",       required_argument, NULL, OPTION_RSVP_ERROR_FLAGS       },
  { "rsvp-error-code",        required_argument, NULL, OPTION_RSVP_ERROR_CODE        },
  { "rsvp-error-value",       required_argument, NULL, OPTION_RSVP_ERROR_VALUE       },
  { "rsvp-scope",             required_argument, NULL, OPTION_RSVP_SCOPE             },
  { "rsvp-address",           required_argument, NULL, OPTION_RSVP_SCOPE_ADDRESS     },
  { "rsvp-style-option",      required_argument, NULL, OPTION_RSVP_STYLE_OPTION      },
  { "rsvp-sender-addr",       required_argument, NULL, OPTION_RSVP_SENDER_ADDRESS    },
  { "rsvp-sender-port",       required_argument, NULL, OPTION_RSVP_SENDER_PORT       },
  { "rsvp-tspec-traffic",     no_argument,       NULL, OPTION_RSVP_TSPEC_TRAFFIC     },
  { "rsvp-tspec-guaranteed",  no_argument,       NULL, OPTION_RSVP_TSPEC_GUARANTEED  },
  { "rsvp-tspec-r",           required_argument, NULL, OPTION_RSVP_TSPEC_TOKEN_R     },
  { "rsvp-tspec-b",           required_argument, NULL, OPTION_RSVP_TSPEC_TOKEN_B     },
  { "rsvp-tspec-p",           required_argument, NULL, OPTION_RSVP_TSPEC_DATA_P      },
  { "rsvp-tspec-m",           required_argument, NULL, OPTION_RSVP_TSPEC_MINIMUM     },
  { "rsvp-tspec-M",           required_argument, NULL, OPTION_RSVP_TSPEC_MAXIMUM     },
  { "rsvp-adspec-ishop",      required_argument, NULL, OPTION_RSVP_ADSPEC_ISHOP      },
  { "rsvp-adspec-path",       required_argument, NULL, OPTION_RSVP_ADSPEC_PATH       },
  { "rsvp-adspec-m",          required_argument, NULL, OPTION_RSVP_ADSPEC_MINIMUM    },
  { "rsvp-adspec-mtu",        required_argument, NULL, OPTION_RSVP_ADSPEC_MTU        },
  { "rsvp-adspec-guaranteed", no_argument,       NULL, OPTION_RSVP_ADSPEC_GUARANTEED },
  { "rsvp-adspec-Ctot",       required_argument, NULL, OPTION_RSVP_ADSPEC_CTOT       },
  { "rsvp-adspec-Dtot",       required_argument, NULL, OPTION_RSVP_ADSPEC_DTOT       },
  { "rsvp-adspec-Csum",       required_argument, NULL, OPTION_RSVP_ADSPEC_CSUM       },
  { "rsvp-adspec-Dsum",       required_argument, NULL, OPTION_RSVP_ADSPEC_DSUM       },
  { "rsvp-adspec-controlled", no_argument,       NULL, OPTION_RSVP_ADSPEC_CONTROLLED },
  { "rsvp-confirm-addr",      required_argument, NULL, OPTION_RSVP_CONFIRM_ADDR      },

  /* XXX IPSEC HEADER OPTIONS (IPPROTO_AH = 51 & IPPROTO_ESP = 50)                   */
  { "ipsec-ah-length",        required_argument, NULL, OPTION_IPSEC_AH_LENGTH        },
  { "ipsec-ah-spi",           required_argument, NULL, OPTION_IPSEC_AH_SPI           },
  { "ipsec-ah-sequence",      required_argument, NULL, OPTION_IPSEC_AH_SEQUENCE      },
  { "ipsec-esp-spi",          required_argument, NULL, OPTION_IPSEC_ESP_SPI          },
  { "ipsec-esp-sequence",     required_argument, NULL, OPTION_IPSEC_ESP_SEQUENCE     },

  /* XXX EIGRP HEADER OPTIONS (IPPROTO_EIGRP = 88)                                   */
  { "eigrp-opcode",           required_argument, NULL, OPTION_EIGRP_OPCODE           },
  { "eigrp-flags",            required_argument, NULL, OPTION_EIGRP_FLAGS            },
  { "eigrp-sequence",         required_argument, NULL, OPTION_EIGRP_SEQUENCE         },
  { "eigrp-acknowledge",      required_argument, NULL, OPTION_EIGRP_ACKNOWLEDGE      },
  { "eigrp-as",               required_argument, NULL, OPTION_EIGRP_AS               },
  { "eigrp-type",             required_argument, NULL, OPTION_EIGRP_TYPE             },
  { "eigrp-length",           required_argument, NULL, OPTION_EIGRP_LENGTH           },
  { "eigrp-k1",               required_argument, NULL, OPTION_EIGRP_K1               },
  { "eigrp-k2",               required_argument, NULL, OPTION_EIGRP_K2               },
  { "eigrp-k3",               required_argument, NULL, OPTION_EIGRP_K3               },
  { "eigrp-k4",               required_argument, NULL, OPTION_EIGRP_K4               },
  { "eigrp-k5",               required_argument, NULL, OPTION_EIGRP_K5               },
  { "eigrp-hold",             required_argument, NULL, OPTION_EIGRP_HOLD             },
  { "eigrp-ios-ver",          required_argument, NULL, OPTION_EIGRP_IOS_VERSION      },
  { "eigrp-rel-ver",          required_argument, NULL, OPTION_EIGRP_PROTO_VERSION    },
  { "eigrp-next-hop",         required_argument, NULL, OPTION_EIGRP_NEXTHOP          },
  { "eigrp-delay",            required_argument, NULL, OPTION_EIGRP_DELAY            },
  { "eigrp-bandwidth",        required_argument, NULL, OPTION_EIGRP_BANDWIDTH        },
  { "eigrp-mtu",              required_argument, NULL, OPTION_EIGRP_MTU              },
  { "eigrp-hop-count",        required_argument, NULL, OPTION_EIGRP_HOP_COUNT        },
  { "eigrp-load",             required_argument, NULL, OPTION_EIGRP_LOAD             },
  { "eigrp-reliability",      required_argument, NULL, OPTION_EIGRP_RELIABILITY      },
  { "eigrp-daddr",            required_argument, NULL, OPTION_EIGRP_DESINATION       },
  { "eigrp-src-router",       required_argument, NULL, OPTION_EIGRP_SOURCE_ROUTER    },
  { "eigrp-src-as",           required_argument, NULL, OPTION_EIGRP_SOURCE_AS        },
  { "eigrp-tag",              required_argument, NULL, OPTION_EIGRP_TAG              },
  { "eigrp-proto-metric",     required_argument, NULL, OPTION_EIGRP_METRIC           },
  { "eigrp-proto-id",         required_argument, NULL, OPTION_EIGRP_ID               },
  { "eigrp-ext-flags",        required_argument, NULL, OPTION_EIGRP_EXTERNAL_FLAGS   },
  { "eigrp-address",          required_argument, NULL, OPTION_EIGRP_ADDRESS          },
  { "eigrp-multicast",        required_argument, NULL, OPTION_EIGRP_MULTICAST        },
  { "eigrp-authentication",   no_argument,       NULL, OPTION_EIGRP_AUTHENTICATION   },
  { "eigrp-auth-key-id",      required_argument, NULL, OPTION_EIGRP_AUTH_KEY_ID      },

  /* XXX OSPF HEADER OPTIONS (IPPROTO_OSPF = 89)                                     */
  { "ospf-type",              required_argument, NULL, OPTION_OSPF_TYPE              },
  { "ospf-length",            required_argument, NULL, OPTION_OSPF_LENGTH            },
  { "ospf-router-id",         required_argument, NULL, OPTION_OSPF_ROUTER_ID         },
  { "ospf-area-id",           required_argument, NULL, OPTION_OSPF_AREA_ID           },
  { "ospf-option-MT",         no_argument,       NULL, '1'                           },
  { "ospf-option-E",          no_argument,       NULL, '2'                           },
  { "ospf-option-MC",         no_argument,       NULL, '3'                           },
  { "ospf-option-NP",         no_argument,       NULL, '4'                           },
  { "ospf-option-L",          no_argument,       NULL, '5'                           },
  { "ospf-option-DC",         no_argument,       NULL, '6'                           },
  { "ospf-option-O",          no_argument,       NULL, '7'                           },
  { "ospf-option-DN",         no_argument,       NULL, '8'                           },
  { "ospf-netmask",           required_argument, NULL, OPTION_OSPF_NETMASK           },
  { "ospf-hello-interval",    required_argument, NULL, OPTION_OSPF_HELLO_INTERVAL    },
  { "ospf-hello-priority",    required_argument, NULL, OPTION_OSPF_HELLO_PRIORITY    },
  { "ospf-hello-dead",        required_argument, NULL, OPTION_OSPF_HELLO_DEAD        },
  { "ospf-hello-design",      required_argument, NULL, OPTION_OSPF_HELLO_DESIGN      },
  { "ospf-hello-backup",      required_argument, NULL, OPTION_OSPF_HELLO_BACKUP      },
  { "ospf-neighbor",          required_argument, NULL, OPTION_OSPF_HELLO_NEIGHBOR    },
  { "ospf-address",           required_argument, NULL, OPTION_OSPF_HELLO_ADDRESS     },
  { "ospf-dd-mtu",            required_argument, NULL, OPTION_OSPF_DD_MTU            },
  { "ospf-dd-dbdesc-MS",      no_argument,       NULL, OPTION_OSPF_DD_MASTER_SLAVE   },
  { "ospf-dd-dbdesc-M",       no_argument,       NULL, OPTION_OSPF_DD_MORE           },
  { "ospf-dd-dbdesc-I",       no_argument,       NULL, OPTION_OSPF_DD_INIT           },
  { "ospf-dd-dbdesc-R",       no_argument,       NULL, OPTION_OSPF_DD_OOBRESYNC      },
  { "ospf-dd-sequence",       required_argument, NULL, OPTION_OSPF_DD_SEQUENCE       },
  { "ospf-dd-include-lsa",    no_argument,       NULL, OPTION_OSPF_DD_INCLUDE_LSA    },
  { "ospf-lsa-age",           required_argument, NULL, OPTION_OSPF_LSA_AGE           },
  { "ospf-lsa-do-not-age",    no_argument,       NULL, OPTION_OSPF_LSA_DO_NOT_AGE    },
  { "ospf-lsa-type",          required_argument, NULL, OPTION_OSPF_LSA_TYPE          },
  { "ospf-lsa-id",            required_argument, NULL, OPTION_OSPF_LSA_LSID          },
  { "ospf-lsa-router",        required_argument, NULL, OPTION_OSPF_LSA_ROUTER        },
  { "ospf-lsa-sequence",      required_argument, NULL, OPTION_OSPF_LSA_SEQUENCE      },
  { "ospf-lsa-metric",        required_argument, NULL, OPTION_OSPF_LSA_METRIC        },
  { "ospf-lsa-flag-B",        no_argument,       NULL, OPTION_OSPF_LSA_FLAG_BORDER   },
  { "ospf-lsa-flag-E",        no_argument,       NULL, OPTION_OSPF_LSA_FLAG_EXTERNAL },
  { "ospf-lsa-flag-V",        no_argument,       NULL, OPTION_OSPF_LSA_FLAG_VIRTUAL  },
  { "ospf-lsa-flag-W",        no_argument,       NULL, OPTION_OSPF_LSA_FLAG_WILD     },
  { "ospf-lsa-flag-NT",       no_argument,       NULL, OPTION_OSPF_LSA_FLAG_NSSA_TR  },
  { "ospf-lsa-link-id",       required_argument, NULL, OPTION_OSPF_LSA_LINK_ID       },
  { "ospf-lsa-link-data",     required_argument, NULL, OPTION_OSPF_LSA_LINK_DATA     },
  { "ospf-lsa-link-type",     required_argument, NULL, OPTION_OSPF_LSA_LINK_TYPE     },
  { "ospf-lsa-attached",      required_argument, NULL, OPTION_OSPF_LSA_ATTACHED      },
  { "ospf-lsa-larger",        no_argument,       NULL, OPTION_OSPF_LSA_LARGER        },
  { "ospf-lsa-forward",       required_argument, NULL, OPTION_OSPF_LSA_FORWARD       },
  { "ospf-lsa-external",      required_argument, NULL, OPTION_OSPF_LSA_EXTERNAL      },
  { "ospf-vertex-router",     no_argument,       NULL, OPTION_OSPF_VERTEX_ROUTER     },
  { "ospf-vertex-network",    no_argument,       NULL, OPTION_OSPF_VERTEX_NETWORK    },
  { "ospf-vertex-id",         required_argument, NULL, OPTION_OSPF_VERTEX_ID         },
  { "ospf-lls-extended-LR",   no_argument,       NULL, OPTIONS_OSPF_LLS_OPTION_LR    },
  { "ospf-lls-extended-RS",   no_argument,       NULL, OPTIONS_OSPF_LLS_OPTION_RS    },
  { "ospf-authentication",    no_argument,       NULL, OPTION_OSPF_AUTHENTICATION    },
  { "ospf-auth-key-id",       required_argument, NULL, OPTION_OSPF_AUTH_KEY_ID       },
  { "ospf-auth-sequence",     required_argument, NULL, OPTION_OSPF_AUTH_SEQUENCE     },

  /* NOTE: Add new long options for new protocols here! */

  /* NOTE: This MUST be at the end of this list. */
  { NULL,                     0,                 NULL, 0                             }
};

/* structure used in getConfigOptions() and getIpAndCidrFromString() */
typedef struct {
  unsigned addr;
  unsigned cidr;
} T50_tmp_addr_t;

static char **getTokensList(void);
static void listProtocols(void);
static void setDefaultModuleOption(void);
static int  getIpAndCidrFromString(char const * const, T50_tmp_addr_t *);

/* CLI options configuration */
struct config_options *getConfigOptions(int argc, char **argv)
{
  int cli_opts;
  int counter;

  char  *optionp;
  char *tmp_ptr;
  char **tokens;

  /* Used by getIpAndCidrFromString() call. */
  T50_tmp_addr_t addr;

  setDefaultModuleOption();

  /* Checking command line interface options. */
  while ( (cli_opts = getopt_long(argc, argv, "s:12345678FSRPAUECW:Bvh?", long_opt, NULL)) != -1 )
  {
    switch (cli_opts)
    {
      /* XXX COMMON OPTIONS */
      case OPTION_THRESHOLD:    co.threshold    = atol(optarg); break;
      case OPTION_FLOOD:        co.flood        = TRUE; break;
      case OPTION_ENCAPSULATED: co.encapsulated = TRUE; break;
      case 'B':                 co.bogus_csum   = TRUE; break;

#ifdef  __HAVE_TURBO__
      case OPTION_TURBO:        co.turbo        = TRUE; break;
#endif  /* __HAVE_TURBO__ */

      case OPTION_LIST_PROTOCOL:
        listProtocols();
        exit(EXIT_SUCCESS);
        break;

      /* XXX GRE HEADER OPTIONS (IPPROTO_GRE = 47) */
      case OPTION_GRE_SEQUENCE_PRESENT: co.gre.options |= GRE_OPTION_SEQUENCE;
                                        co.gre.S = TRUE; break;
      case OPTION_GRE_KEY_PRESENT:      co.gre.options |= GRE_OPTION_KEY;
                                        co.gre.K = TRUE; break;
      case OPTION_GRE_CHECKSUM_PRESENT: co.gre.options |= GRE_OPTION_CHECKSUM;
                                        co.gre.C = TRUE; break;
      case OPTION_GRE_KEY:              co.gre.key      = atol(optarg); break;
      case OPTION_GRE_SEQUENCE:         co.gre.sequence = atoi(optarg); break;
      case OPTION_GRE_SADDR:            co.gre.saddr    = resolv(optarg); break;
      case OPTION_GRE_DADDR:            co.gre.daddr    = resolv(optarg); break;

      /* XXX DCCP, TCP & UDP HEADER OPTIONS */
      case OPTION_SOURCE:       co.source = atoi(optarg); break;
      case OPTION_DESTINATION:  co.dest = atoi(optarg);   break;

      /* XXX IP HEADER OPTIONS  (IPPROTO_IP = 0) */
      case OPTION_IP_TOS:       co.ip.tos       = atoi(optarg); break;
      case OPTION_IP_ID:        co.ip.id        = atoi(optarg); break;
      case OPTION_IP_OFFSET:    co.ip.frag_off  = atoi(optarg); break;
      case OPTION_IP_TTL:       co.ip.ttl       = atoi(optarg); break;
      case 's':                 co.ip.saddr     = resolv(optarg); break;
      case OPTION_IP_PROTOCOL:
        optionp = optarg;

        tokens = getTokensList();

        while (*optionp != '\0')
        {
          char *valuep;

          counter = getsubopt(&optionp, tokens, &valuep);
          if (counter == -1)
          {
            fprintf(stderr,
                "%s(): Protocol %s is not implemented\n",
                __FUNCTION__,
                optarg);
            exit(EXIT_FAILURE);
          }

          if (strcasecmp(tokens[counter], "T50") == 0)
            co.ip.protocol = IPPROTO_T50;
          else
            co.ip.protocol = mod_table[counter].protocol_id;
          co.ip.protoname = counter;
        }

        free(tokens); /* Don't need the tokens list anymore! */
        break;

      /* XXX ICMP HEADER OPTIONS (IPPROTO_ICMP = 1) */
      case OPTION_ICMP_TYPE:      co.icmp.type = atoi(optarg); break;
      case OPTION_ICMP_CODE:      co.icmp.code = atoi(optarg); break;
      case OPTION_ICMP_ID:        co.icmp.id = atoi(optarg); break;
      case OPTION_ICMP_SEQUENCE:  co.icmp.sequence = atoi(optarg); break;
      case OPTION_ICMP_GATEWAY:   co.icmp.gateway = resolv(optarg); break;

      /* XXX IGMP HEADER OPTIONS (IPPROTO_IGMP = 2) */
      case OPTION_IGMP_TYPE:            co.igmp.type = atoi(optarg); break;
      case OPTION_IGMP_CODE:            co.igmp.code = atoi(optarg); break;
      case OPTION_IGMP_GROUP:           co.igmp.group = resolv(optarg); break;
      case OPTION_IGMP_QRV:             co.igmp.qrv = atoi(optarg); break;
      case OPTION_IGMP_SUPPRESS:        co.igmp.suppress = 1;  break;
      case OPTION_IGMP_QQIC:            co.igmp.qqic = atoi(optarg); break;
      case OPTION_IGMP_GREC_TYPE:       co.igmp.grec_type = atoi(optarg); break;
      case OPTION_IGMP_SOURCES:         co.igmp.sources = atoi(optarg); break;
      case OPTION_IGMP_GREC_MULTICAST:  co.igmp.grec_mca = resolv(optarg); break;
      case OPTION_IGMP_ADDRESS:
        for (counter = 0, tmp_ptr = strtok(optarg, ",");
             tmp_ptr && (counter < (int)(sizeof(co.igmp.address)/sizeof(in_addr_t)));
             counter++, tmp_ptr = strtok(NULL, ","))
        {
          co.igmp.address[counter] = resolv(tmp_ptr);
        }
        co.igmp.sources = counter;
        break;

      /* XXX TCP HEADER OPTIONS (IPPROTO_TCP = 6) */
      case OPTION_TCP_SEQUENCE:       co.tcp.sequence = atol(optarg); break;
      case OPTION_TCP_ACKNOWLEDGE:    co.tcp.acknowledge = atol(optarg); break;
      case OPTION_TCP_OFFSET:         co.tcp.doff = atoi(optarg);  break;
      case 'F':                       co.tcp.fin = TRUE;  break;
      case 'S':                       co.tcp.syn = TRUE;  break;
      case 'R':                       co.tcp.rst = TRUE;  break;
      case 'P':                       co.tcp.psh = TRUE;  break;
      case 'A':                       co.tcp.ack = TRUE;  break;
      case 'U':                       co.tcp.urg = TRUE;  break;
      case 'E':                       co.tcp.ece = TRUE;  break;
      case 'C':                       co.tcp.cwr = TRUE;  break;
      case 'W':                       co.tcp.window = atoi(optarg); break;
      case OPTION_TCP_URGENT_POINTER: co.tcp.urg_ptr = atoi(optarg); break;
      case OPTION_TCP_MSS:            co.tcp.options |= TCP_OPTION_MSS;
                                      co.tcp.mss = atoi(optarg); break;
      case OPTION_TCP_WSOPT:          co.tcp.options |= TCP_OPTION_WSOPT;
                                      co.tcp.wsopt = atoi(optarg); break;
      case OPTION_TCP_TSOPT:
        co.tcp.options |= TCP_OPTION_TSOPT;

        /* FIX: The code below is faster and smaller than the previous one. */
        if ( (tmp_ptr = strchr(optarg, ':')) != NULL )
        {
          *tmp_ptr++ = '\0';
          co.tcp.tsecr = atol(tmp_ptr);
          co.tcp.tsval = atol(optarg);
        }
        break;
      case OPTION_TCP_SACK_OK:    co.tcp.options |= TCP_OPTION_SACK_OK; break;
      case OPTION_TCP_CC:         co.tcp.options |= TCP_OPTION_CC;
                                  co.tcp.cc = atol(optarg); break;
      case OPTION_TCP_CC_NEW:     co.tcp.options |= TCP_OPTION_CC_NEXT;
                                  co.tcp.cc_new = atol(optarg); break;
      case OPTION_TCP_CC_ECHO:    co.tcp.options |= TCP_OPTION_CC_NEXT;
                                  co.tcp.cc_echo = atol(optarg); break;
      case OPTION_TCP_SACK_EDGE:
        co.tcp.options |= TCP_OPTION_SACK_EDGE;

        /* FIX: The code below is faster and smaller than the previous one. */
        if ( (tmp_ptr = strchr(optarg, ':')) != NULL )
        {
          *tmp_ptr++ = '\0';
          co.tcp.sack_right = atol(tmp_ptr);
          co.tcp.sack_left = atol(optarg);
        }
        break;

      case OPTION_TCP_MD5_SIGNATURE:  co.tcp.md5  = TRUE;
                                      co.tcp.auth = FALSE; break;
      case OPTION_TCP_AUTHENTICATION: co.tcp.md5  = FALSE;
                                      co.tcp.auth = TRUE; break;
      case OPTION_TCP_AUTH_KEY_ID:    co.tcp.key_id = atoi(optarg); break;
      case OPTION_TCP_AUTH_NEXT_KEY:  co.tcp.next_key = atoi(optarg); break;
      case OPTION_TCP_NOP:            co.tcp.nop = TCPOPT_NOP; break;

      /* XXX EGP HEADER OPTIONS (IPPROTO_EGP = 8) */
      case OPTION_EGP_TYPE:           co.egp.type = atoi(optarg);  break;
      case OPTION_EGP_CODE:           co.egp.code = atoi(optarg);  break;
      case OPTION_EGP_STATUS:         co.egp.status = atoi(optarg); break;
      case OPTION_EGP_AS:             co.egp.as = atoi(optarg); break;
      case OPTION_EGP_SEQUENCE:       co.egp.sequence = atoi(optarg); break;
      case OPTION_EGP_HELLO:          co.egp.hello = atoi(optarg); break;
      case OPTION_EGP_POLL:           co.egp.poll = atoi(optarg);  break;

      /* XXX RIP HEADER OPTIONS (IPPROTO_UDP = 17) */
      case OPTION_RIP_COMMAND:        co.rip.command = atoi(optarg); break;
      case OPTION_RIP_FAMILY:         co.rip.family = atoi(optarg); break;
      case OPTION_RIP_ADDRESS:        co.rip.address = resolv(optarg); break;
      case OPTION_RIP_METRIC:         co.rip.metric = atol(optarg); break;
      case OPTION_RIP_DOMAIN:         co.rip.domain = atoi(optarg); break;
      case OPTION_RIP_TAG:            co.rip.tag = atoi(optarg); break;
      case OPTION_RIP_NETMASK:        co.rip.netmask = resolv(optarg); break;
      case OPTION_RIP_NEXTHOP:        co.rip.next_hop = resolv(optarg); break;
      case OPTION_RIP_AUTHENTICATION: co.rip.auth = TRUE; break;
      case OPTION_RIP_AUTH_KEY_ID:    co.rip.key_id = atoi(optarg); break;
      case OPTION_RIP_AUTH_SEQUENCE:  co.rip.sequence = atol(optarg); break;

      /* XXX DCCP HEADER OPTIONS (IPPROTO_DCCP = 33) */
      case OPTION_DCCP_OFFSET:          co.dccp.doff = atoi(optarg); break;
      case OPTION_DCCP_CSCOV:           co.dccp.cscov = atoi(optarg); break;
      case OPTION_DCCP_CCVAL:           co.dccp.ccval = atoi(optarg); break;
      case OPTION_DCCP_TYPE:            co.dccp.type = atoi(optarg); break;
      case OPTION_DCCP_EXTEND:          co.dccp.ext = TRUE; break;
      case OPTION_DCCP_SEQUENCE_01:     co.dccp.sequence_01 = atoi(optarg); break;
      case OPTION_DCCP_SEQUENCE_02:     co.dccp.sequence_02 = atoi(optarg); break;
      case OPTION_DCCP_SEQUENCE_03:     co.dccp.sequence_03 = atol(optarg); break;
      case OPTION_DCCP_SERVICE:         co.dccp.service = atol(optarg); break;
      case OPTION_DCCP_ACKNOWLEDGE_01:  co.dccp.acknowledge_01 = atoi(optarg); break;
      case OPTION_DCCP_ACKNOWLEDGE_02:  co.dccp.acknowledge_02 = atol(optarg); break;
      case OPTION_DCCP_RESET_CODE:      co.dccp.rst_code = atoi(optarg); break;

      /* XXX RSVP HEADER OPTIONS (IPPROTO_RSVP = 46) */
      case OPTION_RSVP_FLAGS:             co.rsvp.flags = atoi(optarg); break;
      case OPTION_RSVP_TYPE:              co.rsvp.type = atoi(optarg); break;
      case OPTION_RSVP_TTL:               co.rsvp.ttl = atoi(optarg);  break;
      case OPTION_RSVP_SESSION_ADDRESS:   co.rsvp.session_addr = resolv(optarg); break;
      case OPTION_RSVP_SESSION_PROTOCOL:  co.rsvp.session_proto = atoi(optarg); break;
      case OPTION_RSVP_SESSION_FLAGS:     co.rsvp.session_flags = atoi(optarg); break;
      case OPTION_RSVP_SESSION_PORT:      co.rsvp.session_port = atoi(optarg); break;
      case OPTION_RSVP_HOP_ADDRESS:       co.rsvp.hop_addr = resolv(optarg); break;
      case OPTION_RSVP_HOP_IFACE:         co.rsvp.hop_iface = atol(optarg); break;
      case OPTION_RSVP_TIME_REFRESH:      co.rsvp.time_refresh = atol(optarg); break;
      case OPTION_RSVP_ERROR_ADDRESS:     co.rsvp.error_addr = resolv(optarg); break;
      case OPTION_RSVP_ERROR_FLAGS:       co.rsvp.error_flags = atoi(optarg); break;
      case OPTION_RSVP_ERROR_CODE:        co.rsvp.error_code = atoi(optarg); break;
      case OPTION_RSVP_ERROR_VALUE:       co.rsvp.error_value = atoi(optarg); break;
      case OPTION_RSVP_SCOPE:             co.rsvp.scope = atoi(optarg); break;
      case OPTION_RSVP_SCOPE_ADDRESS:
        for (counter = 0, tmp_ptr = strtok(optarg, ","); 
             tmp_ptr && (counter < (int)(sizeof(co.rsvp.address)/sizeof(in_addr_t))); 
             counter++, tmp_ptr = strtok(NULL, ","))
        {
          co.rsvp.address[counter] = resolv(tmp_ptr);
        }
        co.rsvp.scope = counter;
        break;
      case OPTION_RSVP_STYLE_OPTION:      co.rsvp.style_opt = atol(optarg); break;
      case OPTION_RSVP_SENDER_ADDRESS:    co.rsvp.sender_addr = resolv(optarg); break;
      case OPTION_RSVP_SENDER_PORT:       co.rsvp.sender_port = atoi(optarg); break;
      case OPTION_RSVP_TSPEC_TRAFFIC:     co.rsvp.tspec = TSPEC_TRAFFIC_SERVICE; break;
      case OPTION_RSVP_TSPEC_GUARANTEED:  co.rsvp.tspec = TSPEC_GUARANTEED_SERVICE; break;
      case OPTION_RSVP_TSPEC_TOKEN_R:     co.rsvp.tspec = TSPEC_TRAFFIC_SERVICE;
                                          co.rsvp.tspec_r = atol(optarg); break;
      case OPTION_RSVP_TSPEC_TOKEN_B:     co.rsvp.tspec = TSPEC_TRAFFIC_SERVICE;
                                          co.rsvp.tspec_b = atol(optarg); break;
      case OPTION_RSVP_TSPEC_DATA_P:      co.rsvp.tspec = TSPEC_TRAFFIC_SERVICE;
                                          co.rsvp.tspec_p = atol(optarg); break;
      case OPTION_RSVP_TSPEC_MINIMUM:     co.rsvp.tspec = TSPEC_TRAFFIC_SERVICE;
                                          co.rsvp.tspec_m = atol(optarg); break;
      case OPTION_RSVP_TSPEC_MAXIMUM:     co.rsvp.tspec = TSPEC_TRAFFIC_SERVICE;
                                          co.rsvp.tspec_M = atol(optarg); break;
      case OPTION_RSVP_ADSPEC_ISHOP:      co.rsvp.adspec_hop = atol(optarg); break;
      case OPTION_RSVP_ADSPEC_PATH:       co.rsvp.adspec_path = atol(optarg); break;
      case OPTION_RSVP_ADSPEC_MINIMUM:    co.rsvp.adspec_minimum = atol(optarg); break;
      case OPTION_RSVP_ADSPEC_MTU:        co.rsvp.adspec_mtu = atol(optarg); break;
      case OPTION_RSVP_ADSPEC_GUARANTEED: co.rsvp.adspec = ADSPEC_GUARANTEED_SERVICE; break;
      case OPTION_RSVP_ADSPEC_CTOT:       co.rsvp.adspec = ADSPEC_GUARANTEED_SERVICE;
                                          co.rsvp.adspec_Ctot = atol(optarg); break;
      case OPTION_RSVP_ADSPEC_DTOT:       co.rsvp.adspec = ADSPEC_GUARANTEED_SERVICE;
                                          co.rsvp.adspec_Dtot = atol(optarg); break;
      case OPTION_RSVP_ADSPEC_CSUM:       co.rsvp.adspec = ADSPEC_GUARANTEED_SERVICE;
                                          co.rsvp.adspec_Csum = atol(optarg); break;
      case OPTION_RSVP_ADSPEC_DSUM:       co.rsvp.adspec = ADSPEC_GUARANTEED_SERVICE;
                                          co.rsvp.adspec_Dsum = atol(optarg); break;
      case OPTION_RSVP_ADSPEC_CONTROLLED: co.rsvp.adspec = ADSPEC_CONTROLLED_SERVICE; break;
      case OPTION_RSVP_CONFIRM_ADDR:      co.rsvp.confirm_addr = resolv(optarg); break;

      /* XXX IPSEC HEADER OPTIONS (IPPROTO_AH = 51 & IPPROTO_ESP = 50) */
      case OPTION_IPSEC_AH_LENGTH:        co.ipsec.ah_length = atoi(optarg); break;
      case OPTION_IPSEC_AH_SPI:           co.ipsec.ah_spi = atol(optarg); break;
      case OPTION_IPSEC_AH_SEQUENCE:      co.ipsec.ah_sequence = atol(optarg); break;
      case OPTION_IPSEC_ESP_SPI:          co.ipsec.esp_spi = atol(optarg); break;
      case OPTION_IPSEC_ESP_SEQUENCE:     co.ipsec.esp_sequence = atol(optarg); break;

      /* XXX EIGRP HEADER OPTIONS (IPPROTO_EIGRP = 88) */
      case OPTION_EIGRP_OPCODE:      co.eigrp.opcode = atoi(optarg); break;
      case OPTION_EIGRP_FLAGS:       co.eigrp.flags = atol(optarg); break;
      case OPTION_EIGRP_SEQUENCE:    co.eigrp.sequence = atol(optarg); break;
      case OPTION_EIGRP_ACKNOWLEDGE: co.eigrp.acknowledge = atol(optarg); break;
      case OPTION_EIGRP_AS:          co.eigrp.as = atol(optarg); break;
      case OPTION_EIGRP_TYPE:        co.eigrp.type = atoi(optarg); break;
      case OPTION_EIGRP_LENGTH:      co.eigrp.length = atoi(optarg); break;
      case OPTION_EIGRP_K1:          co.eigrp.values |= EIGRP_KVALUE_K1;
                                     co.eigrp.k1 = atoi(optarg); break;
      case OPTION_EIGRP_K2:          co.eigrp.values |= EIGRP_KVALUE_K2;
                                     co.eigrp.k2 = atoi(optarg); break;
      case OPTION_EIGRP_K3:          co.eigrp.values |= EIGRP_KVALUE_K3;
                                     co.eigrp.k3 = atoi(optarg); break;
      case OPTION_EIGRP_K4:          co.eigrp.values |= EIGRP_KVALUE_K4;
                                     co.eigrp.k4 = atoi(optarg); break;
      case OPTION_EIGRP_K5:          co.eigrp.values |= EIGRP_KVALUE_K5;
                                     co.eigrp.k5 = atoi(optarg); break;
      case OPTION_EIGRP_HOLD:        co.eigrp.hold = atoi(optarg); break;
      case OPTION_EIGRP_IOS_VERSION:
        /* FIX: The code below is faster and smaller than the previous one. */
        if ( (tmp_ptr = strchr(optarg, '.')) != NULL )
        {
          *tmp_ptr++ = '\0';
          co.eigrp.ios_minor = atoi(tmp_ptr);
          co.eigrp.ios_major = atoi(optarg);
        }
        break;
      case OPTION_EIGRP_PROTO_VERSION:
        /* FIX: The code below is faster and smaller than the previous one. */
        if ( (tmp_ptr = strchr(optarg, '.')) != NULL )
        {
          *tmp_ptr++ = '\0';
          co.eigrp.ver_minor = atoi(tmp_ptr);
          co.eigrp.ver_major = atoi(optarg);
        }
        break;
      case OPTION_EIGRP_NEXTHOP:     co.eigrp.next_hop = resolv(optarg); break;
      case OPTION_EIGRP_DELAY:       co.eigrp.delay = atol(optarg); break;
      case OPTION_EIGRP_BANDWIDTH:   co.eigrp.bandwidth = atol(optarg); break;
      case OPTION_EIGRP_MTU:         co.eigrp.mtu = atol(optarg); break;
      case OPTION_EIGRP_HOP_COUNT:   co.eigrp.hop_count = atoi(optarg); break;
      case OPTION_EIGRP_LOAD:        co.eigrp.load = atoi(optarg); break;
      case OPTION_EIGRP_RELIABILITY: co.eigrp.reliability = atoi(optarg); break;
      case OPTION_EIGRP_DESINATION:
        if ( (tmp_ptr = strchr(optarg, '/')) == NULL )
          co.eigrp.dest   = resolv(optarg);
        else
        {
          /* FIX: The code below is faster and smaller than the previous one. */
          *tmp_ptr++ = '\0';
          co.eigrp.prefix = atoi(tmp_ptr);
          co.eigrp.dest = resolv(optarg);
        }
        break;
      case OPTION_EIGRP_SOURCE_ROUTER:  co.eigrp.src_router = resolv(optarg); break;
      case OPTION_EIGRP_SOURCE_AS:      co.eigrp.src_as = atol(optarg); break;
      case OPTION_EIGRP_TAG:            co.eigrp.tag = atol(optarg); break;
      case OPTION_EIGRP_METRIC:         co.eigrp.proto_metric = atol(optarg); break;
      case OPTION_EIGRP_ID:             co.eigrp.proto_id = atoi(optarg); break;
      case OPTION_EIGRP_EXTERNAL_FLAGS: co.eigrp.ext_flags = atoi(optarg); break;
      case OPTION_EIGRP_ADDRESS:        co.eigrp.address = resolv(optarg); break;
      case OPTION_EIGRP_MULTICAST:      co.eigrp.multicast = atol(optarg); break;
      case OPTION_EIGRP_AUTHENTICATION: co.eigrp.auth = TRUE; break;
      case OPTION_EIGRP_AUTH_KEY_ID:    co.eigrp.key_id = atol(optarg); break;

      /* XXX OSPF HEADER OPTIONS (IPPROTO_OSPF = 89) */
      case OPTION_OSPF_TYPE:           co.ospf.type = atoi(optarg); break;
      case OPTION_OSPF_LENGTH:         co.ospf.length = atoi(optarg); break;
      case OPTION_OSPF_ROUTER_ID:      co.ospf.rid = resolv(optarg); break;
      case OPTION_OSPF_AREA_ID:        co.ospf.AID = TRUE;
                                       co.ospf.aid = resolv(optarg); break;
      case '1':                        co.ospf.options |= OSPF_OPTION_TOS; break;
      case '2':                        co.ospf.options |= OSPF_OPTION_EXTERNAL; break;
      case '3':                        co.ospf.options |= OSPF_OPTION_MULTICAST; break;
      case '4':                        co.ospf.options |= OSPF_OPTION_NSSA; break;
      case '5':                        co.ospf.options |= OSPF_OPTION_LLS; break;
      case '6':                        co.ospf.options |= OSPF_OPTION_DEMAND; break;
      case '7':                        co.ospf.options |= OSPF_OPTION_OPAQUE; break;
      case '8':                        co.ospf.options |= OSPF_OPTION_DOWN; break;
      case OPTION_OSPF_NETMASK:        co.ospf.netmask = resolv(optarg); break;
      case OPTION_OSPF_HELLO_INTERVAL: co.ospf.hello_interval = atoi(optarg); break;
      case OPTION_OSPF_HELLO_PRIORITY: co.ospf.hello_priority = atoi(optarg); break;
      case OPTION_OSPF_HELLO_DEAD:     co.ospf.hello_dead = atol(optarg); break;
      case OPTION_OSPF_HELLO_DESIGN:   co.ospf.hello_design = resolv(optarg); break;
      case OPTION_OSPF_HELLO_BACKUP:   co.ospf.hello_backup = resolv(optarg); break;
      case OPTION_OSPF_HELLO_NEIGHBOR: co.ospf.neighbor = atoi(optarg); break;
      case OPTION_OSPF_HELLO_ADDRESS:
        for (counter = 0, tmp_ptr = strtok(optarg, ","); 
             tmp_ptr && (counter < (int)(sizeof(co.ospf.address)/sizeof(in_addr_t))); 
             counter++, tmp_ptr = strtok(NULL, ","))
        {
          co.ospf.address[counter] = resolv(tmp_ptr);
        }
        co.ospf.neighbor = counter;
        break;
      case OPTION_OSPF_DD_MTU:            co.ospf.dd_mtu = atoi(optarg); break;
      case OPTION_OSPF_DD_MASTER_SLAVE:   co.ospf.dd_dbdesc |= DD_DBDESC_MSLAVE; break;
      case OPTION_OSPF_DD_MORE:           co.ospf.dd_dbdesc |= DD_DBDESC_MORE; break;
      case OPTION_OSPF_DD_INIT:           co.ospf.dd_dbdesc |= DD_DBDESC_INIT; break;
      case OPTION_OSPF_DD_OOBRESYNC:      co.ospf.dd_dbdesc |= DD_DBDESC_OOBRESYNC; break;
      case OPTION_OSPF_DD_SEQUENCE:       co.ospf.dd_sequence = atol(optarg); break;
      case OPTION_OSPF_DD_INCLUDE_LSA:    co.ospf.dd_include_lsa = TRUE; break;
      case OPTION_OSPF_LSA_AGE:           co.ospf.lsa_age = atoi(optarg); break;
      case OPTION_OSPF_LSA_DO_NOT_AGE:    co.ospf.lsa_dage = TRUE; break;
      case OPTION_OSPF_LSA_TYPE:          co.ospf.lsa_type = atoi(optarg); break;
      case OPTION_OSPF_LSA_LSID:          co.ospf.lsa_lsid = resolv(optarg); break;
      case OPTION_OSPF_LSA_ROUTER:        co.ospf.lsa_router = resolv(optarg); break;
      case OPTION_OSPF_LSA_SEQUENCE:      co.ospf.lsa_sequence = atol(optarg); break;
      case OPTION_OSPF_LSA_METRIC:        co.ospf.lsa_metric = atol(optarg); break;
      case OPTION_OSPF_LSA_FLAG_BORDER:   co.ospf.lsa_flags |= ROUTER_FLAG_BORDER; break;
      case OPTION_OSPF_LSA_FLAG_EXTERNAL: co.ospf.lsa_flags |= ROUTER_FLAG_EXTERNAL; break;
      case OPTION_OSPF_LSA_FLAG_VIRTUAL:  co.ospf.lsa_flags |= ROUTER_FLAG_VIRTUAL; break;
      case OPTION_OSPF_LSA_FLAG_WILD:     co.ospf.lsa_flags |= ROUTER_FLAG_WILD; break;
      case OPTION_OSPF_LSA_FLAG_NSSA_TR:  co.ospf.lsa_flags |= ROUTER_FLAG_NSSA_TR; break;
      case OPTION_OSPF_LSA_LINK_ID:       co.ospf.lsa_link_id = resolv(optarg); break;
      case OPTION_OSPF_LSA_LINK_DATA:     co.ospf.lsa_link_data = resolv(optarg); break;
      case OPTION_OSPF_LSA_LINK_TYPE:     co.ospf.lsa_link_type = atoi(optarg); break;
      case OPTION_OSPF_LSA_ATTACHED:      co.ospf.lsa_attached = resolv(optarg); break;
      case OPTION_OSPF_LSA_LARGER:        co.ospf.lsa_larger = TRUE; break;
      case OPTION_OSPF_LSA_FORWARD:       co.ospf.lsa_forward = resolv(optarg); break;
      case OPTION_OSPF_LSA_EXTERNAL:      co.ospf.lsa_external = resolv(optarg); break;
      case OPTION_OSPF_VERTEX_ROUTER:     co.ospf.vertex_type = VERTEX_TYPE_ROUTER; break;
      case OPTION_OSPF_VERTEX_NETWORK:    co.ospf.vertex_type = VERTEX_TYPE_NETWORK; break;
      case OPTION_OSPF_VERTEX_ID:         co.ospf.vertex_id = resolv(optarg); break;
      case OPTIONS_OSPF_LLS_OPTION_LR:    co.ospf.lls_options = EXTENDED_OPTIONS_LR; break;
      case OPTIONS_OSPF_LLS_OPTION_RS:    co.ospf.lls_options = EXTENDED_OPTIONS_RS; break;
      case OPTION_OSPF_AUTHENTICATION:    co.ospf.auth = TRUE; break;
      case OPTION_OSPF_AUTH_KEY_ID:       co.ospf.key_id = atoi(optarg); break;
      case OPTION_OSPF_AUTH_SEQUENCE:     co.ospf.sequence = atol(optarg); break;

      case 'v':
        show_version();
        exit(EXIT_FAILURE);

      /* XXX HELP/USAGE MESSAGE */
      case 'h':
      case '?':
      default:
        usage();
        exit(EXIT_FAILURE);
    }
  }

  /* Checking the command line interface options. */
  if (optind >= argc)
  {
    ERROR("t50 what? try --help for usage");
    exit(EXIT_FAILURE);
  }

  /* Get host and cidr. */
  if (getIpAndCidrFromString(argv[optind], &addr))
  {
    /* If ok, then set values directly to "options" structure. */
    co.bits = addr.cidr;
    co.ip.daddr = htonl(addr.addr);
  }
  else
  {
    /* Otherwise, probably it's a name. Try to resolve it. 
       '/' still marks the optional cidr here. */
    tmp_ptr = strtok(argv[optind], "/");  /* NOTE: tmp_ptr is never null at this point! */
    co.ip.daddr = resolv(tmp_ptr);
    if ((tmp_ptr = strtok(NULL, "/")) != NULL)
      co.bits = atoi(tmp_ptr);
    else
      co.bits = 32;
  }

  return &co;
}

/* Used on getsubopt(), below */
/* NOTE: This is called just once! */
static char **getTokensList(void)
{
  modules_table_t *ptbl;
  char **p;
  int i;

  /* Create tokens list. This list have the same number of protocols plus "T50" and the NULL entry. */
  p = (char **)malloc(sizeof(char *) * (getNumberOfRegisteredModules() + 2));

  /* Fill the token list with pointers to protocol "names". */
  for (i = 0, ptbl = mod_table; ptbl->acronym != NULL; ptbl++, i++)
    p[i] = ptbl->acronym;
  p[i++] = "T50";
  p[i] = NULL;

  /* NOTE: Just remember to free this list! */
  return p;
}

/* List procotolos on modules table */
static void listProtocols(void)
{
  modules_table_t *ptbl;
  int i;

  puts("List of supported protocols:");

  for (i = 1, ptbl = mod_table; ptbl->func != NULL; ptbl++, i++)
    printf("\t%2d PROTO = %-6s (%s)\n",
           i,
           ptbl->acronym,
           ptbl->description);
}

/* NOTE: Ugly hack, but necessary! */
static void setDefaultModuleOption(void)
{
  modules_table_t *ptbl;
  int i;

  for (i = 0, ptbl = mod_table; ptbl->func != NULL; ptbl++, i++)
  {
    /* FIXME: Is string comparison the best way?! */
    if (strcasecmp(ptbl->acronym, "TCP") == 0)
    {
      co.ip.protocol = ptbl->protocol_id;
      co.ip.protoname = i;
      break;
    }
  }
}

/* POSIX Extended Regular Expression used to match IP addresses with optional CIDR. */
#define IP_REGEX "^([1-2]*[0-9]{1,2})" \
                 "(\\.[1-2]*[0-9]{1,2}){0,1}" \
                 "(\\.[1-2]*[0-9]{1,2}){0,1}" \
                 "(\\.[1-2]*[0-9]{1,2}){0,1}" \
                 "(/[0-9]{1,2}){0,1}$"

/* Auxiliary "match" macros. */
#define MATCH(a)        ((a).rm_so >= 0)
#define MATCH_LENGTH(a) ((a).rm_eo - (a).rm_so)

/* NOTE: There is a bug in strncpy() function.
         '\0' is not set at the end of substring. */
#define COPY_SUBSTRING(d, s, len) { \
  strncpy((d), (s), (len)); \
  *((char *)(d) + (len)) = '\0'; \
}

static int getIpAndCidrFromString(char const * const addr, T50_tmp_addr_t *addr_ptr)
{
  regex_t re;
  regmatch_t rm[6];
  unsigned matches[5];
  int i, len;
  char *t;
  int bits;

  addr_ptr->addr = addr_ptr->cidr = 0;

  /* Try to compile the regular expression. */
  if (regcomp(&re, IP_REGEX, REG_EXTENDED))
    return 0;

  /* Try to execute regex against the addr string. */
  if (regexec(&re, addr, 6, rm, 0))
  {
    regfree(&re);
    return 0;
  }

  /* Allocate enough space for temporary string. */
  t = strdup(addr);
  if (t  == NULL)
  {
    perror("Cannot allocate temporary string");
    abort();
  }

  /* Convert IP octects matches. */
  len = MATCH_LENGTH(rm[1]);
  COPY_SUBSTRING(t, addr+rm[1].rm_so, len);
  matches[0] = atoi(t);

  bits = 32;  /* default is 32 bits netmask. */
  for (i = 2; i <= 4; i++)
  {
    if (MATCH(rm[i]))
    {
      len = MATCH_LENGTH(rm[i]) - 1;
      COPY_SUBSTRING(t, addr + rm[i].rm_so + 1, len);
      matches[i-1] = atoi(t);
    }
    else
    {
      /* if octect is missing, decrease 8 bits from netmask */
      bits -= 8;
      matches[i-1] = 0;
    }
  }

  /* Convert cidr match. */
  if (MATCH(rm[5]))
  {
    len = MATCH_LENGTH(rm[5]) - 1;
    COPY_SUBSTRING(t, addr + rm[5].rm_so + 1, len);

    if ((matches[4] = atoi(t)) == 0)
    {
      /* if cidr is actually '0', then it is an error! */
      free(t);
      regfree(&re);
      return 0;
    }
  }
  else
  {
    /* if cidr is not given, use the calculated one. */
    matches[4] = bits;
  }

  /* We don't need 't' string anymore. */
  free(t);

  /* Validate ip octects */
  for (i = 0; i < 4; i++)
    if (matches[i] > 255)
    {
      regfree(&re);
      return 0;
    }

  /* NOTE: Check 'bits' here! */
  /* Validate cidr. */
  if (matches[4] < CIDR_MINIMUM || matches[4] > CIDR_MAXIMUM)
  {
    char msg[64];

    sprintf(msg, "CIDR must be between %u and %u.\n", CIDR_MINIMUM, CIDR_MAXIMUM);
    ERROR(msg);

    regfree(&re);
    return 0;
  }

  regfree(&re);

  /* Prepare CIDR structure */
  addr_ptr->cidr = matches[4];
  addr_ptr->addr = ( matches[3]        |
                    (matches[2] << 8)  |
                    (matches[1] << 16) |
                    (matches[0] << 24)) &
                      (0xffffffffUL << (32 - addr_ptr->cidr));

  return 1;
}



// Files:
// <sys/sysctl.h>     definitions for top level identifiers, second level
//                    kernel and hardware identifiers, and user level
//                    identifiers
// <sys/socket.h>     definitions for second level    network   identifiers
// <sys/gmon.h>       definitions for third level profiling identifiers
// <vm/vm_param.h>    definitions for second level    virtual   memory identi-
//                    fiers
// <netinet/in.h>     definitions for third level Internet identifiers
//                    and fourth level IP identifiers
// <netinet/icmp_var.h>  definitions for fourth level     ICMP identifiers
// <netinet/udp_var.h>   definitions for fourth level     UDP identifiers
// 
// <netinet6/in6.h>


// <sys/socket.h>
/*
 * Definitions for network related sysctl, CTL_NET.
 *
 * Second level is protocol family.
 * Third level is protocol number.
 *
 * Further levels are defined by the individual families below.
 */
#if !defined(_POSIX_C_SOURCE) || defined(_DARWIN_C_SOURCE)
#define NET_MAXID AF_MAX
#endif /* (_POSIX_C_SOURCE && !_DARWIN_C_SOURCE) */

// <sys/gmon.h>
/*
 * Sysctl definitions for extracting profiling information from the kernel.
 */
#define GPROF_STATE 0 /* int: profiling enabling variable */
#define GPROF_COUNT 1 /* struct: profile tick count buffer */
#define GPROF_FROMS 2 /* struct: from location hash bucket */
#define GPROF_TOS 3 /* struct: destination/count structure */
#define GPROF_GMONPARAM 4 /* struct: profiling parameters (see above) */

// <vm/vm_param.h>



// <netinet/in.h>
/*
 * Definitions for inet sysctl operations.
 *
 * Third level is protocol number.
 * Fourth level is desired variable within that protocol.
 */
#define IPPROTO_MAXID (IPPROTO_AH + 1)  /* don't list to IPPROTO_MAX */


/*
 * Names for IP sysctl objects
 */
#define IPCTL_FORWARDING  1 /* act as router */
#define IPCTL_SENDREDIRECTS 2 /* may send redirects when forwarding */
#define IPCTL_DEFTTL    3 /* default TTL */
#ifdef notyet
#define IPCTL_DEFMTU    4 /* default MTU */
#endif
#define IPCTL_RTEXPIRE    5 /* cloned route expiration time */
#define IPCTL_RTMINEXPIRE 6 /* min value for expiration time */
#define IPCTL_RTMAXCACHE  7 /* trigger level for dynamic expire */
#define IPCTL_SOURCEROUTE 8 /* may perform source routes */
#define IPCTL_DIRECTEDBROADCAST 9 /* may re-broadcast received packets */
#define IPCTL_INTRQMAXLEN 10  /* max length of netisr queue */
#define IPCTL_INTRQDROPS  11  /* number of netisr q drops */
#define IPCTL_STATS   12  /* ipstat structure */
#define IPCTL_ACCEPTSOURCEROUTE 13  /* may accept source routed packets */
#define IPCTL_FASTFORWARDING  14  /* use fast IP forwarding code */
#define IPCTL_KEEPFAITH   15  /* deprecated */
#define IPCTL_GIF_TTL   16  /* default TTL for gif encap packet */
#define IPCTL_MAXID   17

#endif  /* (!_POSIX_C_SOURCE || _DARWIN_C_SOURCE) */



// <netinet/icmp_var.h>
/*
 * Names for ICMP sysctl objects
 */
#define ICMPCTL_MASKREPL  1 /* allow replies to netmask requests */
#define ICMPCTL_STATS   2 /* statistics (read-only) */
#define ICMPCTL_ICMPLIM   3
#define ICMPCTL_TIMESTAMP 4 /* allow replies to time stamp requests */
#define ICMPCTL_MAXID   5


// <netinet/udp_var.h>
/*
 * Names for UDP sysctl objects
 */
#define UDPCTL_CHECKSUM   1 /* checksum UDP packets */
#define UDPCTL_STATS    2 /* statistics (read-only) */
#define UDPCTL_MAXDGRAM   3 /* max datagram size */
#define UDPCTL_RECVSPACE  4 /* default receive buffer space */
#define UDPCTL_PCBLIST    5 /* list of PCBs for UDP sockets */
#define UDPCTL_MAXID    6


// <netinet6/in6.h>
/*
 * Definitions for inet6 sysctl operations.
 *
 * Third level is protocol number.
 * Fourth level is desired variable within that protocol.
 */
#define IPV6PROTO_MAXID (IPPROTO_PIM + 1)  /* don't list to IPV6PROTO_MAX */

/*
 * Names for IP sysctl objects
 */
#define IPV6CTL_FORWARDING  1 /* act as router */
#define IPV6CTL_SENDREDIRECTS 2 /* may send redirects when forwarding */
#define IPV6CTL_DEFHLIM   3 /* default Hop-Limit */
#ifdef notyet
#define IPV6CTL_DEFMTU    4 /* default MTU */
#endif
#define IPV6CTL_FORWSRCRT 5 /* forward source-routed dgrams */
#define IPV6CTL_STATS   6 /* stats */
#define IPV6CTL_MRTSTATS  7 /* multicast forwarding stats */
#define IPV6CTL_MRTPROTO  8 /* multicast routing protocol */
#define IPV6CTL_MAXFRAGPACKETS  9 /* max packets reassembly queue */
#define IPV6CTL_SOURCECHECK 10  /* verify source route and intf */
#define IPV6CTL_SOURCECHECK_LOGINT 11 /* minimume logging interval */
#define IPV6CTL_ACCEPT_RTADV  12
#define IPV6CTL_KEEPFAITH 13  /* deprecated */
#define IPV6CTL_LOG_INTERVAL  14
#define IPV6CTL_HDRNESTLIMIT  15
#define IPV6CTL_DAD_COUNT 16
#define IPV6CTL_AUTO_FLOWLABEL  17
#define IPV6CTL_DEFMCASTHLIM  18
#define IPV6CTL_GIF_HLIM  19  /* default HLIM for gif encap packet */
#define IPV6CTL_KAME_VERSION  20
#define IPV6CTL_USE_DEPRECATED  21  /* use deprec addr (RFC2462 5.5.4) */
#define IPV6CTL_RR_PRUNE  22  /* walk timer for router renumbering */
#if 0 /* obsolete */
#define IPV6CTL_MAPPED_ADDR 23
#endif
#define IPV6CTL_V6ONLY    24
#define IPV6CTL_RTEXPIRE  25  /* cloned route expiration time */
#define IPV6CTL_RTMINEXPIRE 26  /* min value for expiration time */
#define IPV6CTL_RTMAXCACHE  27  /* trigger level for dynamic expire */

#define IPV6CTL_USETEMPADDR 32  /* use temporary addresses [RFC 4941] */
#define IPV6CTL_TEMPPLTIME  33  /* preferred lifetime for tmpaddrs */
#define IPV6CTL_TEMPVLTIME  34  /* valid lifetime for tmpaddrs */
#define IPV6CTL_AUTO_LINKLOCAL  35  /* automatic link-local addr assign */
#define IPV6CTL_RIP6STATS 36  /* raw_ip6 stats */
#define IPV6CTL_PREFER_TEMPADDR 37  /* prefer temporary addr as src */
#define IPV6CTL_ADDRCTLPOLICY 38  /* get/set address selection policy */
#define IPV6CTL_USE_DEFAULTZONE 39  /* use default scope zone */

#define IPV6CTL_MAXFRAGS  41  /* max fragments */
#define IPV6CTL_MCAST_PMTU  44  /* enable pMTU discovery for mcast? */

#define IPV6CTL_NEIGHBORGCTHRESH 46
#define IPV6CTL_MAXIFPREFIXES 47
#define IPV6CTL_MAXIFDEFROUTERS 48
#define IPV6CTL_MAXDYNROUTES  49
#define ICMPV6CTL_ND6_ONLINKNSRFC4861 50

/* New entries should be added here from current IPV6CTL_MAXID value. */
/* to define items, should talk with KAME guys first, for *BSD compatibility */
#define IPV6CTL_MAXID   51

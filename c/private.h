
// ARP
#define NET_RT_DUMPX_FLAGS  9

enum {
    IFNET_LQM_THRESH_OFF        = (-2),
    IFNET_LQM_THRESH_UNKNOWN    = (-1),
    IFNET_LQM_THRESH_BAD        = 10,
    IFNET_LQM_THRESH_POOR       = 50,
    IFNET_LQM_THRESH_GOOD       = 100
};
enum {
    IFNET_NPM_THRESH_UNKNOWN    = (-1),
    IFNET_NPM_THRESH_NEAR       = 30,
    IFNET_NPM_THRESH_GENERAL    = 70,
    IFNET_NPM_THRESH_FAR        = 100,
};
enum {
    IFNET_RSSI_UNKNOWN  = ((-2147483647)-1), /* INT32_MIN */
};
struct rt_reach_info {
    u_int32_t   ri_refcnt;      /* reference count */
    u_int32_t   ri_probes;      /* total # of probes */
    u_int64_t   ri_snd_expire;  /* tx expiration (calendar) time */
    u_int64_t   ri_rcv_expire;  /* rx expiration (calendar) time */
    int32_t     ri_rssi;        /* received signal strength */
    int32_t     ri_lqm;         /* link quality metric */
    int32_t     ri_npm;         /* node proximity metric */
};
struct rt_msghdr_ext {
    u_short   rtm_msglen;         /* to skip over non-understood messages */
    u_char    rtm_version;        /* future binary compatibility */
    u_char    rtm_type;           /* message type */
    u_int32_t rtm_index;          /* index for associated ifp */
    u_int32_t rtm_flags;          /* flags, incl. kern & message, e.g. DONE */
    u_int32_t rtm_reserved;       /* for future use */
    u_int32_t rtm_addrs;          /* bitmask identifying sockaddrs in msg */
    pid_t     rtm_pid;            /* identify sender */
    int       rtm_seq;            /* for sender to identify action */
    int       rtm_errno;          /* why failed */
    u_int32_t rtm_use;            /* from rtentry */
    u_int32_t rtm_inits;          /* which metrics we are initializing */
    struct rt_metrics    rtm_rmx; /* metrics themselves */
    struct rt_reach_info rtm_ri;  /* route reachability info */
};

// NDP
#define ND6_IFF_IFDISABLED      0x8
#define ND6_IFF_INSECURE        0x80
#define IN6_CGA_KEY_MAXSIZE     2048  /* octets */
#define IN6_CGA_MODIFIER_LENGTH 16

struct in6_cga_modifier {
    u_int8_t octets[IN6_CGA_MODIFIER_LENGTH];
};
struct in6_cga_prepare {
    struct in6_cga_modifier cga_modifier;
    u_int8_t cga_security_level;
    u_int8_t reserved_A[15];
};
struct in6_cga_nodecfg {
    struct iovec cga_privkey;
    struct iovec cga_pubkey;
    struct in6_cga_prepare cga_prepare;
};

use libc;

use smoltcp::wire::IpCidr;

use std::io;
use std::ptr;
use std::mem;


pub const RTF_LLDATA: libc::c_int = 0x400;
pub const RTF_DEAD: libc::c_int   = 0x20000000;
pub const RTPRF_OURS: libc::c_int = libc::RTF_PROTO3;


#[allow(non_snake_case)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct rt_msghdr {
    pub rtm_msglen: libc::c_ushort, // to skip over non-understood messages
    pub rtm_version: libc::c_uchar, // future binary compatibility
    pub rtm_type: libc::c_uchar,    // message type 
    pub rtm_index: libc::c_ushort,  // index for associated ifp
    pub rtm_flags: libc::c_int,     // flags, incl. kern & message, e.g. DONE
    pub rtm_addrs: libc::c_int,     // bitmask identifying sockaddrs in msg
    pub rtm_pid: libc::pid_t,       // identify sender
    pub rtm_seq: libc::c_int,       // for sender to identify action
    pub rtm_errno: libc::c_int,     // why failed
    pub rtm_use: libc::c_int,       // from rtentry
    pub rtm_inits: u32,             // which metrics we are initializing
    pub rtm_rmx: rt_metrics,        // metrics themselves
}

// These numbers are used by reliable protocols for determining
// retransmission behavior and are included in the routing structure.
#[allow(non_snake_case)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct rt_metrics {
    pub rmx_locks: u32,       // Kernel leaves these values alone
    pub rmx_mtu: u32,         // MTU for this path
    pub rmx_hopcount: u32,    // max hops expected
    pub rmx_expire: i32,      // lifetime for route, e.g. redirect
    pub rmx_recvpipe: u32,    // inbound delay-bandwidth product
    pub rmx_sendpipe: u32,    // outbound delay-bandwidth product
    pub rmx_ssthresh: u32,    // outbound gateway buffer limit
    pub rmx_rtt: u32,         // estimated round trip time
    pub rmx_rttvar: u32,      // estimated rtt variance
    pub rmx_pksent: u32,      // packets sent using this route
    pub rmx_state: u32,       // route state
    pub rmx_filler: [u32; 3], // will be used for T/TCP later
}

#[allow(non_snake_case)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct rt_msghdr2 {
    pub rtm_msglen: libc::c_ushort,   // to skip over non-understood messages
    pub rtm_version: libc::c_uchar,   // future binary compatibility
    pub rtm_type: libc::c_uchar,      // message type 
    pub rtm_index: libc::c_ushort,    // index for associated ifp
    pub rtm_flags: libc::c_int,       // flags, incl. kern & message, e.g. DONE
    pub rtm_addrs: libc::c_int,       // bitmask identifying sockaddrs in msg
    pub rtm_refcnt: i32,              // reference count
    pub rtm_parentflags: libc::c_int, // which metrics we are initializing
    pub rtm_reserved: libc::c_int,    // metrics themselves
    pub rtm_use: libc::c_int,         // from rtentry
    pub rtm_inits: u32,               // which metrics we are initializing
    pub rtm_rmx: rt_metrics,          // metrics themselves
}


// Route reachability info
#[allow(non_snake_case)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct rt_reach_info {
    pub ri_refcnt: u32,      // reference count
    pub ri_probes: u32,      // total # of probes
    pub ri_snd_expire: u64,  // tx expiration (calendar) time
    pub ri_rcv_expire: u64,  // rx expiration (calendar) time
    pub ri_rssi: i32,        // received signal strength
    pub ri_lqm: i32,         // link quality metric
    pub ri_npm: i32,         // node proximity metric
}

// Extended routing message header (private).
#[allow(non_snake_case)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct rt_msghdr_ext {
    pub rtm_msglen: libc::c_ushort,   // to skip over non-understood messages
    pub rtm_version: libc::c_uchar,   // future binary compatibility
    pub rtm_type: libc::c_uchar,      // message type 
    pub rtm_index: u32,               // index for associated ifp
    pub rtm_flags: u32,               // flags, incl. kern & message, e.g. DONE
    pub rtm_reserved: u32,            // for future use
    pub rtm_addrs: u32,               // bitmask identifying sockaddrs in msg
    pub rtm_pid: libc::pid_t,         // identify sender
    pub rtm_seq: libc::c_int,         // for sender to identify action
    pub rtm_errno: libc::c_int,       // why failed
    pub rtm_use: u32,                 // from rtentry
    pub rtm_inits: u32,               // which metrics we are initializing
    pub rtm_rmx: rt_metrics,          // metrics themselves
    pub rtm_ri: rt_reach_info,        // route reachability info
}


// Routing statistics.
#[allow(non_snake_case)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct rtstat {
    pub rts_badredirect : libc::c_short, // bogus redirect calls
    pub rts_dynamic     : libc::c_short, // routes created by redirects
    pub rts_newgateway  : libc::c_short, // routes modified by redirects
    pub rts_unreach     : libc::c_short, // lookups which failed
    pub rts_wildcard    : libc::c_short, // lookups satisfied by a wildcard
    pub rts_badrtgwroute: libc::c_short, // route to gateway is not direct
}

#[allow(non_snake_case)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct rt_addrinfo {
    pub rti_addrs: libc::c_int,
    pub rti_info : [ *mut libc::sockaddr; libc::RTAX_MAX as usize ],
}

#[derive(Debug, Clone)]
pub struct RouteTableMessage {
    pub hdr: rt_msghdr,
    pub dst: IpCidr,
    pub gateway: Addr,
    // pub netmask: Option<std::net::IpAddr>,
    // pub broadcast: Option<std::net::IpAddr>,
}

impl RouteTableMessage {
    pub fn is_up(&self) -> bool {
        self.hdr.rtm_flags & libc::RTF_UP == 1
    }
}


pub fn get() {

}

pub fn add() {
    // route -n get default
    // sudo route add <server_ip> 192.168.199.1
    // sudo route add default 172.16.10.13

    // #[allow(non_snake_case)]
    // #[repr(C)]
    // #[derive(Debug, Clone, Copy)]
    // pub struct rt_msghdr {
    //     pub rtm_msglen: libc::c_ushort, // to skip over non-understood messages
    //     pub rtm_version: libc::c_uchar, // future binary compatibility
    //     pub rtm_type: libc::c_uchar,    // message type 
    //     pub rtm_index: libc::c_ushort,  // index for associated ifp
    //     pub rtm_flags: libc::c_int,     // flags, incl. kern & message, e.g. DONE
    //     pub rtm_addrs: libc::c_int,     // bitmask identifying sockaddrs in msg
    //     pub rtm_pid: libc::pid_t,       // identify sender
    //     pub rtm_seq: libc::c_int,       // for sender to identify action
    //     pub rtm_errno: libc::c_int,     // why failed
    //     pub rtm_use: libc::c_int,       // from rtentry
    //     pub rtm_inits: u32,             // which metrics we are initializing
    //     pub rtm_rmx: rt_metrics,        // metrics themselves
    // }

    // rtm_type   : RTM_ADD RTM_CHANGE RTM_GET RTM_DELETE
    // rtm_flags  : 
    //      flags = RTF_STATIC | RTF_UP
    //      flags |= RTF_HOST
    //      flags |= RTF_GATEWAY
    // rtm_version: RTM_VERSION
    // rtm_seq    : 0
    // 
}

pub fn delete() {

}

// 16 bytes
#[repr(C)]
#[derive(Debug)]
pub struct sockaddr {
    pub sa_len: u8,
    pub sa_family: libc::sa_family_t,  // u8
    pub sa_data: [libc::c_char; 14],
}
// 16 bytes
#[repr(C)]
pub struct sockaddr_in {
    pub sin_len: u8,
    pub sin_family: libc::sa_family_t,  // u8
    pub sin_port: libc::in_port_t,
    pub sin_addr: libc::in_addr,        // u32
    pub sin_zero: [libc::c_char; 8],
}
// 28 bytes
#[repr(C)]
pub struct sockaddr_in6 {
    pub sin6_len: u8,
    pub sin6_family: libc::sa_family_t,
    pub sin6_port: libc::in_port_t,
    pub sin6_flowinfo: u32,
    pub sin6_addr: libc::in6_addr, // [u8; 16]
    pub sin6_scope_id: u32,
}
// 20 bytes
#[repr(C)]
#[derive(Debug)]
pub struct sockaddr_dl {
    pub sdl_len: libc::c_uchar,
    pub sdl_family: libc::c_uchar,
    pub sdl_index: libc::c_ushort,
    pub sdl_type: libc::c_uchar,
    pub sdl_nlen: libc::c_uchar,
    pub sdl_alen: libc::c_uchar,
    pub sdl_slen: libc::c_uchar,
    pub sdl_data: [libc::c_uchar; 12],
}

const NLA_ALIGNTO: usize       = 4;

#[inline]
pub const fn align(len: usize) -> usize {
    (len + NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1)
}

#[derive(Copy, Clone)]
pub enum Addr {
    V4(std::net::Ipv4Addr),
    V6(std::net::Ipv6Addr),
    Link {
        ifindex: u32,
        mac: Option<[u8; 6]>,
    },
}

impl std::fmt::Debug for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Addr::V4(addr) => std::fmt::Debug::fmt(&addr, f),
            Addr::V6(addr) => std::fmt::Debug::fmt(&addr, f),
            Addr::Link { ifindex, mac } => {
                match mac {
                    Some(addr) => {
                        write!(f, "Link#{}({:x}:{:x}:{:x}:{:x}:{:x}:{:x})",
                            ifindex,
                            addr[0],
                            addr[1],
                            addr[2],
                            addr[3],
                            addr[4],
                            addr[5],
                            )
                    },
                    None => write!(f, "Link#{}", ifindex),
                }
            },
        }
    }
}

impl std::fmt::Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

unsafe fn sa_to_ipaddr(sa: *const libc::sockaddr) -> Addr {
    let sa_family = (*sa).sa_family as i32;
    match sa_family {
        libc::AF_INET => {
            let sa_in = sa as *const libc::sockaddr_in;
            let sa_in_addr = (*sa_in).sin_addr.s_addr.to_ne_bytes();
            let ipv4_addr = std::net::Ipv4Addr::from(sa_in_addr);            
            Addr::V4(ipv4_addr)
        },
        libc::AF_INET6 => {
            let sa_in = sa as *const libc::sockaddr_in6;
            let sa_in_addr = (*sa_in).sin6_addr.s6_addr;
            let ipv6_addr = std::net::Ipv6Addr::from(sa_in_addr);
            Addr::V6(ipv6_addr)
        },
        libc::AF_LINK => {
            let sa_dl = sa as *const libc::sockaddr_dl;
            let ifindex = (*sa_dl).sdl_index;
            let mac;
            if (*sa_dl).sdl_alen == 6 {
                let i = (*sa_dl).sdl_nlen as usize;
            
                let a = (*sa_dl).sdl_data[i+0] as u8;
                let b = (*sa_dl).sdl_data[i+1] as u8;
                let c = (*sa_dl).sdl_data[i+2] as u8;
                let d = (*sa_dl).sdl_data[i+3] as u8;
                let e = (*sa_dl).sdl_data[i+4] as u8;
                let f = (*sa_dl).sdl_data[i+5] as u8;
                mac = Some([ a, b, c, d, e, f, ]);
            } else {
                mac = None;
            }
            Addr::Link { ifindex: ifindex as u32, mac: mac }
        },
        _ => unreachable!("UNKNOW_AF_FAMILY({})", sa_family)
    }
}

const RTM_MSGHDR_LEN: usize = std::mem::size_of::<rt_msghdr>();

pub struct RouteTableMessageIter<'a> {
    buffer: &'a mut [u8],
    offset: usize,
}

impl<'a> Iterator for RouteTableMessageIter<'a> {
    type Item = RouteTableMessage;

    fn next(&mut self) -> Option<Self::Item> {
        let buffer = &mut self.buffer[self.offset..];

        if buffer.len() < RTM_MSGHDR_LEN {
            return None;
        }

        unsafe {
            let rtm_hdr = mem::transmute::<*const u8, &rt_msghdr>(buffer.as_ptr());
            assert!(rtm_hdr.rtm_addrs < libc::RTAX_MAX);
            assert_eq!(rtm_hdr.rtm_version, 5);
            assert_eq!(rtm_hdr.rtm_errno, 0);

            let rtm_pkt_len = rtm_hdr.rtm_msglen as usize;
            self.offset += rtm_pkt_len;

            let rtm_pkt = &mut buffer[..rtm_pkt_len];
            assert!(rtm_pkt.len() >= rtm_pkt_len);
            let mut rtm_payload = &mut rtm_pkt[RTM_MSGHDR_LEN..rtm_pkt_len];

            let mut dst = None;
            let mut gateway = None;
            let mut dst_val = None;

            if rtm_hdr.rtm_addrs & ( 1 << libc::RTAX_DST ) == 0 {
                // Need a destination
                return self.next();
            }
            let sa = mem::transmute::<*const u8, &libc::sockaddr>(rtm_payload.as_ptr());
            let sa_len    = sa.sa_len as usize;
            let sa_family = sa.sa_family as i32;
            match sa_to_ipaddr(sa as *const libc::sockaddr) {
                Addr::V4(v4_addr) => {
                    dst = Some(std::net::IpAddr::from(v4_addr));
                },
                Addr::V6(v6_addr) => {
                    dst = Some(std::net::IpAddr::from(v6_addr));
                },
                Addr::Link { .. } => {
                    unreachable!();
                },
            }
            rtm_payload = &mut rtm_payload[align(sa_len)..];
            
            if rtm_hdr.rtm_addrs & ( 1 << libc::RTAX_GATEWAY ) == 0 {
                // Need a gateway
                return self.next();
            }
            let sa = mem::transmute::<*const u8, &libc::sockaddr>(rtm_payload.as_ptr());
            let sa_len    = sa.sa_len as usize;
            let sa_family = sa.sa_family as i32;
            gateway = Some(sa_to_ipaddr(sa as *const libc::sockaddr));
            rtm_payload = &mut rtm_payload[align(sa_len)..];

            if rtm_hdr.rtm_addrs & ( 1 << libc::RTAX_NETMASK ) != 0 {
                let sa = mem::transmute::<*const u8, &libc::sockaddr>(rtm_payload.as_ptr());
                let sa_len    = sa.sa_len as usize;
                let sa_family = sa.sa_family as i32;
                dst_val = Some(rtm_payload[0] as usize);
                rtm_payload = &mut rtm_payload[align(sa_len)..];
            }

            let dst_cidr = match dst {
                Some(addr) => {
                    let prefix_len = if dst_val.is_some() {
                        let dst_val = dst_val.unwrap();
                        (dst_val * 4) - (align(dst_val) - dst_val) * 4
                    } else {
                        if addr.is_unspecified() { 
                            0
                        } else if addr.is_ipv4() {
                            32
                        } else if addr.is_ipv6() {
                            128
                        } else {
                            unreachable!();
                        }
                    };
                    Some(IpCidr::new(addr.into(), prefix_len as u8))
                },
                None => None,
            };

            Some(RouteTableMessage {
                hdr: *rtm_hdr,
                dst: dst_cidr.unwrap(),
                gateway: gateway.unwrap(),
            })
        }
    }
}

pub fn list<'a>(buffer: &'a mut Vec<u8>) -> Result<RouteTableMessageIter<'a>, io::Error> {
    let family = 0;  // inet4 & inet6
    let flags = 0;

    let mut mib: [libc::c_int; 6] = [0; 6];
    let mut lenp: libc::size_t = 0;

    mib[0] = libc::CTL_NET;
    mib[1] = libc::AF_ROUTE;
    mib[2] = 0;
    mib[3] = family; // only addresses of this family
    mib[4] = libc::NET_RT_DUMP;
    mib[5] = flags;  // not looked at with NET_RT_DUMP

    let mib_ptr = &mib as *const libc::c_int as *mut libc::c_int;

    if unsafe { libc::sysctl(mib_ptr, 6, ptr::null_mut(), &mut lenp, ptr::null_mut(), 0) } < 0 {
        return Err(io::Error::last_os_error());
    }

    buffer.resize(lenp as usize, 0);

    let buffer_ptr: *mut u8 = buffer.as_mut_ptr() as _;
    if unsafe { libc::sysctl(mib_ptr, 6, buffer_ptr as _, &mut lenp, ptr::null_mut(), 0) } < 0 {
        return Err(io::Error::last_os_error());
    }

    if buffer_ptr.is_null() {
        return Err(io::Error::last_os_error());
    }

    Ok(RouteTableMessageIter { buffer: buffer, offset: 0 })
}

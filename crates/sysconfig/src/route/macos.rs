use libc;

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



#[derive(Debug, Copy, Clone)]
pub enum RouteAddr {
    V4(std::net::SocketAddrV4),
    V6(std::net::SocketAddrV6),
    Unix(nix::sys::socket::UnixAddr),
    // Linux: sockaddr_ll
    // macOS: sockaddr_dl
    Link(nix::sys::socket::LinkAddr),
    // TODO:
    // Linux/Android Netlink ?
    // sys::sockaddr_nl
    // SysControl ?
}


#[derive(Debug, Clone)]
pub struct RouteTableMessage {
    pub hdr: rt_msghdr,
    pub addrs: Vec<RouteAddr>,
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


unsafe fn sa_to_addr(sa: *mut libc::sockaddr) -> (RouteAddr, *mut u8) {
    match (*sa).sa_family as i32 {
        libc::AF_INET => {
            let sa_in = sa as *mut libc::sockaddr_in;
            let sa_in_addr = (*sa_in).sin_addr.s_addr;
            let sa_in_port = (*sa_in).sin_port;
            let ipv4_addr = std::net::Ipv4Addr::from(sa_in_addr);
            let socket_addr = std::net::SocketAddrV4::new(ipv4_addr, sa_in_port);

            (RouteAddr::V4(socket_addr), sa_in as _)

        },
        libc::AF_INET6 => {
            let sa_in = sa as *mut libc::sockaddr_in6;
            let sa_in_addr = (*sa_in).sin6_addr.s6_addr;
            let sa_in_port = (*sa_in).sin6_port;
            let sa_flowinfo = (*sa_in).sin6_flowinfo;
            let sa_scope_id = (*sa_in).sin6_scope_id;
            
            let ipv6_addr = std::net::Ipv6Addr::from(sa_in_addr);

            let socket_addr = std::net::SocketAddrV6::new(ipv6_addr, sa_in_port, sa_flowinfo, sa_scope_id);

            (RouteAddr::V6(socket_addr), sa_in as _)
        },
        libc::AF_UNIX => {
            println!("sa_len: {:?} sa_family: {:?} sa_data: {:?}",
                (*sa).sa_len,
                (*sa).sa_family,
                mem::transmute::<[libc::c_char; 14], [u8; 14]>((*sa).sa_data),
                );
            unimplemented!()
        },
        libc::AF_LINK => {
            println!("sa_len: {:?} sa_family: {:?} sa_data: {:?}",
                (*sa).sa_len,
                (*sa).sa_family,
                mem::transmute::<[libc::c_char; 14], [u8; 14]>((*sa).sa_data),
                );
            unimplemented!()
        },
        _ => unreachable!(),
    }
}


fn req(family: libc::c_int, flags: libc::c_int) -> Result<(*mut u8, usize), io::Error> {
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

    let mut buf: Vec<libc::c_char> = Vec::with_capacity(lenp as usize);
    let buf_ptr: *mut u8 = buf.as_mut_ptr() as _;
    if unsafe { libc::sysctl(mib_ptr, 6, buf_ptr as _, &mut lenp, ptr::null_mut(), 0) } < 0 {
        return Err(io::Error::last_os_error());
    }

    if buf_ptr.is_null() {
        return Err(io::Error::last_os_error());
    }

    Ok((buf_ptr, lenp))
}

pub fn iter() -> Result<RouteTableMessageIter, io::Error> {
    // let family = sys::AF_INET;
    // let family = sys::AF_INET6;
    let family = 0;  // inet4 & inet6
    let flags = 0;
    let (buf_ptr, len) = req(family, flags)?;

    let end_ptr = unsafe { buf_ptr.add(len) };

    Ok(RouteTableMessageIter {
        buf_ptr,
        len,
        end_ptr,
    })
}


pub struct RouteTableMessageIter {
    buf_ptr: *mut u8,
    #[allow(dead_code)]
    len: usize,
    end_ptr: *mut u8,
}

impl Iterator for RouteTableMessageIter {
    type Item = RouteTableMessage;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf_ptr >= self.end_ptr {
            return None;
        }

        unsafe {
            let rtm = self.buf_ptr as *mut rt_msghdr;
            let rtm_msglen = (*rtm).rtm_msglen as usize;

            let mut sa = rtm.add(1) as *mut libc::sockaddr;
            let mut addrs = vec![];
            for _ in 0..(*rtm).rtm_addrs {
                let (addr, _new_sa) = sa_to_addr(sa);
                let sa_len = (*sa).sa_len as usize;
                sa = sa.add( 32 ) as *mut libc::sockaddr;
                println!("{:?}", addr);
                addrs.push(addr);
            }

            self.buf_ptr = self.buf_ptr.add(rtm_msglen);

            Some(RouteTableMessage {
                hdr: *rtm,
                addrs,
            })
        }
    }
}


pub fn list() -> Result<Vec<RouteTableMessage>, io::Error> {
    iter().map(|handle| handle.collect::<Vec<_>>())
}

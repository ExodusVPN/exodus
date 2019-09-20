extern crate netlink;

use netlink::packet::RouteType;

use std::io;
use std::net::IpAddr;

fn list() -> Result<(), io::Error> {
    let mut buffer = netlink::packet::alloc();
    let mut socket = netlink::route::RouteController::new()?;
    for x in socket.routes(&mut buffer)? {
        let item = x?;
        // println!("{:?}", item);

        if item.kind != RouteType::RTN_UNSPEC && item.kind != RouteType::RTN_UNICAST {
            continue;
        }
        if item.out_ifindex.is_none() {
            continue;
        }
        if item.address_family.is_unspecified() || item.address_family.is_unknow() {
            continue;
        }
        
        let dst = if let Some(cidr) = item.dst_cidr {
            format!("{}", cidr)
        } else {
            if item.address_family.is_ipv4() {
                format!("{}", std::net::Ipv4Addr::UNSPECIFIED)
            } else if item.address_family.is_ipv6() {
                format!("{}", std::net::Ipv6Addr::UNSPECIFIED)
            } else {
                unreachable!()
            }
        };

        let src = if let Some(addr) = item.pref_src {
            format!("{}", addr)
        } else {
            "None".to_string()
        };

        let out_ifindex = if let Some(index) = item.out_ifindex {
            format!("{}", index)
        } else {
            "None".to_string()
        };

        let gateway = if let Some(addr) = item.gateway {
            format!("{}", addr)
        } else {
            "None".to_string()
        };

        println!("table={:16} protocol={:16} scope={:18} kind={:12} DST={:20} PrefSrc={:20} Gateway={:20} Link=#{} Flags={:?}",
            format!("{:?}", item.table),
            format!("{:?}", item.protocol),
            format!("{:?}", item.scope),
            format!("{:?}", item.kind),
            dst,
            src,
            gateway,
            out_ifindex,
            item.flags);
    }

    Ok(())
}

fn del(dst_addr: IpAddr, prefix_len: u8) -> Result<(), io::Error> {
    let mut buffer = netlink::packet::alloc();
    let mut socket = netlink::route::RouteController::new()?;
    socket.remove_route(dst_addr, prefix_len, &mut buffer)
}

fn add(dst_addr: IpAddr, prefix_len: u8, gateway: Option<IpAddr>, ifindex: Option<u32>) -> Result<(), io::Error> {
    let mut buffer = netlink::packet::alloc();
    let mut socket = netlink::route::RouteController::new()?;
    socket.add_route(dst_addr, prefix_len, gateway, ifindex, &mut buffer)
}

fn get(dst_addr: IpAddr, prefix_len: u8) -> Result<netlink::route::route::Route, io::Error> {
    let mut buffer = netlink::packet::alloc();
    let mut socket = netlink::route::RouteController::new()?;
    socket.get_route(dst_addr, prefix_len, &mut buffer)
}

fn main() -> Result<(), io::Error> {
    let addr: IpAddr = [1, 1, 1, 1].into();
    let prefix_len = 32u8;

    println!("$ route get {}/{}", addr, prefix_len);
    println!("{:?}\n\n", get(addr, prefix_len)?);

    list()?;

    let ifindex = 2; // libc::if_nametoindex() -> c_int;
    println!("$ route add {}/{} dev LINK#{}", addr, prefix_len, ifindex);
    add(addr, prefix_len, None, Some(ifindex))?;

    list()?;
    
    println!("$ route del {}/{}", addr, prefix_len);
    del(addr, prefix_len)?;
    
    list()?;

    Ok(())
}
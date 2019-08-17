extern crate netlink;

use netlink::packet::RouteType;

use std::io;

fn main() -> Result<(), io::Error> {
    let mut buffer = netlink::packet::alloc();
    let mut socket = netlink::route::RouteController::new()?;
    for x in socket.routes(&mut buffer)? {
        let item = x?;
        // println!("{:?}", item);
        if (item.kind != RouteType::RTN_UNSPEC && item.kind != RouteType::RTN_UNICAST) || item.out_ifindex.is_none() {
            continue;
        }

        let dst = if let Some(cidr) = item.dst_cidr {
            format!("{}", cidr)
        } else {
            "default".to_string()
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

        println!("table={:16} protocol={:16} scope={:18} kind={:12} DST={:20} PrefSrc={:20} Gateway={:20} Link=#{}",
            format!("{:?}", item.table),
            format!("{:?}", item.protocol),
            format!("{:?}", item.scope),
            format!("{:?}", item.kind),
            dst,
            src,
            gateway,
            out_ifindex);
    }
    
    Ok(())
}
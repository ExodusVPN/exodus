extern crate sysconfig;

use std::io;
use std::net::IpAddr;

#[cfg(target_os = "macos")]
fn list() -> Result<(), io::Error> {
    println!("$ ip route list");
    let mut buffer = Vec::with_capacity(8192);

    for x in sysconfig::route::list(&mut buffer)? {
        println!("DST={:32} Gateway={:32} LINK=#{}",
                format!("{}", x.dst),
                format!("{}", x.gateway),
                x.hdr.rtm_index, );
    }

    println!("\n\n");

    Ok(())
}

#[cfg(target_os = "macos")]
fn get(dst_addr: IpAddr, prefix_len: u8) -> Result<(), io::Error> {
    println!("$ ip route get {}/{}", dst_addr, prefix_len);
    let route = sysconfig::route::get(dst_addr, prefix_len)?;
    match route {
        Some(route) => {
            println!("DST={:32} Gateway={:32} LINK=#{}",
                format!("{}", route.dst),
                format!("{}", route.gateway),
                route.hdr.rtm_index, );
        },
        None => {
            println!("None");
        },
    }

    println!("\n\n");

    Ok(())
}

#[cfg(target_os = "macos")]
fn add(dst_addr: IpAddr, prefix_len: u8, gateway: Option<IpAddr>, ifindex: Option<u32>) -> Result<(), io::Error> {
    match (gateway, ifindex) {
        (Some(gateway_addr), None) => {
            println!("$ ip route add {}/{} {}", dst_addr, prefix_len, gateway_addr);
        },
        (None, Some(interface_index)) => {
            println!("$ ip route add {}/{} -interface LINK#{}", dst_addr, prefix_len, interface_index);
        },
        _ => unreachable!(),
    }
    
    sysconfig::route::add(dst_addr, prefix_len, gateway, ifindex)?;

    println!("\n\n");

    Ok(())
}

#[cfg(target_os = "macos")]
fn del(dst_addr: IpAddr, prefix_len: u8) -> Result<(), io::Error> {
    println!("$ ip route delete {}/{}", dst_addr, prefix_len);
    sysconfig::route::delete(dst_addr, prefix_len)?;

    println!("\n\n");

    Ok(())
}



#[cfg(target_os = "macos")]
fn main() -> Result<(), io::Error> {
    let dst_addr = "1.1.1.1".parse::<std::net::IpAddr>().unwrap();
    let prefix_len = 32u8;

    list()?;

    let gateway = "192.168.199.1".parse::<std::net::IpAddr>().unwrap();
    let ifindex = 5u32; // en0
    add(dst_addr, prefix_len, Some(gateway), None)?;

    list()?;
    del(dst_addr, prefix_len)?;
    
    add(dst_addr, prefix_len, None, Some(ifindex))?;

    list()?;
    del(dst_addr, prefix_len)?;

    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() -> Result<(), io::Error> {
    Ok(())
}

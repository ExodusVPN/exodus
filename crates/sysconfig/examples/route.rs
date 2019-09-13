extern crate sysconfig;

use std::io;


#[cfg(target_os = "macos")]
fn main() -> Result<(), io::Error> {
    let mut buffer = Vec::with_capacity(8192);

    for x in sysconfig::route::list(&mut buffer)? {
        println!("DST={:32} Gateway={:32} LINK=#{}",
                format!("{}", x.dst),
                format!("{}", x.gateway),
                x.hdr.rtm_index, );
    }

    sysconfig::route::get("8.8.8.8".parse::<std::net::IpAddr>().unwrap())?;
    
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() -> Result<(), io::Error> {
    Ok(())
}

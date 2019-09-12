extern crate sysconfig;

use std::io;


fn main() -> Result<(), io::Error> {
    let mut buffer = Vec::with_capacity(8192);

    for x in sysconfig::route::list(&mut buffer)? {
        if x.dst.is_some() {
            println!("DST={:28} Gateway={:42} Netmask={:42} Broadcast={:42} LINK=#{}",
                format!("{}", x.dst.unwrap()),
                format!("{:?}", x.gateway),
                format!("{:?}", x.netmask),
                format!("{:?}", x.broadcast),
                x.hdr.rtm_index, );
        }
    }

    Ok(())
}

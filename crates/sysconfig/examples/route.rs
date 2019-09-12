extern crate sysconfig;

use std::io;


fn main() -> Result<(), io::Error> {
    let mut buffer = Vec::with_capacity(8192);

    for x in sysconfig::route::list(&mut buffer)? {
        println!("DST={:28} Gateway={:42} LINK=#{}",
                format!("{}", x.dst),
                format!("{}", x.gateway),
                x.hdr.rtm_index, );
    }

    Ok(())
}

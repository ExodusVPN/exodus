extern crate netlink;

use std::io;

fn main() -> Result<(), io::Error> {
    let mut buffer = netlink::packet::alloc();
    let mut socket = netlink::route::RouteController::new()?;
    for x in socket.addrs(&mut buffer)? {
        let item = x?;
        println!("{:?}", item);
    }
    
    Ok(())
}
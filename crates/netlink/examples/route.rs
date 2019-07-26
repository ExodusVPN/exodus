extern crate netlink;

use std::io;

fn main() -> Result<(), io::Error> {
    let mut response = netlink::alloc_response();
    let mut socket = netlink::route::RouteController::new()?;
    for x in socket.routes(&mut response)? {
        let item = x?;
        println!("{:?}", item);
    }
    
    Ok(())
}
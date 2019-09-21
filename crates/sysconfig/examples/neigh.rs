extern crate sysconfig;

use std::io;


#[cfg(target_os = "macos")]
fn main() -> Result<(), io::Error> {
    let mut buffer = Vec::with_capacity(8192);
    
    for neigh in sysconfig::neigh::list(&mut buffer)? {
        println!("LINK#{:3}  {}    {}", format!("{}", neigh.link_index), neigh.link_addr, neigh.ip_addr);
    }
    
    Ok(())
}


#[cfg(not(target_os = "macos"))]
fn main() -> Result<(), io::Error> {
    Ok(())
}

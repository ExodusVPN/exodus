extern crate sysconfig;

use std::io;


#[cfg(target_os = "linux")]
fn main() -> Result<(), io::Error> {
    let config = sysconfig::dns::load_resolver_config()?;
    
    println!("{:?}", config);

    Ok(())
}


#[cfg(not(target_os = "linux"))]
fn main() -> Result<(), io::Error> {
    Ok(())
}
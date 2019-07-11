extern crate sysctl;

use std::io;


fn main() -> Result<(), io::Error> {
    #[cfg(target_os = "linux")]
    let key = "net.ipv4.conf.all.forwarding";

    #[cfg(target_os = "macos")]
    let key = "net.inet.ip.forwarding";

    let mib = key.parse::<sysctl::Mib>()?;
    
    println!("{}: {:?}", mib.name()?, mib.value()?);
    
    Ok(())
}
extern crate sysctl;

use std::io;


fn main() -> Result<(), io::Error> {
    let root = sysctl::Mib::default();
    for item in root.iter()? {
        let mib = item?;
        println!("{}", mib.name()?);
    }
    
    Ok(())
}
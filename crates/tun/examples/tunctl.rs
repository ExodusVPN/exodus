extern crate tun;


use std::io::{self, Read};

fn main() -> Result<(), io::Error> {
    let mut device = tun::Device::new("utun6")?;
    device.set_address([10, 0, 0, 1])?;
    device.set_netmask([255, 255, 255, 0])?;
    device.set_mtu(1500)?;
    device.enabled(true)?;

    let mut buf = [0; 4096];
    
    loop {
        let amount = device.read(&mut buf).unwrap();
        println!("{:?}", &buf[0 .. amount]);
    }
}

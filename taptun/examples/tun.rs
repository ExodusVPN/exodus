
#[allow(dead_code, unused_imports)]

extern crate pretty_env_logger;
#[macro_use] extern crate log;


extern crate taptun;
extern crate netpacket;

use std::io::Read;
use std::net::Ipv4Addr;


use taptun::tun;

const MTU: usize = 1500;


/**
    sudo route add 10.0.0.1/24 -interface utun10
    curl "10.0.0.50:80"
    ping 10.0.0.50
    ping 10.0.0.1
    
    sudo route get default
    sudo route delete default
    sudo route add default -interface utun10
    netstat -nr
**/


#[cfg(target_os = "macos")]
fn main (){
    pretty_env_logger::init().unwrap();

    let mut config = tun::Configuration::default();
    config.address(Ipv4Addr::new(10, 0, 0, 1))
           .netmask(Ipv4Addr::new(255, 255, 255, 0))
           .destination(Ipv4Addr::new(10, 0, 0, 50))
           .mtu(MTU as i32)  // https://en.wikipedia.org/wiki/Maximum_transmission_unit
           .name("utun10")   // WARN: XNU
           .up();
    
    let mut buf = [0; MTU];
    
    match tun::create(&config) {
        Ok(mut dev) => {
            println!("TUN 创建成功: {:?}", dev);
            loop {
                let amount = dev.read(&mut buf).unwrap();
                let data: &[u8] = &buf[4 .. amount];
                // warn!("Raw Packet: {:?}", data);
                println!("");

                // // Test Ethernet Packet
                // let packet = netpacket::ethernet::Packet::from_bytes(data).unwrap();
                // let ip = netpacket::ip::Packet::from_bytes(packet.frame().payload());
                // info!("{:?}", ip);

                // // Test Ethernet Frame
                // let frame = netpacket::ethernet::Frame::from_bytes(data).unwrap();
                // let ip    = netpacket::ip::Packet::from_bytes(frame.payload());
                // info!("{:?}", ip);

                // Test Ethernet TCP Packet
                let ip    = netpacket::ip::Packet::from_bytes(data);
                println!("{:?}", ip);
                if ip.is_ok() {
                    let tcp = netpacket::tcp::Packet::from_bytes(ip.unwrap().payload());
                    println!("{:?}", tcp);
                }
            }
        },
        Err(e) => error!("TUN 创建失败: {:?}", e)
    };
}


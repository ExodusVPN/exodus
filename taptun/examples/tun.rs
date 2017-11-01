#![allow(unused_imports, dead_code, unused_mut, unused_must_use, unused_variables)]

extern crate libc;

#[allow(unused_imports)]
#[macro_use(trace, debug, info, warn, error, log)]
extern crate logging;
extern crate netpacket;

extern crate taptun;

use std::io::Read;
use std::net::Ipv4Addr;

use taptun::tun;


#[cfg(unix)]
fn main (){
    logging::init(Some("debug")).unwrap();

    if unsafe { libc::getuid() } > 0 {
        error!("请以管理员身份运行该程序！");
        ::std::process::exit(1);
    }

    let mut config = tun::Configuration::default();

    let name = "utun10";
    let gw = Ipv4Addr::new(10, 0, 0, 1);

    config.address(gw)
           .netmask(Ipv4Addr::new(255, 255, 255, 0))
           .destination(Ipv4Addr::new(0, 0, 0, 0))
           .mtu(1500)
           .name(name)
           .up();
    
    let mut buf: [u8; 1500] = [0u8; 1500];
    
    match tun::create(&config) {
        Ok(mut dev) => {
            info!("虚拟网络设备创建成功, 网关: {:?}", gw);
            warn!("$ sudo route add {}/32 -interface {}", gw, name);
            warn!("$ curl {}:80", gw);
            warn!("$ ping {}", gw);

            loop {
                let amount = dev.read(&mut buf).unwrap();
                info!("Raw Packet: {:?}", &buf[..amount]);

                let offset: usize = if cfg!(target_os = "macOS") {
                    4
                } else {
                    0
                };
                
                let data: &[u8] = &buf[offset .. amount];
                
                if offset == 4 {
                    info!("macOS Packet: {:?}", data);
                }
                
                match netpacket::ip::Packet::from_bytes(data) {
                    Ok(ip_packet) => {
                        info!("IP Packet: {:?}", ip_packet);
                        match netpacket::tcp::Packet::from_bytes(ip_packet.payload()) {
                            Ok(tcp_packet) => {
                                info!("TCP/IP Packet: {:?}", tcp_packet);
                            },
                            Err(e) => {
                                // debug("Unknow Packet: {:?}", e);
                            }
                        }
                    },
                    Err(e) => {
                        // debug("Unknow Packet: {:?}", e);
                    }
                }
            }
        },
        Err(e) => error!("虚拟网络设备创建失败: {:?}", e)
    };
}
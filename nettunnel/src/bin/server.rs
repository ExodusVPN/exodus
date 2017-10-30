#![allow(unused_imports, dead_code, unused_mut, unused_must_use, unused_variables)]

extern crate taptun;
extern crate netpacket;

extern crate futures;

#[macro_use(try_nb)]
extern crate tokio_core;
extern crate tokio_io;
extern crate byteorder;

#[allow(unused_imports)]
#[macro_use(trace, debug, info, warn, error, log)]
extern crate logging;

extern crate libc;
extern crate mio;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate bincode;


use std::fmt;
use std::convert::AsMut;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use std::rc::Rc;
use std::sync::{ Arc, Mutex };
use std::cell::{ RefCell, RefMut, Cell };
use std::borrow::{ BorrowMut, Borrow };
use std::thread;
use std::collections::HashMap;
use std::mem::transmute;
use std::sync::mpsc::channel;


use tokio_core::net::{TcpStream, TcpListener};
use tokio_io::io::{read_exact, read_to_end, read, write_all, Window, copy};

use ::futures::sync::oneshot;
use tokio_core::net::UdpSocket;

use futures::stream;
use futures::future;
use futures::{Future, Stream, Poll, Async};
use byteorder::{BigEndian, ReadBytesExt, ByteOrder};

use mio::Evented;

use taptun::tun;


/**
    sudo route add 10.200.200.1/32 -interface utun10
    curl "10.200.200.1:80"
    ping 10.200.200.1
    
    sudo route get default
    sudo route delete default
    sudo route add default -interface utun10
    netstat -nr

GNU/Linux:
    ip -4 route list 0/0 | awk '{print $3}'
macOS:
    route -n get default | grep gateway | awk '{print $2}'


sudo iptables -t nat -A POSTROUTING -s 10.200.200.0/24 -o utun10 -j MASQUERADE

sudo route add default -net 192.168.0.1

**/

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum Cmd {
    AllocIp,
    ExchangeData
}


fn main () {
    logging::init(Some("debug")).unwrap();

    if unsafe { libc::getuid() } > 0 {
        error!("请以管理员身份运行该程序！");
        ::std::process::exit(1);
    }

    let mut config = tun::Configuration::default();
    config.address(Ipv4Addr::new(10, 200, 200, 1))
           .netmask(Ipv4Addr::new(255, 255, 255, 0))
           .destination(Ipv4Addr::new(0, 0, 0, 0))
           .mtu(1500)
           .name("utun10")
           .up();
    let dev_res = tun::create(&config);
    if dev_res.is_err() {
        error!("虚拟网络设备创建失败: {:?}", dev_res);
        ::std::process::exit(1);
    }
    let mut tun_device = dev_res.unwrap();
    info!("虚拟网络设备 utun10 初始化完成，网关: 10.200.200.1 ...");

    let addr = "0.0.0.0:9250".parse::<::std::net::SocketAddr>().unwrap();
    let udp_socket_raw_fd = mio::net::UdpSocket::bind(&addr).unwrap();
    info!("UDP Socket Listening on: {:?} ...", addr);

    let poll = mio::Poll::new().unwrap();

    const TUN_TOKEN: mio::Token = mio::Token(0);
    const UDP_TOKEN: mio::Token = mio::Token(1);

    tun_device.register(&poll, TUN_TOKEN, mio::Ready::readable(), mio::PollOpt::level()).unwrap();
    poll.register(&udp_socket_raw_fd, UDP_TOKEN, mio::Ready::readable(), mio::PollOpt::level()).unwrap();


    let mut events = mio::Events::with_capacity(1024);
    let mut registry: HashMap<Ipv4Addr, SocketAddr> = HashMap::new();
    let mut buf = [0u8; 1600];

    info!("Ready for transmission.");

    let mut best_ip_number = u32::from(Ipv4Addr::new(10, 200, 200, 9));

    loop {
        poll.poll(&mut events, None).unwrap();
        for event in events.iter() {
            match event.token() {
                UDP_TOKEN => {
                    let (size, remote_socket_addr) = udp_socket_raw_fd.recv_from(&mut buf).unwrap();
                    if size == 0 || remote_socket_addr.ip().is_ipv6() {
                        debug!("Error Pakcet: {:?}", &buf[..size]);
                        continue;
                    }
                    let cmd = buf[0];
                    match cmd {
                        1 => {
                            best_ip_number += 1;
                            if let IpAddr::V4(remote_ip) = remote_socket_addr.ip() {
                                let remote_ip_number = u32::from(remote_ip);
                                let msg = [1, 
                                    ((best_ip_number >> 24) & 0xff) as u8, ((best_ip_number >> 16) & 0xff) as u8,
                                    ((best_ip_number >> 8) & 0xff) as u8, (best_ip_number & 0xff) as u8,
                                    ((remote_ip_number >> 24) & 0xff) as u8, ((remote_ip_number >> 16) & 0xff) as u8,
                                    ((remote_ip_number >> 8) & 0xff) as u8, (remote_ip_number & 0xff) as u8,
                                ];
                                udp_socket_raw_fd.send_to(&msg, &remote_socket_addr);
                                let internal_ip = Ipv4Addr::from(best_ip_number);
                                debug!("为 {:?} 分配虚拟地址 {:?}", remote_socket_addr, internal_ip);
                                registry.insert(internal_ip, remote_socket_addr);
                            }
                        },
                        2 => {
                            let data = &buf[1..size];
                            match tun_device.write(data) {
                                Ok(_) => {},
                                Err(e) => {
                                    debug!("虚拟网络设备写入数据失败: {:?}", e);
                                }
                            };
                        },
                        _ => continue
                    };
                },
                TUN_TOKEN => {
                    let size: usize = tun_device.read(&mut buf).unwrap();
                    if size == 0 {
                        continue;
                    }

                    for (internal_ip, remote_socket_addr) in &registry {
                        let mut data: Vec<u8> = vec![2];
                        data.extend(&buf[..size]);
                        udp_socket_raw_fd.send_to(&data, remote_socket_addr).unwrap();
                        debug!("转发数据至 {:?} ({:?}) ...", internal_ip, remote_socket_addr);
                    }
                },
                _ => unreachable!(),
            }
        }
    }
  
}
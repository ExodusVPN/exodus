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


#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum Cmd {
    AllocIp,
    ExchangeData
}

fn main (){
    logging::init(Some("debug")).unwrap();

    if unsafe { libc::getuid() } > 0 {
        error!("请以管理员身份运行该程序！");
        ::std::process::exit(1);
    }

    let server_addr = "35.194.146.161:9250".parse::<::std::net::SocketAddr>().unwrap();
    let addr = "0.0.0.0:9251".parse::<::std::net::SocketAddr>().unwrap();
    let udp_socket = ::std::net::UdpSocket::bind(&addr).expect("couldn't bind to address");

    info!("UDP Socket Listening at: {:?} ...", addr);

    udp_socket.connect(&server_addr).expect("connect function failed");    

    info!("UDP Socket connect to {:?} ...", server_addr);
    
    let mut buf = [0u8; 1600];

    let internal_ip: Ipv4Addr;
    let public_ip: Ipv4Addr;

    // DHCP
    {
        let msg = [1];
        let size = udp_socket.send(&msg).expect("couldn't send message");
        let size = udp_socket.recv(&mut buf).expect("recv function failed");
        if size == 0 {
            error!("虚拟网络地址申请失败！");
            ::std::process::exit(1);
        }
        match buf[0] {
            1 => {
                internal_ip = Ipv4Addr::from(BigEndian::read_u32(&buf[1..5]));
                public_ip = Ipv4Addr::from(BigEndian::read_u32(&buf[5..9]));
            },
            _ => ::std::process::exit(1)
        };
    }

    let mut config = tun::Configuration::default();
    config.address(internal_ip)
           .netmask(Ipv4Addr::new(255, 255, 255, 0))
           .destination(Ipv4Addr::new(10, 200, 200, 1))
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
    info!("虚拟地址: {:?} ({:?})", internal_ip, public_ip);


    let udp_socket_raw_fd = mio::net::UdpSocket::from_socket(udp_socket).unwrap();
    udp_socket_raw_fd.connect(server_addr).unwrap();

    let mut events = mio::Events::with_capacity(1024);
    let poll = mio::Poll::new().unwrap();

    const TUN_TOKEN: mio::Token = mio::Token(0);
    const UDP_TOKEN: mio::Token = mio::Token(1);

    poll.register(&udp_socket_raw_fd, UDP_TOKEN, mio::Ready::readable(), mio::PollOpt::level()).unwrap();
    tun_device.register(&poll, TUN_TOKEN, mio::Ready::readable(), mio::PollOpt::level()).unwrap();
    
    info!("Ready for transmission.");

    let mut best_ip_number = u32::from(Ipv4Addr::new(10, 200, 200, 9));

    loop {
        poll.poll(&mut events, None).unwrap();
        for event in events.iter() {
            match event.token() {
                UDP_TOKEN => {
                    let size = udp_socket_raw_fd.recv(&mut buf).unwrap();
                    let cmd = buf[0];
                    match cmd {
                        2 => match tun_device.write(&buf[1..size]){
                            Ok(_) => {},
                            Err(e) => {
                                debug!("虚拟网络设备写入数据失败: {:?}", e);
                            }
                        },
                        _ => continue
                    };
                },
                TUN_TOKEN => {
                    let size: usize = tun_device.read(&mut buf).unwrap();
                    if size == 0 {
                        continue;
                    }

                    let mut data = vec![2];
                    data.extend(&buf[..size]);
                    udp_socket_raw_fd.send(&data).unwrap();
                },
                _ => unreachable!()
            }
        }
    }
}


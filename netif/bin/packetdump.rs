#![cfg(any(target_os = "macos", target_os = "freebsd", target_os = "linux"))]

extern crate netif;
extern crate smoltcp;

use netif::LinkLayer;
use netif::sys;
use smoltcp::wire;


use std::env;
use std::mem;
use std::ptr;
use std::io;
use std::os::unix::io::AsRawFd;


fn handle_ip_packet(packet: &[u8]) {
    match wire::IpVersion::of_packet(&packet) {
        Ok(version) => match version {
            wire::IpVersion::Ipv4 => {
                println!("{}", &wire::PrettyPrinter::<wire::Ipv4Packet<&[u8]>>::new("", &packet));
            },
            wire::IpVersion::Ipv6 => {
                println!("{}", &wire::PrettyPrinter::<wire::Ipv6Packet<&[u8]>>::new("", &packet));
            },
            _ => { }
        },
        Err(_) => { }
    }
}

fn handle_ethernet_frame(packet: &[u8]) {
    println!("{}", &wire::PrettyPrinter::<wire::EthernetFrame<&[u8]>>::new("", &packet));
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn main() {
    let mut args = env::args();
    if args.len() < 2 {
        println!("Usage:\n    $ sudo target/debug/packetdump <interface name>");
        return ();
    }
    let ifname = args.nth(1).unwrap().clone();

    let mut raw_socket = netif::RawSocket::open(&ifname)
                            .expect(format!("can't open raw socket on netif {}", ifname).as_str());
    let mut buffer = vec![0u8; raw_socket.blen()];

    let link_layer = raw_socket.link_layer();

    println!("[INFO] Netif: {} Link layer: {:?}\n", ifname, link_layer);

    loop {
        let ret = raw_socket.read(&mut buffer);
        if ret.is_err() {
            println!("[ERROR] {:?}", ret);
            continue;
        }

        let pos = ret.unwrap();
        if pos.is_none() {
            continue;
        }

        let (start, end) = pos.unwrap();

        match link_layer {
            LinkLayer::Null => {
                // macOS loopback or utun
                let packet = &buffer[start+4..end];
                handle_ip_packet(&packet);
            },
            LinkLayer::Eth => {
                let packet = &buffer[start..end];
                handle_ethernet_frame(&packet);
            },
            LinkLayer::Ip => {
                let packet = &buffer[start..end];
                handle_ip_packet(&packet);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn main(){
    let mut args = env::args();
    if args.len() < 2 {
        println!("Usage:\n    $ sudo target/debug/packetdump <interface name>");
        return ();
    }
    let ifname = args.nth(1).unwrap().clone();

    let mut raw_socket = netif::RawSocket::open(&ifname)
                            .expect(format!("can't open raw socket on netif {}", ifname).as_str());
    let raw_fd = raw_socket.as_raw_fd();

    let mut buffer = vec![0u8; raw_socket.blen()];

    let link_layer = raw_socket.link_layer();

    println!("[INFO] Netif: {} Link layer: {:?}\n", ifname, link_layer);
    
    loop {
        let millis: Option<u64> = None;
        unsafe {
            let mut readfds = mem::uninitialized::<sys::fd_set>();
            sys::FD_ZERO(&mut readfds);
            sys::FD_SET(raw_fd, &mut readfds);

            let mut writefds = mem::uninitialized::<sys::fd_set>();
            sys::FD_ZERO(&mut writefds);

            let mut exceptfds = mem::uninitialized::<sys::fd_set>();
            sys::FD_ZERO(&mut exceptfds);

            let mut timeout = sys::timeval { tv_sec: 0, tv_usec: 0 };
            let timeout_ptr =
                if let Some(millis) = millis {
                    timeout.tv_usec = (millis * 1_000) as sys::suseconds_t;
                    &mut timeout as *mut _
                } else {
                    ptr::null_mut()
                };

            let res = sys::select(raw_fd + 1, &mut readfds, &mut writefds, &mut exceptfds, timeout_ptr);
            if res == -1 {
                println!("[ERROR] {:?}", io::Error::last_os_error() );
                break;
            }
        }


        match raw_socket.recv(&mut buffer) {
            Ok(size) => {
                if size <= 0 {
                    continue;
                }
                
                match link_layer {
                    LinkLayer::Null => {
                        // macOS loopback or utun
                        let packet = &buffer[..size];
                        handle_ip_packet(&packet);
                    },
                    LinkLayer::Eth => {
                        let packet = &buffer[..size];
                        handle_ethernet_frame(&packet);
                    },
                    LinkLayer::Ip => {
                        let packet = &buffer[..size];
                        handle_ip_packet(&packet);
                    }
                }
            },
            Err(e) => {
                println!("[ERROR] {:?}", e);
            }
        }
    }
}

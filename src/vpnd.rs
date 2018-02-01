#![feature(test)]

/// VPN Server
extern crate test;
#[allow(unused_imports)]
#[macro_use]
extern crate logging;
extern crate clap;
extern crate ctrlc;
extern crate byteorder;
extern crate mio;
extern crate mio_more;
extern crate futures;

extern crate libc;
extern crate nix;

extern crate openssl;
extern crate rand;
extern crate snap;
extern crate tun;

extern crate ipnetwork;
extern crate smoltcp;
extern crate netif;


pub mod signal;
pub mod syscfg;
pub mod crypto;
pub mod compression;
pub mod error;


use std::env;
use std::process;
use std::time::Duration;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use std::str::FromStr;
use std::io::{self, Read, Write};


use smoltcp::wire;
use tun::platform::Device as TunDevice;
use ipnetwork::Ipv4Network;


const TUN_TOKEN: mio::Token = mio::Token(0);
const UDP_TOKEN: mio::Token = mio::Token(1);


#[derive(Debug)]
pub struct ServerConfig {
    pub verbose: String,

    pub no_autoconfig: bool,
    pub tun_ifname: String,
    pub tun_network: Ipv4Network,

    pub default_ifname: String,
    
    pub server_udp_port: u16,
    
    pub disable_compression: bool,
    pub disable_crypto: bool
}


fn get_public_ip() -> Option<Ipv4Addr> {
    let output = process::Command::new("curl")
        .arg("ipecho.net/plain")
        .output()
        .expect("failed to execute `$ curl http://ipecho.net/plain` ");

    if output.status.success() == false {
        debug!("{}", String::from_utf8(output.stderr).unwrap());
        None
    } else {
        let ipv4_addr: Ipv4Addr = String::from_utf8(output.stdout)
                                    .unwrap()
                                    .parse()
                                    .expect("parse public ip fail.");
        Some(ipv4_addr)
    }
}


#[cfg(target_os = "linux")]
fn boot() -> Result<ServerConfig, io::Error> {
    use clap::{App, Arg};

    let matches = App::new("VPN")
        .version("0.1")
        .author("Luozijun <gnulinux@126.com>")
        .about("VPN server")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .required(false)
                .takes_value(true)
                .help("Use a custom config file")
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .required(false)
                .takes_value(true)
                .default_value("info")
                .help("Specify the logging level. Must conform to the same format as RUST_LOG.")
        )
        .arg(
            Arg::with_name("daemon")
                .long("daemon")
                .required(false)
                .help("VPN server running process into the background")
        )
        .arg(
            Arg::with_name("no-autoconfig")
                .long("no-auto-config")
                .required(false)
                .help("Auto config system routing table and nameserver")
        )
        .arg(
            Arg::with_name("default-ifname")
                .long("default-ifname")
                .required(false)
                .takes_value(true)
                .help("Specify the default network interface")
        )
        .arg(
            Arg::with_name("tun-ifname")
                .long("tun-ifname")
                .required(false)
                .takes_value(true)
                .default_value("utun9")
                .help("Specify the tun network device name")
        )
        .arg(
            Arg::with_name("tun-network")
                .long("tun-network")
                .required(true)
                .takes_value(true)
                .help("Specify the default gateway")
        )
        .arg(
            Arg::with_name("disable-compression")
                .long("disable-compression")
                .required(false)
                .help("Disable compression on transport layer")
        )
        .arg(
            Arg::with_name("disable-crypto")
                .long("disable-crypto")
                .required(false)
                .help("Disable crypto for transport layer")
        )
        .arg(
            Arg::with_name("port")
                .long("port")
                .required(false)
                .takes_value(true)
                .default_value("9050")
                .help("UDP Port")
        )
        .get_matches();


    if matches.is_present("daemon") {
        let mut args = vec![];
        for arg in env::args() {
            if arg != "--daemon" {
                args.push(arg);
            }
        }
        let executable = &args[0];
        let child = process::Command::new(executable)
                            .args(&args[1..])
                            .spawn()
                            .expect("Child process failed to start.");
        let pid = child.id();
        println!("child pid: {}", pid);
        process::exit(0);
    }

    let verbose: String = matches.value_of("verbose").unwrap().to_lowercase();

    let tun_ifname: String = matches.value_of("tun-ifname").unwrap().to_string();
    let tun_network: Ipv4Network = Ipv4Network::from_str(matches.value_of("tun-network").unwrap()).unwrap();
    
    let server_udp_port: u16 = matches.value_of("port").unwrap().parse().unwrap();

    let no_autoconfig: bool = if matches.is_present("no-autoconfig") { true } else { false };

    let disable_compression: bool = if matches.is_present("disable-compression") { true } else { false };
    let disable_crypto: bool = if matches.is_present("disable-crypto") { true } else { false };

    let default_ifname: String = if no_autoconfig {
        match matches.value_of("default-ifname") {
            Some(ifname) => ifname.to_string(),
            None => {
                println!("{}", matches.usage());
                process::exit(1);
            }
        }
    } else {
        match syscfg::get_default_route() {
            Some((ifname, _)) => ifname,
            None => {
                println!("Can't get default gateway.");
                process::exit(1);
            }
        }
    };

    Ok(ServerConfig{
        verbose: verbose,

        no_autoconfig: no_autoconfig,

        default_ifname: default_ifname,

        tun_ifname: tun_ifname,
        tun_network: tun_network,

        server_udp_port: server_udp_port,

        disable_compression: disable_compression,
        disable_crypto: disable_crypto
    })
}

#[cfg(target_os = "macos")]
fn boot() -> Result<ServerConfig, io::Error> {
    unimplemented!()
}

#[cfg(target_os = "linux")]
fn run(config: &ServerConfig) {
    // let gateway_interface_ip = Ipv4Addr::new(0, 0, 0, 0);
    let gateway_interface_ip = {
        let ifindex = netif::sys::if_name_to_index(&config.default_ifname);
        let mut addrs = vec![];
        for iface in netif::interface::interfaces() {
            if iface.index() == ifindex {
                match iface.addr(){
                    Some(addr) => {
                        if !addr.is_loopback() {
                            addrs.push(addr);
                        }
                    },
                    None => { }
                }
            }
        }

        assert_eq!(addrs.len() > 0, true);
        addrs[0]
    };
    let server_socket_addr = SocketAddr::new(IpAddr::V4(gateway_interface_ip), config.server_udp_port);

    let tun_ip = Ipv4Addr::from(u32::from(config.tun_network.ip()) + 1);
    let tun_octets = tun_ip.octets();
    let tun_netmask = config.tun_network.mask();
    let tun_netmask_octets = tun_netmask.octets();
    let tun_ip_addr = wire::Ipv4Address::from_bytes(&tun_octets);
    let mut tun_device: TunDevice = {
        let mut tun_config = tun::Configuration::default();
        tun_config
            .address(tun_ip)
            .netmask(tun_netmask)
            .destination(Ipv4Addr::new(0, 0, 0, 0))
            .mtu(1500)
            .name(config.tun_ifname.clone())
            .up();
        tun::create(&tun_config).expect("can't create tun device.")
    };

    let udp_socket_raw_fd = mio::net::UdpSocket::bind(&server_socket_addr).unwrap();
    info!("bind at {} ...", &server_socket_addr);
    info!("tun device running at: {} --> 0.0.0.0 netmask: {}", tun_ip, tun_netmask);

    // Auto Config
    auto_config(&config);

    let mut udp_buf = [0u8; 1600];
    let mut tun_buf = [0u8; 1600];

    let mut events = mio::Events::with_capacity(1024);
    let mut registry: HashMap<Ipv4Addr, SocketAddr> = HashMap::new();

    let poll = mio::Poll::new().unwrap();
    poll.register(&udp_socket_raw_fd, UDP_TOKEN, mio::Ready::readable(), mio::PollOpt::level()).unwrap();
    poll.register(&tun_device, TUN_TOKEN, mio::Ready::readable(), mio::PollOpt::level()).unwrap();

    info!("Ready for transmission.");
    let mut best_ip_number = u32::from(tun_ip) + 5;

    let timeout = Duration::new(2, 0);
    loop {
        if !signal::is_running() {
            break;
        }
        match poll.poll(&mut events, Some(timeout)) {
            Ok(_) => {},
            Err(_) => continue
        };

        for event in events.iter() {
            match event.token() {
                UDP_TOKEN => {
                    let (size, remote_socket_addr) = udp_socket_raw_fd.recv_from(&mut udp_buf).unwrap();
                    if size == 0 || remote_socket_addr.ip().is_ipv6() {
                        debug!("Error Pakcet: {:?}", &udp_buf[..size]);
                        continue;
                    }
                    let cmd = udp_buf[0];
                    match cmd {
                        1 => {
                            // DHCP
                            best_ip_number += 1;
                            if let IpAddr::V4(remote_ip) = remote_socket_addr.ip() {
                                let remote_octets = remote_ip.octets();
                                let best_octets = Ipv4Addr::from(best_ip_number).octets();
                                
                                let msg = [1,
                                    best_octets[0], best_octets[1], best_octets[2], best_octets[3],
                                    remote_octets[0], remote_octets[1], remote_octets[2], remote_octets[3],
                                    tun_octets[0], tun_octets[1], tun_octets[2], tun_octets[3],
                                    tun_netmask_octets[0], tun_netmask_octets[1], tun_netmask_octets[2], 
                                    tun_netmask_octets[3]
                                ];

                                udp_socket_raw_fd.send_to(&msg, &remote_socket_addr).unwrap();
                                let client_tun_ip = Ipv4Addr::from(best_ip_number);
                                debug!("为 {:?} 分配虚拟地址 {:?}", remote_socket_addr, client_tun_ip);
                                registry.insert(client_tun_ip, remote_socket_addr);
                            }
                        },
                        2 => {
                            let packet = &udp_buf[1..size];
                            
                            let ipv4_packet = wire::Ipv4Packet::new(&packet);
                            let dst_ip = Ipv4Addr::from(ipv4_packet.dst_addr().0);
                            
                            if config.tun_network.contains(dst_ip) {
                                if dst_ip != tun_ip {
                                    match registry.get(&dst_ip) {
                                        Some(remote_socket_addr) => {
                                            udp_socket_raw_fd.send_to(&udp_buf[..size], remote_socket_addr).unwrap();
                                        }
                                        None => { }
                                    }
                                }
                            } else if dst_ip.is_loopback()
                                    || dst_ip.is_link_local()
                                    || dst_ip.is_broadcast()
                                    || dst_ip.is_documentation()
                                    || dst_ip.is_unspecified() {
                                    
                            } else {
                                let _ = tun_device.write(&packet);
                            }
                        },
                        _ => { }
                    }
                },
                TUN_TOKEN => {
                    let size: usize = tun_device.read(&mut tun_buf[1..]).unwrap();
                    let data = if cfg!(target_os = "macos") {
                        if size < 4 {
                            continue;
                        }
                        tun_buf[4] = 2;
                        &tun_buf[4..size+1]
                    } else if cfg!(target_os = "linux") {
                        if size == 0 {
                            continue;
                        }
                        tun_buf[0] = 2;
                        &tun_buf[..size+1]
                    } else {
                        panic!("oops ...");
                    };

                    let packet = &data[1..];
                    if packet[0] == 69 {
                        // Ipv4
                        let ipv4_packet = wire::Ipv4Packet::new(&packet);
                        let dst_ip = Ipv4Addr::from(ipv4_packet.dst_addr().0);
                        match registry.get(&dst_ip) {
                            Some(remote_socket_addr) => {
                                udp_socket_raw_fd.send_to(&data, remote_socket_addr).unwrap();
                            }
                            None => { }
                        }
                    } else if packet[0] == 96 {
                        // IPv6
                        continue;
                    }
                },
                _ => { }
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn run(config: &ServerConfig) {
    unimplemented!()
}


#[cfg(target_os = "linux")]
fn auto_config(config: &ServerConfig) {
    if !config.no_autoconfig {
        // sudo sysctl -w net.ipv4.ip_forward=1
        process::Command::new("sysctl")
            .arg("-w")
            .arg("net.ipv4.ip_forward=1")
            .status()
            .expect("failed to execute process");

        // sudo route add -net 172.16.10.0/24  dev utun10
        process::Command::new("route")
            .arg("add")
            .arg("-net")
            .arg(format!("{}", config.tun_network))
            .arg("dev")
            .arg(&config.tun_ifname)
            .status()
            .expect("failed to execute process");

        // sudo iptables -t nat -A POSTROUTING -s 172.16.10.1/24 -o enp0s3 -j MASQUERADE
        process::Command::new("iptables")
            .arg("-t")
            .arg("nat")
            .arg("-A")
            .arg("POSTROUTING")
            .arg("-s")
            .arg(format!("{}", config.tun_network))
            .arg("-o")
            .arg(&config.default_ifname)
            .arg("-j")
            .arg("MASQUERADE")
            .status()
            .expect("failed to execute process");

        // sudo iptables -A OUTPUT -o utun10 -j ACCEPT
        process::Command::new("iptables")
            .arg("-A")
            .arg("OUTPUT")
            .arg("-o")
            .arg(&config.tun_ifname)
            .arg("-j")
            .arg("ACCEPT")
            .status()
            .expect("failed to execute process");
    }
}

#[cfg(target_os = "macos")]
fn auto_config(config: &ServerConfig) {
    // unimplemented!()
}

#[cfg(target_os = "linux")]
fn cleanup(config: &ServerConfig) {
    // unimplemented!()
}

#[cfg(target_os = "macos")]
fn cleanup(config: &ServerConfig) {
    // unimplemented!()
}


fn main (){
    signal::init();

    let config = boot();
    if config.is_err() {
        println!("Config err: {:?}", config);
        process::exit(1);
    }
    let config = config.unwrap();
    logging::init(Some(&config.verbose)).unwrap();

    run(&config);
    cleanup(&config);
}
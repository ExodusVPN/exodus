
/// VPN Client
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


use std::env;
use std::process;
use std::time::Duration;
use std::fs::{File, OpenOptions};

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

use std::str::FromStr;
use std::io::{self, Read, Write};
use std::os::unix::io::{RawFd, AsRawFd};


use byteorder::{ByteOrder, NetworkEndian};

use mio::Evented;
// use mio::unix::EventedFd;

use smoltcp::wire;
use tun::platform::Device as TunDevice;
use ipnetwork::Ipv4Network;

use netif::{LinkLayer, RawSocket};
use netif::interface::Interface;


const TUN_TOKEN: mio::Token = mio::Token(0);
const UDP_TOKEN: mio::Token = mio::Token(1);
const GATEWAY_TOKEN: mio::Token = mio::Token(2);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SystemDns {
    dns_server: Ipv4Addr,
    #[cfg(target_os = "macos")]
    default_networkservice: String,
    #[cfg(target_os = "linux")]
    resolv_conf: String
}

impl SystemDns {
    #[cfg(target_os = "macos")]
    pub fn new(networkservice: String, dns_server: Ipv4Addr) -> Result<SystemDns, io::Error> {
        Ok(SystemDns {
            dns_server: dns_server,
            default_networkservice: networkservice
        })
    }

    #[cfg(target_os = "linux")]
    pub fn new(dns_server: Ipv4Addr) -> Result<SystemDns, io::Error> {
        match File::open("/etc/resolv.conf") {
            Ok(file) => {
                let mut contents = String::new();
                match file.read_to_string(&mut contents) {
                    Ok(_) => Ok(SystemDns {
                            dns_server: dns_server,
                            resolv_conf: contents
                    }),
                    Err(e) => Err(e)
                }
            }
            Err(e) => Err(e)
        }
    }

    #[cfg(target_os = "macos")]
    pub fn execute(&self) -> Result<(), io::Error> {
         match process::Command::new("networksetup")
                .arg("-setdnsservers")
                .arg(&self.default_networkservice)
                .arg(format!("{}", self.dns_server))
                .status() {
            Ok(status) => {
                if status.success() {
                    Ok(())
                } else {
                    Err(io::Error::new(io::ErrorKind::Other, "Ooops ..."))
                }
            },
            Err(e) => Err(e)
        }
    }

    #[cfg(target_os = "linux")]
    pub fn execute(&self) -> Result<(), io::Error> {
        let data = format!("nameserver {}\n", self.dns_server);
        match OpenOptions::new().write(true).create(true).open("/etc/resolv.conf") {
            Ok(file) => file.write_all(&data.as_bytes()),
            Err(e) => Err(e)
        }
    }

    #[cfg(target_os = "macos")]
    pub fn recover(&self) -> Result<(), io::Error> {
        // sudo networksetup -setdnsservers Wi-Fi Empty
        match process::Command::new("networksetup")
                .arg("-setdnsservers")
                .arg(&self.default_networkservice)
                .arg("Empty")
                .status() {
            Ok(status) => {
                if status.success() {
                    Ok(())
                } else {
                    Err(io::Error::new(io::ErrorKind::Other, "Ooops ..."))
                }
            },
            Err(e) => Err(e)
        }
    }

    #[cfg(target_os = "linux")]
    pub fn recover(&self) -> Result<(), io::Error> {
        match OpenOptions::new().write(true).create(true).open("/etc/resolv.conf") {
            Ok(file) => file.write_all(self.resolv_conf.as_bytes()),
            Err(e) => Err(e)
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AutoSystemConfig {
    pub server_ipv4: Ipv4Addr,
    pub tun_ipv4: Ipv4Addr,

    pub default_ifname: String,
    pub default_gateway: Ipv4Addr,
    pub defaul_dns: SystemDns,
}

impl AutoSystemConfig {
    pub fn execute(&self) -> Result<(), io::Error> {
        Ok(())
    }

    pub fn recover(&self) -> Result<(), io::Error> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct ClientConfig {
    pub verbose: String,

    pub no_autoconfig: bool,
    pub tun_ifname: String,
    pub default_ifname: String,
    pub default_gateway: Ipv4Addr,
    pub default_networkservice: Option<String>,
    
    pub dns_server: Option<Ipv4Addr>,

    pub server_socket_addr: SocketAddr,
    pub local_udp_port: u16,
    
    pub disable_compression: bool,
    pub disable_crypto: bool,
    pub prikey: Option<crypto::rsa::PriKey>,
}


#[cfg(target_os = "linux")]
fn boot() -> Result<ClientConfig, io::Error> {
    error!("VPN client does not yet support your platform");
    unimplemented!()
}


#[cfg(target_os = "macos")]
fn boot() -> Result<ClientConfig, io::Error> {
    use clap::{App, Arg};

    let matches = App::new("VPN")
        .version("0.1")
        .author("Luozijun <gnulinux@126.com>")
        .about("VPN client")
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
                .help("VPN client running process into the background")
        )
        .arg(
            Arg::with_name("no-autoconfig")
                .long("no-auto-config")
                .required(false)
                .help("Auto config system routing table and nameserver")
        )
        .arg(
            Arg::with_name("dns")
                .long("dns")
                .required(false)
                .takes_value(true)
                .default_value("8.8.8.8")
                .help("Use a custom nameserver")
        )
        .arg(
            Arg::with_name("default-ifname")
                .long("default-ifname")
                .required(false)
                .takes_value(true)
                .help("Specify the default network interface")
        )
        .arg(
            Arg::with_name("default-gateway")
                .long("default-gateway")
                .required(false)
                .takes_value(true)
                .help("Specify the default gateway")
        )
        .arg(
            Arg::with_name("default-networkservice")
                .long("default-networkservice")
                .required(false)
                .takes_value(true)
                .help("Specify the default networkservice name (macOS Only)")
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
        .arg(
            Arg::with_name("server-addr")
                .long("server-addr")
                .required(true)
                .takes_value(true)
                .help("VPN server ipv4 address and port. (e.g 35.200.200.111:9050)")
        )
        .arg(
            Arg::with_name("key")
                .long("key")
                .required(false)
                .takes_value(true)
                .help("RSA private key (PEM Format)")
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
    let local_udp_port: u16 = matches.value_of("port").unwrap().parse().unwrap();
    let server_socket_addr: SocketAddr = {
        let sa: SocketAddr = matches.value_of("server-addr").unwrap().parse().unwrap();
        if !sa.ip().is_ipv4() {
            println!("Sry, Only Supported IPv4 Network.");
            process::exit(1);
        } else {
            sa
        }
    };

    let disable_compression: bool = if matches.is_present("disable-compression") { true } else { false };
    let disable_crypto: bool;
    let prikey: Option<crypto::rsa::PriKey> = if matches.is_present("disable-crypto") {
        disable_crypto = true;
        None
    } else {
        disable_crypto = false;
        match matches.value_of("key") {
            Some(key_file_name) => match crypto::rsa::PriKey::from_file(key_file_name) {
                Ok(rsa_prikey) => Some(rsa_prikey),
                Err(e) => {
                    println!("Can't load RSA private key.\n{:?}", e);
                    process::exit(1);
                }
            },
            None => {
                println!("{}", matches.usage());
                process::exit(1);
            }
        }
    };

    let (default_ifname, default_gateway, default_networkservice) = if matches.is_present("no-autoconfig") {
        let default_ifname = match matches.value_of("default-ifname") {
            Some(ifname) => ifname.to_string(),
            None => {
                println!("{}", matches.usage());
                process::exit(1);
            }
        };
        let default_gateway: Ipv4Addr = match matches.value_of("default-gateway") {
            Some(gateway) => gateway.parse().unwrap(),
            None => {
                println!("{}", matches.usage());
                process::exit(1);
            }
        };
        let default_networkservice = None;
        (default_ifname, default_gateway, default_networkservice)
    } else {
        match syscfg::get_default_route() {
            Some((ifname, gateway)) => match syscfg::get_default_networkservice(&ifname) {
                Some(networkservice) => (ifname, gateway, Some(networkservice)),
                None => {
                    println!("Can't get default networkservice.");
                    process::exit(1);
                }
            },
            None => {
                println!("Can't get default gateway.");
                process::exit(1);
            }
        }
    };

    let no_autoconfig: bool;
    let dns_server: Option<Ipv4Addr> = if matches.is_present("no-autoconfig") {
        no_autoconfig = true;
        None
    } else {
        no_autoconfig = false;
        Some(matches.value_of("dns").unwrap().parse().unwrap())
    };
    
    Ok(ClientConfig {
        verbose: verbose,

        tun_ifname: tun_ifname,
        server_socket_addr: server_socket_addr,
        local_udp_port: local_udp_port,

        no_autoconfig: no_autoconfig,

        default_ifname: default_ifname,
        default_gateway: default_gateway,
        default_networkservice: default_networkservice,
        
        // default_dns_config: 

        dns_server: dns_server,

        disable_crypto: disable_crypto,
        disable_compression: disable_compression,
        prikey: prikey
    })
}


fn run (config: &ClientConfig) {
    let gateway_interface = Interface::with_name(&config.default_ifname).unwrap();
    let gateway_interface_ip = gateway_interface.addr().unwrap();

    assert_eq!(config.server_socket_addr.ip().is_ipv4(), true);

    info!("use default interface {:?}", config.default_ifname);
    let udp_socket = {
        let local_udp_socket_addr = SocketAddr::new(IpAddr::V4(gateway_interface_ip), config.local_udp_port);
        let s = UdpSocket::bind(&local_udp_socket_addr).unwrap();
        info!("bind on interface {} {}", config.default_ifname, local_udp_socket_addr);
        s.set_read_timeout(Some(Duration::new(10, 0))).unwrap();
        s.set_write_timeout(Some(Duration::new(10, 0))).unwrap();
        s.connect(&config.server_socket_addr).unwrap();
        info!("connect to {}", config.server_socket_addr);
        s
    };

    let mut udp_buf = [0u8; 1600];
    let mut tun_buf = [0u8; 1600];

    let (tun_ip, public_ip, server_tun_ip, tun_netmask) = {
        let msg = [1u8];
        let size = udp_socket.send(&msg).expect("couldn't send message");
        assert_eq!(size, 1);

        let size = udp_socket.recv(&mut udp_buf).expect("recv function failed");
        if size == 0 {
            error!("tun device dhcp failed.");
            process::exit(2);
        }

        if udp_buf[0] != 1 {
            error!("unknow protocol.");
            process::exit(2);
        }

        let local_tun_ip = Ipv4Addr::from(NetworkEndian::read_u32(&udp_buf[1..5]));
        let local_public_ip = Ipv4Addr::from(NetworkEndian::read_u32(&udp_buf[5..9]));
        let server_gateway_ip = Ipv4Addr::from(NetworkEndian::read_u32(&udp_buf[9..14]));
        let tun_netmask = Ipv4Addr::from(NetworkEndian::read_u32(&udp_buf[14..18]));
        (local_tun_ip, local_public_ip, server_gateway_ip, tun_netmask)
    };

    let mut tun_device: TunDevice = {
        let mut tun_config = tun::Configuration::default();
        tun_config
            .address(tun_ip)
            .netmask(tun_netmask)
            .destination(server_tun_ip)
            .mtu(1500)
            .name(config.tun_ifname.clone())
            .up();
        tun::create(&tun_config).expect("can't create tun device.")
    };

    info!("tun device running at {} --> {} netmask: {}", tun_ip, server_tun_ip, tun_netmask);

    let udp_socket_raw_fd = mio::net::UdpSocket::from_socket(udp_socket).unwrap();


    // Auto Config
    auto_config(&config, &tun_ip);


    let mut events = mio::Events::with_capacity(1024);
    let poll = mio::Poll::new().unwrap();

    poll.register(&udp_socket_raw_fd, UDP_TOKEN, mio::Ready::readable(), mio::PollOpt::level()).unwrap();
    poll.register(&tun_device, TUN_TOKEN, mio::Ready::readable(), mio::PollOpt::level()).unwrap();

    info!("Ready for transmission.");
    let timeout = Some(Duration::new(2, 0));
    loop {
        if !signal::is_running() {
            break;
        }
        match poll.poll(&mut events, timeout) {
            Ok(_) => {},
            Err(_) => continue
        };
        for event in events.iter() {
            match event.token() {
                UDP_TOKEN => {
                    let size = match udp_socket_raw_fd.recv(&mut udp_buf[4..]) {
                        Ok(size) => size,
                        Err(_) => continue
                    };
                    let cmd = udp_buf[4];
                    if cmd != 2 {
                        continue;
                    }
                    let packet = if cfg!(target_os = "macos") {
                        // IPv4: [0, 0, 0, 2]
                        udp_buf[1] = 0;
                        udp_buf[2] = 0;
                        udp_buf[3] = 0;
                        udp_buf[4] = 2;
                        &mut udp_buf[1..size+5]
                    } else if cfg!(target_os = "linux") {
                        &mut udp_buf[5..size+5]
                    } else {
                        panic!("oops...");
                    };
                    let _ = tun_device.write(&packet);
                },
                TUN_TOKEN => {
                    let size: usize = match tun_device.read(&mut tun_buf[1..]){
                        Ok(size) => size,
                        Err(_) => continue
                    };

                    if size == 0 {
                        continue;
                    }
                    let data = if cfg!(target_os = "macos") {
                        tun_buf[4] = 2;
                        &tun_buf[4..size+1]
                    } else if cfg!(target_os = "linux") {
                        tun_buf[0] = 2;
                        &tun_buf[..size+1]
                    } else {
                        panic!("oops ...");
                    };

                    // let packet = &data[1..];
                    let _ = udp_socket_raw_fd.send(&data);
                },
                _ => { }
            }
        }
    }
    drop(tun_device);
}


#[cfg(target_os = "linux")]
fn auto_config(config: &ClientConfig, tun_ip: &Ipv4Addr) {
    unimplemented!()
}

#[cfg(target_os = "macos")]
fn auto_config(config: &ClientConfig, tun_ip: &Ipv4Addr) {
    if !config.no_autoconfig {
        // route -n get default | grep interface | awk '{print $2}'
        let server_ip: Ipv4Addr = match config.server_socket_addr.ip() {
            IpAddr::V4(ipv4_addr) => ipv4_addr,
            _ => unreachable!()
        };
         // sudo route add <server_ip> 192.168.199.1
        process::Command::new("route")
            .arg("add")
            .arg(format!("{}", server_ip))
            .arg(format!("{}", config.default_gateway))
            .status()
            .expect("failed to auto config route");

        // sudo route delete default
        process::Command::new("route")
            .arg("delete")
            .arg("default")
            .status()
            .expect("failed to auto config route");
        // sudo route add default 172.16.10.13
        process::Command::new("route")
            .arg("add")
            .arg("default")
            .arg(format!("{}", tun_ip))
            .status()
            .expect("failed to auto config route");

        info!("auto config routing table    [OK]");

        assert_eq!(config.dns_server.is_some(), true);
        assert_eq!(config.default_networkservice.is_some(), true);
        // networksetup -setdnsservers "Wi-Fi" "8.8.8.8"
        process::Command::new("networksetup")
            .arg("-setdnsservers")
            .arg(config.default_networkservice.clone().unwrap())
            .arg(format!("{}", config.dns_server.unwrap()))
            .status()
            .expect("failed to auto config dns");
        info!("auto config dns server       [OK]");
    }
}

#[cfg(target_os = "linux")]
fn cleanup(config: &Config) {
    unimplemented!()
}


#[cfg(target_os = "macos")]
fn cleanup(config: &ClientConfig) {
    if !config.no_autoconfig {
        // 恢复默认路由表设定
        // sudo route delete default
        process::Command::new("route")
            .arg("delete")
            .arg("default")
            .status()
            .expect("failed to restore default route");
        // sudo route add default 192.168.199.1
        process::Command::new("route")
            .arg("add")
            .arg("default")
            .arg(format!("{}", config.default_gateway))
            .status()
            .expect("failed to restore default route");
        
        let server_ip: Ipv4Addr = match config.server_socket_addr.ip() {
            IpAddr::V4(ipv4_addr) => ipv4_addr,
            _ => unreachable!()
        };
        process::Command::new("route")
            .arg("delete")
            .arg(format!("{}", server_ip))
            .status()
            .expect("failed to restore default route");

        info!("restore default routing table    [OK]");

        // 恢复系统DNS设定
        assert_eq!(config.dns_server.is_some(), true);
        assert_eq!(config.default_networkservice.is_some(), true);
        // sudo networksetup -setdnsservers Wi-Fi Empty
        process::Command::new("networksetup")
            .arg("-setdnsservers")
            .arg(config.default_networkservice.clone().unwrap())
            .arg("Empty")
            .status()
            .expect("failed to restore dns setting");
        info!("restore default dns setting      [OK]");
    }
}


fn main (){
    signal::init();

    let config = boot();
    if config.is_err() {
        println!("Config err: {:?}", config);
        process::exit(1);
    }
    let config = config.unwrap();

    logging::init(Some(config.verbose.as_str())).unwrap();

    run(&config);
    cleanup(&config);
}
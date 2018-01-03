#![cfg(any(target_os = "macos", target_os = "freebsd", target_os = "linux"))]

#[allow(unused_imports)]
#[macro_use]
extern crate logging;
extern crate exodus;
extern crate clap;



use std::net::SocketAddr;

use clap::{App, Arg, SubCommand};

// TUN IP:
//      Ipv4Addr::new(172, 16, 10, 1)
//      172.16.10.1


fn main(){
    exodus::signal::init();
    logging::init(Some("debug")).unwrap();

    let matches = App::new("VPN")
        .version("0.1")
        .author("Luozijun <gnulinux@126.com>")
        .about("VPN Server/client")
        .subcommand(
            SubCommand::with_name("server")
                .about("VPN server)")
                .arg(Arg::with_name("port").required(true).help("port"))
                .arg(Arg::with_name("eth_dev").required(true).help("ethernet interface (e.g eth0/en0)")),
        )
        .subcommand(
            SubCommand::with_name("client")
                .about("VPN client)")
                .arg(Arg::with_name("port").required(true).help("port"))
                .arg(Arg::with_name("eth_dev").required(true).help("ethernet interface (e.g eth0/en0)"))
                .arg(Arg::with_name("server_addr").required(true).help("vpn server socket addr"))
        )
        .get_matches();

        match (
            matches.subcommand_matches("server"),
            matches.subcommand_matches("client")
        ) {
            (Some(sub_matches), None) => {
                // Server
                let eth_dev = sub_matches.value_of("eth_dev").unwrap();
                let port: u16 = sub_matches.value_of("port").unwrap().parse().unwrap();
                exodus::create_vpn_server("utun10", eth_dev, port);
            },
            (None, Some(sub_matches)) => {
                // Client
                let eth_dev = sub_matches.value_of("eth_dev").unwrap();
                let port: u16 = sub_matches.value_of("port").unwrap().parse().unwrap();
                let server_socket_addr: SocketAddr = sub_matches.value_of("server_addr").unwrap().parse().unwrap();
                exodus::create_vpn_client("utun9", eth_dev, port, server_socket_addr);
            },
            _ => {
                println!("{}", matches.usage());
            }

        }

}


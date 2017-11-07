#![feature(ip)]
// #![allow(unused_imports, dead_code, unused_mut, unused_must_use,
// unused_variables)]


#[allow(unused_imports)]
#[macro_use(trace, debug, info, warn, error, log)]
extern crate logging;
extern crate netpacket;
extern crate taptun;

extern crate clap;
extern crate ctrlc;
extern crate mio;
extern crate byteorder;

pub extern crate pnet;

pub mod sysctl;
pub mod gateway;
pub mod signal;
pub mod server;
pub mod client;

// pub use pnet;

fn main() {
    signal::init();

    use clap::{App, Arg, SubCommand};
    let matches = App::new("Net Tunnel")
        .version("0.1")
        .author("Luozijun <gnulinux@126.com>")
        .about("an VPN client and server")
        .subcommand(
            SubCommand::with_name("listen")
                .about("VPN Server")
                .arg(Arg::with_name("socket_addr").required(true).help(
                    "IPv4 Address and port (example: 0.0.0.0:9000)",
                ))
                .arg(Arg::with_name("gateway").required(true).help(
                    "Virtual Gateway (example: 10.10.10.1, 172.16.0.1, 192.168.0.1)",
                )),
        )
        .subcommand(SubCommand::with_name("connect").about("VPN Client").arg(
            Arg::with_name("socket_addr").required(true).help(
                "IPv4 Address and port (example: 121.221.220.35:9000)",
            ),
        ))
        .arg(
            Arg::with_name("logging")
                .required(false)
                .short("l")
                .long("logging")
                .help("logging level"),
        )
        .get_matches();

    let logging_level = match matches.value_of("logging") {
        Some(lv) => lv,
        None => "debug",
    };
    logging::init(Some(logging_level)).unwrap();
    assert!(sysctl::enable_ipv4_forwarding());

    // Server
    match matches.subcommand_matches("listen") {
        Some(sub_matches) => {
            let addr_val = sub_matches.value_of("socket_addr").unwrap();
            let gateway_val = sub_matches.value_of("gateway").unwrap();

            let socket_addr: ::std::net::SocketAddr = addr_val.parse().expect("socket addr parse error");
            let gateway_addr: ::std::net::Ipv4Addr = gateway_val.parse().expect("gateway addr parse error");

            assert_eq!(
                socket_addr.ip().is_ipv4() && (socket_addr.ip().is_global() || socket_addr.ip().is_unspecified()),
                true
            );
            assert_eq!(gateway_addr.is_private(), true);

            server::main(socket_addr, gateway_addr);
        }
        None => {}
    }

    // Client
    match matches.subcommand_matches("connect") {
        Some(sub_matches) => {
            let socket_addr: ::std::net::SocketAddr = sub_matches
                .value_of("socket_addr")
                .unwrap()
                .parse()
                .expect("socket addr parse error");

            assert_eq!(
                socket_addr.ip().is_ipv4() && socket_addr.ip().is_global(),
                true
            );
            client::main(socket_addr);
        }
        None => {}
    }
}

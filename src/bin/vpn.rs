
#[allow(unused_imports)]
#[macro_use]
extern crate logging;
extern crate exodus;

use std::env;
use std::net::SocketAddr;


// TUN IP:
//      Ipv4Addr::new(172, 16, 10, 1)
//      172.16.10.1


fn run_server() {
    info!("running server ...");
    let socket_addr: SocketAddr = "0.0.0.0:9250".parse().unwrap();
    exodus::create_vpn_server("utun10", socket_addr);
}

fn run_client(){
    info!("running client ...");
    let server_socket_addr: SocketAddr = "192.168.199.232:9250".parse().unwrap();
    exodus::create_vpn_client("utun10", "en0", server_socket_addr);
}

fn main(){
    exodus::signal::init();
    logging::init(Some("debug")).unwrap();

    let mut args = env::args();
    
    let cmd = args.nth(1).unwrap();
    if cmd == "server" {
        run_server();
    } else if cmd == "client" {
        run_client();
    } else {

    }
}


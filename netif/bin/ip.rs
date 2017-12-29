#![cfg(any(target_os = "macos", target_os = "freebsd"))]

extern crate clap;
extern crate netif;

use clap::{App, Arg, SubCommand};

fn main(){
    let matches = App::new("IpRoute2")
        .version("0.1")
        .author("Luozijun <gnulinux@126.com>")
        .about("show links(Network interface), neighbors(ARP table and NDP table), routing table")
        .subcommand(
            SubCommand::with_name("link")
                .about("Show links(Network interface)")
                .arg(
                    Arg::with_name("list").required(false).help("Show links")
                )
                .arg(
                    Arg::with_name("add").required(false).help("Add links")
                ),
        )
        .subcommand(
            SubCommand::with_name("neigh")
                .about("Show neighbors(ARP table and NDP table)")
                .arg(
                    Arg::with_name("list").required(false).help("show neighbors")
                )
                .arg(Arg::with_name("add").required(false).help(""))
        )
        .subcommand(
            SubCommand::with_name("route")
                .about("Show routing table")
                .arg(
                    Arg::with_name("list").required(false).help("Show routing table")
                )
        )
        .get_matches();

    match (
        matches.subcommand_matches("link"),
        matches.subcommand_matches("neigh"),
        matches.subcommand_matches("route"),
    ) {
        (Some(sub_matches), None, None) => {
            let ifaces = netif::interface::interfaces();
            for x in ifaces{
                println!("{}", x);
            }
        },
        (None, Some(sub_matches), None) => {
            let arp_table = netif::neighbor::V4::list().unwrap();
            println!("IP Address              Hardware Address     Netif");
            for item in arp_table.iter() {
                println!("{}", item);
            }
        },
        (None, None, Some(sub_matches)) => {
            let routing_table = netif::route::list().unwrap();
            println!("{:40} {:40} {:55} {}", "Destination", "Gateway", "Flags", "Netif");
            for item in routing_table.iter() {
                println!("{}", item);
            }
        },
        _ => {
            println!("{}", matches.usage());
        }
    }
}
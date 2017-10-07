#![feature(lookup_host)]
extern crate trust_dns_resolver;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::io::{Error, ErrorKind};

use trust_dns_resolver::config::{
    NameServerConfig, ResolverConfig, ResolverOpts,
    Protocol, LookupIpStrategy
};
use trust_dns_resolver::Resolver;



#[allow(dead_code)]
fn lookup_host (s: &str) -> Vec<IpAddr> {
    ::std::net::lookup_host(s).unwrap().map(|socket_addr: SocketAddr| socket_addr.ip()).collect::<Vec<IpAddr>>()
}

pub struct DNS {
    resolver: Resolver
}

impl DNS {
    #[allow(unused_doc_comment)]
    pub fn new() -> Result<DNS, Error> {
        /**
        DNS 协议:
            TCP/UDP 53
        NOTE:
            不少代理是无法代理 UDP 协议的，这意味着你的DNS查询服务可能依然是在本地操作的。
        **/
        let mut resolver_config = ResolverConfig::new();
        resolver_config.add_name_server(NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            protocol   : Protocol::Tcp,
        });
        resolver_config.add_name_server(NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 53),
            protocol   : Protocol::Tcp,
        });
        resolver_config.add_name_server(NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x88, 0x88)), 53),
            protocol   : Protocol::Tcp,
        });
        resolver_config.add_name_server(NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x88, 0x44)), 53),
            protocol   : Protocol::Tcp,
        });

        let mut resolver_opts        = ResolverOpts::default();
        resolver_opts.validate       = false;
        resolver_opts.use_hosts_file = true;
        resolver_opts.ip_strategy    = LookupIpStrategy::Ipv4thenIpv6;

        match Resolver::new(resolver_config, resolver_opts) {
            Ok(resolver) => Ok(DNS{resolver: resolver}),
            Err(_) => Err(Error::new(ErrorKind::Other, "Oh, no ..."))
        }
    }

    pub fn lookup(&self, s: &str) -> Vec<IpAddr> {
        match s.clone().parse() {
            Ok(ip_addr) => vec![ip_addr],
            Err(_) => {
                match self.resolver.lookup_ip(s) {
                    Ok(answers) => answers.iter().collect::<Vec<IpAddr>>(),
                    Err(_)  => vec![]
                }
            }
        }
    }
}


fn main (){
    let dns = DNS::new().unwrap();
    println!("{:?}", dns.lookup("localhost"));
    println!("{:?}", dns.lookup("127.0.0.1"));
    println!("{:?}", dns.lookup("59.24.3.173"));
    println!("{:?}", dns.lookup("www.baidu.com"));
    println!("{:?}", dns.lookup("www.youtube.com"));
}

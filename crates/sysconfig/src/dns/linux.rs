use crate::{IpCidr, Ipv4Cidr, Ipv6Cidr, ip_cidr_from_netmask, netmask_from_ipcidr, };

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::convert::TryFrom;

// https://tools.ietf.org/html/rfc952
const HOSTS_FILE_PATH: &str           = "/etc/hosts";
// http://man7.org/linux/man-pages/man5/resolv.conf.5.html
const RESOLVER_CONFIG_FILE_PATH: &str = "/etc/resolv.conf";

const CR: u8 = b'\r';
const LF: u8 = b'\n';

#[cfg(unix)]
const LINE_BREAK: &str = "\n";
#[cfg(windows)]
const LINE_BREAK: &str = "\r\n";


struct Lines<'a> {
    start: usize,
    end: usize,
    buffer: &'a [u8],
}

impl<'a> Iterator for Lines<'a> {
    type Item = (usize, usize);
    
    fn next(&mut self) -> Option<Self::Item> {
        if self.end >= self.buffer.len() {
            return None;
        }

        loop {
            if self.end >= self.buffer.len() {
                let pos = (self.start, self.buffer.len());
                self.start = self.buffer.len();
                if pos.0 == pos.1 {
                    return self.next();
                } else {
                    return Some(pos);
                }
            }

            let ch = self.buffer[self.end];
            match ch {
                LF => {
                    let pos = (self.start, self.end);
                    self.end += 1;
                    self.start = self.end;
                    if pos.0 == pos.1 {
                        return self.next();
                    } else {
                        return Some(pos);
                    }
                },
                CR => {
                    match self.buffer.get(self.end + 1) {
                        Some(&LF) => {
                            let pos = (self.start, self.end);
                            self.end += 2;
                            self.start = self.end;
                            if pos.0 == pos.1 {
                                return self.next();
                            } else {
                                return Some(pos);
                            }
                        },
                        _ => {
                            let pos = (self.start, self.end);
                            self.end += 1;
                            self.start = self.end;
                            if pos.0 == pos.1 {
                                return self.next();
                            } else {
                                return Some(pos);
                            }
                        }
                    }
                },
                _ => {
                    self.end += 1;
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolverConfig {
    pub nameservers: Vec<IpAddr>,
    pub domains: Vec<String>,
    pub search: Vec<String>,
    pub sortlist: Vec<IpCidr>,
}

#[derive(Debug, Clone)]
enum ResolverConfigItem {
    Empty,
    Comment,
    NameServer(IpAddr),
    Domain(String),
    Search(Vec<String>),
    SortList(Vec<IpCidr>),
    // Options(),
}

impl TryFrom<&[u8]> for ResolverConfigItem {
    type Error = io::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        // http://man7.org/linux/man-pages/man5/resolv.conf.5.html
        const NAMESERVER: &[u8] = b"nameserver";
        const DOMAIN: &[u8]     = b"domain";
        const SEARCH: &[u8]     = b"search";
        const SORTLIST: &[u8]   = b"sortlist";
        const OPTIONS: &[u8]    = b"options";
        
        let mut token_start: usize = 0;
        let mut offset: usize = 0;

        while value[offset].is_ascii_whitespace() {
            offset += 1;
            token_start = offset;
            if offset >= value.len() {
                return Ok(Self::Empty);
            }
        }

        loop {
            if offset >= value.len() {
                break;
            }

            let ch = value[offset];
            if !ch.is_ascii() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "not an ascii token."));
            }

            if ch.is_ascii_whitespace() {
                break;
            }

            match ch {
                b'#' => return Ok(Self::Comment),
                b'a' ..= b'z' => offset += 1,
                _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("invalid character {:?} in identifier.", ch) )),
            }
        }

        let token = &value[token_start..offset];
        if token == b"" {
            return Ok(Self::Empty);
        }

        token_start = offset;
        while value[offset] != b'#' {
            if offset < value.len() - 1 {
                offset += 1;
            } else if offset == value.len() - 1 {
                offset += 1;
                break;
            } else {
                break;
            }
        }

        let val = std::str::from_utf8(&value[token_start..offset])
                    .map(|s| s.trim())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid utf-8 sequence."))?;

        match token {
            NAMESERVER => {
                // Name server IP address
                // 
                // Example:
                //      nameserver 1.1.1.1
                //      nameserver 8.8.8.8
                //      nameserver 2620:fe::fe
                //      nameserver 2620:fe::9
                match val.parse::<IpAddr>() {
                    Ok(addr) => Ok(ResolverConfigItem::NameServer(addr)),
                    Err(_) => Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid IP address syntax.")),
                }
            },
            DOMAIN => {
                // Local domain name.
                // 
                // Example:
                //      domain lan
                // 
                // TODO: Check DOMAIN ?
                Ok(ResolverConfigItem::Domain(val.to_string()))
            },
            SEARCH => {
                // Search list for host-name lookup.
                // The search list is currently limited to six domains with a total of 256 characters.
                // 
                // Example:
                //      search example.com local.test
                let search = val.split(" ")
                    .map(|s| s.trim().to_string())
                    .collect::<Vec<String>>();
                Ok(ResolverConfigItem::Search(search))
            },
            SORTLIST => {
                // A sortlist is specified by IP-address-netmask
                // pairs.  The netmask is optional and defaults to the natural
                // netmask of the net.
                // The IP address and optional network pairs
                // are separated by slashes.  Up to 10 pairs may be specified.
                // 
                // Example:
                //      sortlist 130.155.160.0/255.255.240.0 130.155.0.0
                let mut sortlist = vec![];
                for s in val.split(" ") {
                    let s = s.trim();
                    let has_slash = s.contains('/');
                    let mut netmask_s = None;
                    let addr = if has_slash {
                        // CIDR
                        let tmp = s.split('/').collect::<Vec<&str>>();
                        if tmp.len() != 2 {
                            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid IP/netmask address syntax."));
                        }
                        netmask_s = Some(tmp[1]);
                        tmp[0].parse::<IpAddr>()
                    } else {
                        s.parse::<IpAddr>()
                    };
                    
                    let addr = addr.map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid IP address syntax."))?;
                    match netmask_s {
                        Some(s) => {
                            let netmask = s.parse::<IpAddr>()
                                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid IP address syntax."))?;
                            
                            let cidr = ip_cidr_from_netmask(addr, netmask)
                                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid IP/netmask address syntax."))?;

                            sortlist.push(cidr);
                        },
                        None => {
                            let prefix_len = if addr.is_ipv4() { 32 } else { 128 };
                            let cidr = IpCidr::new(addr.into(), prefix_len);

                            sortlist.push(cidr);
                        }
                    }
                }

                Ok(ResolverConfigItem::SortList(sortlist))
            },
            OPTIONS => {
                // Options allows certain internal resolver variables to be
                // modified.
                // The syntax is
                //      options <option> ...
                // 
                // Detail: http://man7.org/linux/man-pages/man5/resolv.conf.5.html
                // 
                unimplemented!()
            },
            _ => {
                Err(io::Error::new(io::ErrorKind::InvalidInput, "unknow token."))
            }
        }
    }
}

#[inline]
fn lines<'a>(buffer: &'a [u8]) -> Lines<'a> {
    Lines { start: 0, end: 0, buffer: buffer }
}

fn parse_resolver_config(buffer: &[u8]) -> Result<ResolverConfig, io::Error> {
    let mut resolver_config = ResolverConfig {
        nameservers: Vec::new(),
        domains: Vec::new(),
        search: Vec::new(),
        sortlist: Vec::new(),
    };

    for (start, end) in lines(&buffer) {
        let line = &buffer[start..end];
        let item = ResolverConfigItem::try_from(line)?;
        match item {
            ResolverConfigItem::NameServer(addr) => {
                resolver_config.nameservers.push(addr);
            },
            ResolverConfigItem::Domain(domain) => {
                resolver_config.domains.push(domain);
            },
            ResolverConfigItem::Search(hostnames) => {
                for hostname in hostnames.into_iter() {
                    if !resolver_config.search.contains(&hostname) {
                        resolver_config.search.push(hostname);
                    }
                }
            },
            ResolverConfigItem::SortList(ip_cidr_list) => {
                for ip_cidr in ip_cidr_list.into_iter() {
                    if !resolver_config.sortlist.contains(&ip_cidr) {
                        resolver_config.sortlist.push(ip_cidr);
                    }
                }
            },
            ResolverConfigItem::Empty | ResolverConfigItem::Comment => { },
        }
    }

    Ok(resolver_config)
}


pub fn load_resolver_config() -> Result<ResolverConfig, io::Error> {
    let buffer = fs::read(RESOLVER_CONFIG_FILE_PATH)?;
    parse_resolver_config(&buffer)
}

pub fn save_resolver_config(config: &ResolverConfig) -> Result<(), io::Error> {
    let mut file = OpenOptions::new().create(true).write(true).open(RESOLVER_CONFIG_FILE_PATH)?;
    for nameserver in config.nameservers.iter() {
        file.write_all(format!("nameserver {}{}", nameserver, LINE_BREAK).as_bytes())?;
    }
    for domain in config.domains.iter() {
        file.write_all(format!("domain {}{}", domain, LINE_BREAK).as_bytes())?;
    }

    let search = config.search.join(" ");
    if search.len() > 0 {
        file.write_all(format!("search {}{}", search, LINE_BREAK).as_bytes())?;
    }
    
    let sortlist = config.sortlist.iter()
        .map(|cidr| {
            let addr = cidr.address();
            let netmask = netmask_from_ipcidr(*cidr);
            format!("{}/{}", addr, cidr)
        })
        .collect::<Vec<String>>()
        .join(" ");
    if sortlist.len() > 0 {
        file.write_all(format!("sortlist {}{}", sortlist, LINE_BREAK).as_bytes())?;
    }

    Ok(())
}

pub fn load_hosts() -> Result<Vec<(IpAddr, String)>, io::Error> {
    let buffer = fs::read(HOSTS_FILE_PATH)?;
    let mut hosts = vec![];

    for (start, end) in lines(&buffer) {
        let line = &buffer[start..end];
        let mut val = std::str::from_utf8(line)
                    .map(|s| s.trim())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid utf-8 sequence."))?;
        if val.starts_with("#") {
            continue;
        }

        if val.contains('#') {
            val = val.split('#').next().unwrap();
        }

        let tmp = val.split(' ').collect::<Vec<&str>>();
        if tmp.len() < 2 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid host line."));
        }

        let addr = tmp[0].parse::<IpAddr>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid IP address syntax."))?;

        for hostname in &tmp[1..] {
            hosts.push((addr, hostname.trim().to_string()));
        }
    }

    Ok(hosts)
}

pub fn save_hosts(hosts: &[(IpAddr, String)]) -> Result<(), io::Error> {
    let mut file = OpenOptions::new().create(true).write(true).open(HOSTS_FILE_PATH)?;

    for (addr, hostname) in hosts.iter() {
        file.write_all(format!("{}    {}{}", addr, hostname, LINE_BREAK).as_bytes())?;
    }

    Ok(())
}


pub fn get_default_dns() -> Option<Vec<IpAddr>> {
    let config = load_resolver_config().ok()?;
    Some(config.nameservers)
}


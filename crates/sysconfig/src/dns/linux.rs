use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::IpAddr;

// file: /etc/resolv.conf

pub fn get_default_dns() -> Option<Vec<IpAddr>> {
    
    match File::open("/etc/resolv.conf") {
        Ok(mut file) => {
            let mut ips = Vec::new();

            let mut contents = String::new();
            file.read_to_string(&mut contents).ok()?;
            for line in contents.lines() {
                if line.starts_with("nameserver") {
                    for tmp in line.trim().split(" ") {
                        if let Ok(ip) = tmp.parse::<IpAddr>() {
                            ips.push(ip);
                        }
                    }
                }
            }
            
            if ips.len() > 0 {
                return Some(ips);
            } else {
                return None;
            }
        },
        Err(_) => None,
    }
}


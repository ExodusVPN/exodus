
use std::process;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DefaultDNS {
    #[cfg(target_os = "macos")]
    pub default_networkservice: String,

    #[cfg(target_os = "linux")]
    pub resolv_conf: String,

    // #[cfg(target_os = "linux")]
    // pub nameservers: Vec<IpAddr>,
    // #[cfg(target_os = "linux")]
    // pub search: Vec<String>,
}


#[cfg(target_os = "macos")]
pub fn get_default_networkservice(default_ifname: &str) -> Option<String> {
    // networksetup -listnetworkserviceorder
    match process::Command::new("networksetup")
            .arg("-listnetworkserviceorder")
            .output() {
        Ok(output) => {
            if output.status.success() {
                for line in String::from_utf8(output.stdout).unwrap().lines() {
                    if line.find(default_ifname).is_some() {
                        return Some(line
                                    .split(",").nth(0).unwrap()
                                    .split(":").nth(1).unwrap()
                                    .trim()
                                    .to_string());
                    }
                }
            }
        }
        Err(_) => {  }
    }
    
    None
}

#[cfg(target_os = "macos")]
pub fn get_default_route() -> Option<(String, Ipv4Addr)> {
    // route get default
    match process::Command::new("route")
            .arg("-n")
            .arg("get")
            .arg("default")
            .output() {
        Ok(output) => {
            if output.status.success() {
                let mut ifname: Option<String> = None;
                let mut gateway: Option<Ipv4Addr> = None;

                for line in String::from_utf8(output.stdout).unwrap().lines() {
                    let s = line.trim();
                    if s.starts_with("gateway") {
                        if gateway.is_none() {
                            let ip: Ipv4Addr = s.split(":").nth(1).unwrap().trim().parse().unwrap();
                            gateway = Some(ip);
                        }
                    } else if s.starts_with("interface") {
                        if ifname.is_none() {
                            let ss = s.split(":").nth(1).unwrap().trim().to_string();
                            ifname = Some(ss);
                        }
                    }
                }
                if ifname.is_some() && gateway.is_some() {
                    return Some((ifname.unwrap(), gateway.unwrap()))
                }
            }
        },
        Err(_) => { }
    }

    None
}

#[cfg(target_os = "linux")]
pub fn get_default_route() -> Option<(String, Ipv4Addr)> {
    // ip route
    match process::Command::new("ip")
            .arg("route")
            .output() {
        Ok(output) => {
            if output.status.success() {
                for line in String::from_utf8(output.stdout).unwrap().lines() {
                    let s = line.trim();
                    if s.starts_with("default") {
                        let mut _tmp = s.split(" ").collect::<Vec<&str>>();
                        assert_eq!(_tmp.len(), 5);
                        let gateway_ip: Ipv4Addr = _tmp[2].trim().parse().unwrap();
                        let ifname = _tmp[4].trim().to_string();
                        return Some((ifname, gateway_ip))
                    }
                }
            }
        },
        Err(_) => { }
    }

    None
}

#[cfg(target_os = "macos")]
pub fn get_default_dns(networkservice: String) -> Option<DefaultDNS> {
    Some(DefaultDNS{
        default_networkservice: networkservice
    })
}

#[cfg(target_os = "linux")]
pub fn get_default_dns() -> Option<DefaultDNS> {
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};

    match File::open("/etc/resolv.conf") {
        Ok(mut file) => {
            let mut contents = String::new();
            match file.read_to_string(&mut contents) {
                Ok(_) => Some(DefaultDNS {
                        resolv_conf: contents
                }),
                Err(e) => None
            }
        }
        Err(e) => None
    }
}

// #[cfg(target_os = "macos")]
// pub fn set_default_dns(networkservice: String, dns_server: Ipv4Addr) -> Result<(), io::Error> {
    
// }
// // sudo networksetup -setdnsservers Wi-Fi Empty
//         match process::Command::new("networksetup")
//                 .arg("-setdnsservers")
//                 .arg(&self.default_networkservice)
//                 .arg("Empty")
//                 .status() {
//             Ok(status) => {
//                 if status.success() {
//                     Ok(())
//                 } else {
//                     Err(io::Error::new(io::ErrorKind::Other, "Ooops ..."))
//                 }
//             },
//             Err(e) => Err(e)
//         }
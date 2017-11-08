

use std::net::Ipv4Addr;
use std::process::Command;

use pnet::util::MacAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemGateway {
    ifname: String,
    ipv4_addr: Ipv4Addr,
    ether_addr: [u8; 6],
    current_gateway_addr: Option<Ipv4Addr>,
}

impl SystemGateway {
    pub fn new() -> Result<Self, String> {
        // get default gateway ip addr
        let cmd = if cfg!(target_os = "linux") {
            "ip -4 route list 0/0 | awk '{print $3}'"
        } else if cfg!(target_os = "macos") {
            "route -n get default | grep gateway | awk '{print $2}'"
        } else {
            unimplemented!()
        };
        let output = Command::new("bash").arg("-c").arg(cmd).output().unwrap();

        if !output.status.success() {
            debug!("{}", String::from_utf8(output.stderr).unwrap());
            panic!("获取系统默认网关地址失败！");
        }
        let ipv4_addr = String::from_utf8(output.stdout)
            .unwrap()
            .trim_right()
            .to_string();

        // get default gateway interface name
        let ifname_cmd = if cfg!(target_os = "linux") {
            "ip -4 route list 0/0 | awk '{print $5}'"
        } else if cfg!(target_os = "macos") {
            "route -n get default | grep interface | awk '{print $2}'"
        } else {
            unimplemented!()
        };
        let ifname_output = Command::new("bash")
            .arg("-c")
            .arg(ifname_cmd)
            .output()
            .unwrap();
        if !ifname_output.status.success() {
            debug!("{}", String::from_utf8(ifname_output.stderr).unwrap());
            panic!("获取系统默认网关名称失败！");
        }
        let ifname = String::from_utf8(ifname_output.stdout)
            .unwrap()
            .trim_right()
            .to_string();

        // Get gateway mac addr.
        let arp_cmd = if cfg!(target_os = "linux") || cfg!(target_os = "macos") {
            format!("arp -a | grep \"{} \" | awk '{{print $4}}'", ipv4_addr)
        } else {
            unimplemented!()
        };

        let arp_output = Command::new("bash")
            .arg("-c")
            .arg(arp_cmd)
            .output()
            .unwrap();
        if !arp_output.status.success() {
            debug!("{}", String::from_utf8(arp_output.stderr).unwrap());
            panic!("获取系统默认网关硬件地址失败！");
        }
        let _ether_addr: String = String::from_utf8(arp_output.stdout)
            .unwrap()
            .trim_right()
            .to_string();
        let _ether_addr_temp = _ether_addr.split(':').collect::<Vec<&str>>();
        if _ether_addr_temp.len() != 6 {
            panic!("获取系统默认网关硬件地址失败！");
        }
        let ether_addr: [u8; 6] = [
            u8::from_str_radix(&_ether_addr_temp[0], 16).unwrap(),
            u8::from_str_radix(&_ether_addr_temp[1], 16).unwrap(),
            u8::from_str_radix(&_ether_addr_temp[2], 16).unwrap(),
            u8::from_str_radix(&_ether_addr_temp[3], 16).unwrap(),
            u8::from_str_radix(&_ether_addr_temp[4], 16).unwrap(),
            u8::from_str_radix(&_ether_addr_temp[5], 16).unwrap(),
        ];

        let system_gateway = SystemGateway {
            ifname: ifname,
            ipv4_addr: ipv4_addr.parse().unwrap(),
            ether_addr: ether_addr,
            current_gateway_addr: None,
        };
        Ok(system_gateway)
    }

    pub fn add_route(&self, route_type: &str, route: &str, gateway: &str) -> Result<(), String> {
        // route_type: -net || -host
        let output = if cfg!(target_os = "linux") {
            Command::new("route")
                .arg("-n")
                .arg("add")
                .arg(route_type)
                .arg(route)
                .arg("gw")
                .arg(gateway)
                .output()
                .expect(&format!(
                    "failed to execute `route -n add {} {} gw {}`",
                    route_type,
                    route,
                    gateway
                ))
        } else if cfg!(target_os = "macos") {
            Command::new("route")
                .arg("-n")
                .arg("add")
                .arg(route_type)
                .arg(route)
                .arg(gateway)
                .output()
                .expect(&format!(
                    "failed to execute `route -n add {} {} {}`",
                    route_type,
                    route,
                    gateway
                ))
        } else {
            unimplemented!()
        };

        if output.status.success() {
            Ok(())
        } else {
            Err(format!("route: {}", output.status))
        }
    }

    pub fn delete_route(&self, route_type: &str, route: &str) -> Result<(), String> {
        // route_type: -net || -host
        let output = if cfg!(target_os = "linux") {
            Command::new("route")
                .arg("-n")
                .arg("del")
                .arg(route_type)
                .arg(route)
                .output()
                .expect(&format!(
                    "failed to execute `route -n del {} {}`",
                    route_type,
                    route
                ))
        } else if cfg!(target_os = "macos") {
            Command::new("route")
                .arg("-n")
                .arg("delete")
                .arg(route_type)
                .arg(route)
                .output()
                .expect(&format!(
                    "failed to execute `route -n del {} {}`",
                    route_type,
                    route
                ))
        } else {
            unimplemented!()
        };
        if output.status.success() {
            Ok(())
        } else {
            Err(format!("route: {}", output.status))
        }
    }

    pub fn set_default(&mut self, gateway: &Ipv4Addr) -> Result<(), String> {
        self.delete_route("-net", "default").unwrap();
        self.current_gateway_addr = Some(gateway.clone());
        self.add_route("-host", "default", &gateway.to_string())
    }

    pub fn ifname(&self) -> &str {
        &self.ifname
    }
    pub fn ipv4_addr(&self) -> Ipv4Addr {
        self.ipv4_addr
    }

    pub fn mac_address(&self) -> MacAddr {
        MacAddr::new(
            self.ether_addr[0],
            self.ether_addr[1],
            self.ether_addr[2],
            self.ether_addr[3],
            self.ether_addr[4],
            self.ether_addr[5],
        )
    }
}

impl Drop for SystemGateway {
    fn drop(&mut self) {
        warn!("系统路由表已恢复！");
        if self.current_gateway_addr.is_some() {
            self.delete_route("-host", &self.current_gateway_addr.unwrap().to_string())
                .unwrap();
        }
        let addr = &self.ipv4_addr.clone();
        self.set_default(addr).unwrap();
    }
}

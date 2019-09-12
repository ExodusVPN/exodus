use sysctl::Mib;
use sysctl::Value;

use std::io;


#[cfg(any(target_os = "ios", target_os = "macos", target_os = "freebsd"))]
const IPV4_KEY: &str = "net.inet.ip.forwarding";
#[cfg(any(target_os = "ios", target_os = "macos", target_os = "freebsd"))]
const IPV6_KEY: &str = "net.inet6.ip6.forwarding";


#[cfg(any(target_os = "android", target_os = "linux"))]
const IPV4_KEY: &str = "net.ipv4.conf.all.forwarding"; // "net.ipv4.ip_forward"
#[cfg(any(target_os = "android", target_os = "linux"))]
const IPV6_KEY: &str = "net.ipv6.conf.all.forwarding";

const ZERO: Value = Value::I32(0);
const ONE: Value  = Value::I32(1);


#[inline]
fn get_value(key: &str) -> Result<Value, io::Error> {
    let mib = key.parse::<Mib>()?;
    mib.value()
}

#[inline]
fn set_value(key: &str, val: Value) -> Result<Value, io::Error> {
    let mib = key.parse::<Mib>()?;
    mib.set_value(val)
}

// Ipv4
#[inline]
pub fn ipv4_forwarding() -> Result<bool, io::Error> {
    let val = get_value(IPV4_KEY)?;
    Ok(val == ONE)
}

#[inline]
pub fn enable_ipv4_forwarding() -> Result<bool, io::Error> {
    let _ = set_value(IPV4_KEY, ONE)?;
    ipv4_forwarding()
}

#[inline]
pub fn disable_ipv4_forwarding() -> Result<bool, io::Error> {
    let _ = set_value(IPV4_KEY, ZERO)?;
    ipv4_forwarding()
}

// Ipv6
#[inline]
pub fn ipv6_forwarding() -> Result<bool, io::Error> {
    let val = get_value(IPV6_KEY)?;
    Ok(val == ONE)
}

#[inline]
pub fn enable_ipv6_forwarding() -> Result<bool, io::Error> {
    let _ = set_value(IPV6_KEY, ONE)?;
    ipv4_forwarding()
}

#[inline]
pub fn disable_ipv6_forwarding() -> Result<bool, io::Error> {
    let _ = set_value(IPV6_KEY, ZERO)?;
    ipv4_forwarding()
}

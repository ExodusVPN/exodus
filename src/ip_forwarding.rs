use sysctl;

use std::io;


#[cfg(any(target_os = "ios", target_os = "macos"))]
const IPV4_KEY: &str = "net.inet.ip.forwarding";
#[cfg(any(target_os = "ios", target_os = "macos"))]
const IPV6_KEY: &str = "net.inet6.ip.forwarding";

#[cfg(any(target_os = "android", target_os = "linux"))]
const IPV4_KEY: &str = "net.ipv4.ip_forward";
#[cfg(any(target_os = "android", target_os = "linux"))]
const IPV6_KEY: &str = "net.ipv6.ip_forward";


#[inline]
fn value_to_bool(value: sysctl::CtlValue) -> Result<bool, io::Error> {
    match value {
        sysctl::CtlValue::Int(n) => Ok(n == 1),
        sysctl::CtlValue::Uint(n) => Ok(n == 1),
        sysctl::CtlValue::Long(n) => Ok(n == 1),
        sysctl::CtlValue::Ulong(n) => Ok(n == 1),
        
        sysctl::CtlValue::U8(n) => Ok(n == 1),
        sysctl::CtlValue::U16(n) => Ok(n == 1),
        sysctl::CtlValue::U32(n) => Ok(n == 1),
        sysctl::CtlValue::U64(n) => Ok(n == 1),

        sysctl::CtlValue::S8(n) => Ok(n == 1),
        sysctl::CtlValue::S16(n) => Ok(n == 1),
        sysctl::CtlValue::S32(n) => Ok(n == 1),
        sysctl::CtlValue::S64(n) => Ok(n == 1),
        _ => Err(io::Error::from(io::ErrorKind::InvalidData)),
    }
}

#[inline]
pub fn ipv4_forwarding() -> Result<bool, io::Error> {
    sysctl::value(IPV4_KEY)
        .map(value_to_bool)
        .map_err(|_| io::Error::last_os_error())?
}

#[inline]
pub fn enable_ipv4_forwarding() -> Result<bool, io::Error> {
    sysctl::set_value(IPV4_KEY, sysctl::CtlValue::Int(1))
        .map(value_to_bool)
        .map_err(|_| io::Error::last_os_error())?
}

#[inline]
pub fn disable_ipv4_forwarding() -> Result<bool, io::Error> {
    sysctl::set_value(IPV4_KEY, sysctl::CtlValue::Int(0))
        .map(value_to_bool)
        .map_err(|_| io::Error::last_os_error())?
}

#[inline]
pub fn ipv6_forwarding() -> Result<bool, io::Error> {
    sysctl::value(IPV6_KEY)
        .map(value_to_bool)
        .map_err(|_| io::Error::last_os_error())?
}

#[inline]
pub fn enable_ipv6_forwarding() -> Result<bool, io::Error> {
    sysctl::set_value(IPV6_KEY, sysctl::CtlValue::Int(1))
        .map(value_to_bool)
        .map_err(|_| io::Error::last_os_error())?
}

#[inline]
pub fn disable_ipv6_forwarding() -> Result<bool, io::Error> {
    sysctl::set_value(IPV6_KEY, sysctl::CtlValue::Int(0))
        .map(value_to_bool)
        .map_err(|_| io::Error::last_os_error())?
}
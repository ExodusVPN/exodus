#![allow(dead_code)]

extern crate libc;
// extern crate errno;
#[macro_use]
extern crate ioctl_sys;

use std::os::unix::io::{AsRawFd, RawFd};

#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(dead_code)]
mod pfvar;
pub use pfvar::*;

pub const PF_DEV_PATH: &'static str = "/dev/pf";
pub const IOCTL_ERROR: i32 = -1;

// exports from <netinet/tcp.h>
pub const TH_FIN: ::std::os::raw::c_uint = 0x01;
pub const TH_SYN: ::std::os::raw::c_uint = 0x02;
pub const TH_RST: ::std::os::raw::c_uint = 0x04;
pub const TH_PSH: ::std::os::raw::c_uint = 0x08;
pub const TH_ACK: ::std::os::raw::c_uint = 0x10;
pub const TH_URG: ::std::os::raw::c_uint = 0x20;
pub const TH_ECE: ::std::os::raw::c_uint = 0x40;
pub const TH_CWR: ::std::os::raw::c_uint = 0x80;

#[allow(dead_code)]
extern {
    #[cfg_attr(any(target_os = "macos",
                   target_os = "ios",
                   target_os = "freebsd"),
                   link_name = "__error")]
    #[cfg_attr(target_os = "dragonfly",
                   link_name = "__dfly_error")]
    #[cfg_attr(any(target_os = "openbsd", target_os = "bitrig", target_os = "android"),
                   link_name = "__errno")]
    #[cfg_attr(target_os = "linux",
                   link_name = "__errno_location")]
    fn errno_location() -> *mut libc::c_int;

    #[cfg_attr(target_os = "linux", link_name = "__xpg_strerror_r")]
    fn strerror_r(errnum: libc::c_int, buf: *mut libc::c_char,
                  buflen: libc::size_t) -> libc::c_int;
}


// The definitions of the ioctl calls come from pfvar.h. Look for the comment "ioctl operations"
// The documentation describing the order of calls and accepted parameters can be found at:
// http://man.openbsd.org/pf.4
// DIOCSTART
ioctl!(none pf_start with b'D', 1);
// DIOCSTOP
ioctl!(none pf_stop with b'D', 2);
// DIOCADDRULE
ioctl!(readwrite pf_add_rule with b'D', 4; pfvar::pfioc_rule);
// DIOCGETRULES
ioctl!(readwrite pf_get_rules with b'D', 6; pfvar::pfioc_rule);
// DIOCGETRULE
ioctl!(readwrite pf_get_rule with b'D', 7; pfvar::pfioc_rule);
// DIOCGETSTATUS
ioctl!(readwrite pf_get_status with b'D', 21; pfvar::pf_status);
// DIOCGETSTATES
ioctl!(readwrite pf_get_states with b'D', 25; pfvar::pfioc_states);
// DIOCCHANGERULE
ioctl!(readwrite pf_change_rule with b'D', 26; pfvar::pfioc_rule);
// DIOCINSERTRULE
ioctl!(readwrite pf_insert_rule with b'D', 27; pfvar::pfioc_rule);
// DIOCDELETERULE
ioctl!(readwrite pf_delete_rule with b'D', 28; pfvar::pfioc_rule);
// DIOCKILLSTATES
ioctl!(readwrite pf_kill_states with b'D', 41; pfvar::pfioc_state_kill);
// DIOCBEGINADDRS
ioctl!(readwrite pf_begin_addrs with b'D', 51; pfvar::pfioc_pooladdr);
// DIOCADDADDR
ioctl!(readwrite pf_add_addr with b'D', 52; pfvar::pfioc_pooladdr);
// DIOCXBEGIN
ioctl!(readwrite pf_begin_trans with b'D', 81; pfvar::pfioc_trans);
// DIOCXCOMMIT
ioctl!(readwrite pf_commit_trans with b'D', 82; pfvar::pfioc_trans);


pub enum Rule {
    Filter(FilterRule),
    Redirect(RedirectRule)
}

pub struct FilterRule {

}

pub enum Address {
    Any,
    IP,
    IPNetwork,
    Interface
}

pub enum Action {
    // FilterRuleAction
    Pass,
    Drop,
    // RedirectRuleAction
    Redirect,
    NoRedirect,
}

pub enum Port {
    Any,
    Only(u32),
    Range(PortRange)
}
pub struct PortRange {
    start: u16,
    end  : u16,
    opt  : String,
}


pub struct RedirectRule {
    source      : Address,
    destination : Address,
    to          : Address,
    action      : Action
}

impl FilterRule {

}

pub struct Anchor {
    name: String
}

impl Anchor {
    pub fn add_rule(){

    }
    pub fn remove_rule(){

    }
    pub fn flush_rules(){

    }
}

/// Struct communicating with the PF firewall.
pub struct PfCtl {
    file: ::std::fs::File,
}

impl PfCtl {
    pub fn new() -> Result<Self, ::std::io::Error> {
        match ::std::fs::OpenOptions::new().read(true).write(true).open(PF_DEV_PATH) {
            Ok(file) => Ok(PfCtl {file: file}),
            Err(e) => match e.kind() {
                ::std::io::ErrorKind::PermissionDenied => {
                    println!("[WARN] 请使用 `sudo`  ...");
                    panic!(e);
                },
                _ => Err(e)
            }
        }
    }
    pub fn get_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    pub fn enable(&mut self) -> Result<(), ::std::io::Error> {
        let ret_code = unsafe { pf_start(self.get_raw_fd()) };
        if ret_code == -1 {
            let last_error = ::std::io::Error::last_os_error();
            if last_error.kind() == ::std::io::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                Err(last_error)
            }
        } else {
            Ok(())
        }
    }

    pub fn disable(&self) -> Result<(), ::std::io::Error> {
        let ret_code = unsafe { pf_stop(self.get_raw_fd()) };
        if ret_code == -1 {
            let last_error = ::std::io::Error::last_os_error();
            if last_error.kind() == ::std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(last_error)
            }
        } else {
            Ok(())
        }
    }

    pub fn add_anchor() {

    }

    pub fn remove_anchor() {

    }
}


fn main (){
    let mut pfctl = PfCtl::new().unwrap();
    println!("{:?}", pfctl.enable());
    println!("{:?}", pfctl.disable());
}
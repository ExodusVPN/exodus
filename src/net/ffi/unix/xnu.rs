#[macro_use]
extern crate ioctl_sys;


#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(dead_code)]
mod pfvar;
pub use pfvar::*;

// exports from <netinet/tcp.h>
pub const TH_FIN: ::std::os::raw::c_uint = 0x01;
pub const TH_SYN: ::std::os::raw::c_uint = 0x02;
pub const TH_RST: ::std::os::raw::c_uint = 0x04;
pub const TH_PSH: ::std::os::raw::c_uint = 0x08;
pub const TH_ACK: ::std::os::raw::c_uint = 0x10;
pub const TH_URG: ::std::os::raw::c_uint = 0x20;
pub const TH_ECE: ::std::os::raw::c_uint = 0x40;
pub const TH_CWR: ::std::os::raw::c_uint = 0x80;



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

extern crate errno;
extern crate libc;


pub const IOCTL_ERROR: i32 = -1;
/// Macro for taking an expression with an ioctl call, perform it and return a Rust ´Result´.
macro_rules! ioctl_guard {
    ($func:expr) => (ioctl_guard!($func, $crate::libc::EEXIST));
    ($func:expr, $already_active:expr) => {
        if unsafe { $func } == $crate::IOCTL_ERROR {
            let ::errno::Errno(error_code) = ::errno::errno();
            Err(::std::io::Error::from_raw_os_error(error_code))
            // Err(::std::io::Error::new(::std::io::ErrorKind::Other, "Oh, no ..."))
            // let mut err = Err($crate::ErrorKind::IoctlError(io_error).into());
            // if error_code == $already_active {
            //     err = err.chain_err(|| $crate::ErrorKind::StateAlreadyActive);
            // }
            // err
        } else {
            Ok(())
        }
    }
}

use std::os::unix::io::{AsRawFd, RawFd};
/// The path to the PF device file this library will use to communicate with PF.
const PF_DEV_PATH: &'static str = "/dev/pf";

/// Struct communicating with the PF firewall.
pub struct PfCtl {
    file: ::std::fs::File,
}

impl PfCtl {
    /// Returns a new `PfCtl` if opening the PF device file succeeded.
    pub fn new() -> Result<Self, ::std::io::Error> {
        match ::std::fs::OpenOptions::new().read(true).write(true).open(PF_DEV_PATH) {
            Ok(file) => Ok(PfCtl {file: file}),
            Err(e) => Err(e)
        }
    }
    pub fn get_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    pub fn enable(&mut self) -> Result<(), ::std::io::Error> {
        ioctl_guard!(pf_start(self.get_raw_fd()))
    }

}


fn main (){
    let mut pfctl = PfCtl::new().unwrap();
    let ret = pfctl.enable();
    println!("{:?}", ret);
}
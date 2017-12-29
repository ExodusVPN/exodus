#[cfg(any(target_os = "macos", target_os = "freebsd"))]

use libc;

pub const SIOCGIFMTU: libc::c_ulong = 0xc0206933;
pub const SIOCSIFMTU: libc::c_ulong = 0x80206934;
pub const SIOCGIFMETRIC: libc::c_ulong = 0xc0206917;
pub const SIOCSIFMETRIC: libc::c_ulong = 0x80206918;

pub const BIOCSETIF: libc::c_ulong = 0x8020426c;
pub const BIOCIMMEDIATE: libc::c_ulong = 0x80044270;
pub const BIOCGBLEN: libc::c_ulong = 0x40044266;
pub const BIOCGDLT: libc::c_ulong = 0x4004426a;
pub const BIOCSBLEN: libc::c_ulong = 0xc0044266;
pub const BIOCSHDRCMPLT: libc::c_ulong = 0x80044275;
pub const BIOCSRTIMEOUT: libc::c_ulong = 0x8010426d;
pub const BIOCSSEESENT: libc::c_ulong = 0x80044277;


#[cfg(all(target_os = "macos", target_pointer_width = "32"))]
pub type BPF_TIMEVAL = libc::timeval;
#[cfg(all(target_os = "macos", target_pointer_width = "64"))]
pub type BPF_TIMEVAL = libc::timeval32;
#[cfg(target_os = "freebsd")]
pub type BPF_TIMEVAL = libc::timeval;

pub fn BPF_WORDALIGN(x: isize) -> isize {
    let bpf_alignment = libc::BPF_ALIGNMENT as isize;
    (x + (bpf_alignment - 1)) & !(bpf_alignment - 1)
}


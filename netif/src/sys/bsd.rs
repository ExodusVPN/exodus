#[cfg(any(target_os = "macos", target_os = "freebsd"))]

use libc;

// macOS
pub const SIOCGIFMTU: libc::c_ulong = 0xc0206933;
pub const SIOCSIFMTU: libc::c_ulong = 0x80206934;
pub const SIOCGIFMETRIC: libc::c_ulong = 0xc0206917;
pub const SIOCSIFMETRIC: libc::c_ulong = 0x80206918;

pub const BIOCGDLT: libc::c_ulong = 1074020970;


#[cfg(target_pointer_width = "32")]
pub type BPF_TIMEVAL = libc::timeval32;
#[cfg(target_pointer_width = "64")]
pub type BPF_TIMEVAL = libc::timeval;


#[cfg(target_os = "freebsd")]
const BPF_ALIGNMENT: libc::c_int = ::std::mem::size_of::<libc::c_long>() as libc::c_int;
#[cfg(target_os = "macos")]
const BPF_ALIGNMENT: libc::c_int = ::std::mem::size_of::<libc::int32_t>() as libc::c_int;


#[repr(C)]
pub struct bpf_hdr {
    pub bh_tstamp: BPF_TIMEVAL,
    pub bh_caplen: libc::uint32_t,
    pub bh_datalen: libc::uint32_t,
    pub bh_hdrlen: libc::c_ushort,
}

impl ::std::fmt::Debug for bpf_hdr {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "bpf_hdr {{ bh_tstamp: timeval{} {{ tv_sec: {:?}, tv_usec: {:?} }}, bh_caplen: {:?}, bh_datalen: {:?}, bh_hdrlen: {:?} }}",
            if cfg!(target_pointer_width = "32") { "32" } else { "" },
            self.bh_tstamp.tv_sec,
            self.bh_tstamp.tv_usec,
            self.bh_caplen,
            self.bh_datalen,
            self.bh_hdrlen)
    }
}

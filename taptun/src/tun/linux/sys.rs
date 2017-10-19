use libc::{c_char, c_int, c_short, c_uchar, c_uint, c_ulong, c_ushort, c_void, sockaddr};

pub const IFNAMSIZ: usize = 16;

pub const IFF_UP: c_short = 0x1;
pub const IFF_RUNNING: c_short = 0x40;

pub const IFF_TUN: c_short = 0x0001;
pub const IFF_NO_PI: c_short = 0x1000;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifmap {
    pub mem_start: c_ulong,
    pub mem_end: c_ulong,
    pub base_addr: c_ushort,
    pub irq: c_uchar,
    pub dma: c_uchar,
    pub port: c_uchar,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct raw_hdlc_proto {
    pub encoding: c_ushort,
    pub parity: c_ushort,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct cisco_proto {
    pub interval: c_uint,
    pub timeout: c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct fr_proto {
    pub t391: c_uint,
    pub t392: c_uint,
    pub n391: c_uint,
    pub n392: c_uint,
    pub n393: c_uint,
    pub lmi: c_ushort,
    pub dce: c_ushort,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct fr_proto_pvc {
    pub dlci: c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct fr_proto_pvc_info {
    pub dlci: c_uint,
    pub master: [c_char; IFNAMSIZ],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sync_serial_settings {
    pub clock_rate: c_uint,
    pub clock_type: c_uint,
    pub loopback: c_ushort,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct te1_settings {
    pub clock_rate: c_uint,
    pub clock_type: c_uint,
    pub loopback: c_ushort,
    pub slot_map: c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union _ifs_ifsu {
    pub raw_hdlc: *mut raw_hdlc_proto,
    pub cisco: *mut cisco_proto,
    pub fr: *mut fr_proto,
    pub fr_pvc: *mut fr_proto_pvc,
    pub fr_pvc_info: *mut fr_proto_pvc_info,
    pub sync: *mut sync_serial_settings,
    pub te1: *mut te1_settings,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct if_settings {
    pub type_: c_uint,
    pub size: c_uint,
    pub ifs_ifsu: _ifs_ifsu,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union _ifr_ifrn {
    pub ifrn_name: [c_char; IFNAMSIZ],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union _ifr_ifru {
    pub ifru_addr: sockaddr,
    pub ifru_dstaddr: sockaddr,
    pub ifru_broadaddr: sockaddr,
    pub ifru_netmask: sockaddr,
    pub ifru_hwaddr: sockaddr,

    pub ifru_flags: c_short,
    pub ifru_ivalue: c_int,
    pub ifru_mtu: c_int,
    pub ifru_map: ifmap,
    pub ifru_slave: [c_char; IFNAMSIZ],
    pub ifru_newname: [c_char; IFNAMSIZ],
    pub data: *mut c_void,
    pub if_settings: if_settings,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifreq {
    pub ifr_ifrn: _ifr_ifrn,
    pub ifr_ifru: _ifr_ifru,
}

ioctl!(bad read siocgifflags with 0x8913; ifreq);
ioctl!(bad write siocsifflags with 0x8914; ifreq);

ioctl!(bad read siocgifaddr with 0x8915; ifreq);
ioctl!(bad write siocsifaddr with 0x8916; ifreq);

ioctl!(bad read siocgifdstaddr with 0x8917; ifreq);
ioctl!(bad write siocsifdstaddr with 0x8918; ifreq);

ioctl!(bad read siocgifbrdaddr with 0x8919; ifreq);
ioctl!(bad write siocsifbrdaddr with 0x891a; ifreq);

ioctl!(bad read siocgifnetmask with 0x891b; ifreq);
ioctl!(bad write siocsifnetmask with 0x891c; ifreq);

ioctl!(bad read siocgifmtu with 0x8921; ifreq);
ioctl!(bad write siocsifmtu with 0x8922; ifreq);

ioctl!(bad write siocsifname with 0x8923; ifreq);

ioctl!(write tunsetiff with b'T', 202; c_int);
ioctl!(write tunsetpersist with b'T', 203; c_int);
ioctl!(write tunsetowner with b'T', 204; c_int);
ioctl!(write tunsetgroup with b'T', 206; c_int);

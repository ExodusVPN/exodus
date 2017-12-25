// #![allow(non_camel_case_types, non_snake_case, dead_code)]

#![cfg(any(target_os = "macos", target_os = "freebsd"))]

extern crate libc;

use std::ffi::CString;
use std::io;


// macOS:
//     https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man4/bpf.4.html
// FreeBSD:
//     https://www.freebsd.org/cgi/man.cgi?query=bpf&sektion=9

pub const SIOCGIFMTU: libc::c_ulong = 0xc0206933;
pub const SIOCSIFMTU: libc::c_ulong = 0x80206934;
pub const SIOCGIFMETRIC: libc::c_ulong = 0xc0206917;
pub const SIOCSIFMETRIC: libc::c_ulong = 0x80206918;


const IOC_IN: libc::c_ulong = 0x80000000;
const IOC_OUT: libc::c_ulong = 0x40000000;
const IOC_INOUT: libc::c_ulong = IOC_IN | IOC_OUT;
const IOCPARM_SHIFT: libc::c_ulong = 13;
const IOCPARM_MASK: libc::c_ulong = (1 << (IOCPARM_SHIFT as usize)) - 1;

// FIXME: target_pointer_width
const SIZEOF_TIMEVAL: libc::c_ulong = 16;
const SIZEOF_IFREQ: libc::c_ulong = 32;
const SIZEOF_C_UINT: libc::c_ulong = 4;


pub const BIOCSETIF: libc::c_ulong =
    IOC_IN | ((SIZEOF_IFREQ & IOCPARM_MASK) << 16usize) | (('B' as libc::c_ulong) << 8usize) | 108;
pub const BIOCIMMEDIATE: libc::c_ulong =
    IOC_IN | ((SIZEOF_C_UINT & IOCPARM_MASK) << 16) | (('B' as libc::c_ulong) << 8) | 112;
pub const BIOCGBLEN: libc::c_ulong =
    IOC_OUT | ((SIZEOF_C_UINT & IOCPARM_MASK) << 16) | (('B' as libc::c_ulong) << 8) | 102;
pub const BIOCGDLT: libc::c_ulong =
    IOC_OUT | ((SIZEOF_C_UINT & IOCPARM_MASK) << 16) | (('B' as libc::c_ulong) << 8) | 106;

pub const BIOCSBLEN: libc::c_ulong =
    IOC_INOUT | ((SIZEOF_C_UINT & IOCPARM_MASK) << 16) | (('B' as libc::c_ulong) << 8) | 102;
pub const BIOCSHDRCMPLT: libc::c_ulong =
    IOC_IN | ((SIZEOF_C_UINT & IOCPARM_MASK) << 16) | (('B' as libc::c_ulong) << 8) | 117;
pub const BIOCSRTIMEOUT: libc::c_ulong =
    IOC_IN | ((SIZEOF_TIMEVAL & IOCPARM_MASK) << 16) | (('B' as libc::c_ulong) << 8) | 109;

#[cfg(target_os = "freebsd")]
pub const BIOCFEEDBACK: libc::c_ulong =
    IOC_IN | ((SIZEOF_C_UINT & IOCPARM_MASK) << 16) | (('B' as libc::c_ulong) << 8) | 124;

pub const BIOCSSEESENT: libc::c_ulong = 2147762807;


// Loopback
pub const DLT_NULL: libc::c_uint = 0;         // no link-layer encapsulation
pub const DLT_EN10MB: libc::c_uint = 1;       // Ethernet (10Mb)
pub const DLT_EN3MB: libc::c_uint = 2;        // Experimental Ethernet (3Mb)
pub const DLT_AX25: libc::c_uint = 3;         // Amateur Radio AX.25
pub const DLT_PRONET: libc::c_uint = 4;       // Proteon ProNET Token Ring
pub const DLT_CHAOS: libc::c_uint = 5;        // Chaos
pub const DLT_IEEE802: libc::c_uint = 6;      // IEEE 802 Networks
pub const DLT_ARCNET: libc::c_uint = 7;       // ARCNET
pub const DLT_SLIP: libc::c_uint = 8;         // Serial Line IP
pub const DLT_PPP: libc::c_uint = 9;          // Point-to-point Protocol
pub const DLT_FDDI: libc::c_uint = 10;        // FDDI
pub const DLT_ATM_RFC1483: libc::c_uint = 11; // LLC/SNAP encapsulated atm
pub const DLT_RAW: libc::c_uint = 12;         // raw IP
/*
 * OpenBSD DLT_LOOP, for loopback devices; it's like DLT_NULL, except
 * that the AF_ type in the link-layer header is in network byte order.
 *
 * OpenBSD defines it as 12, but that collides with DLT_RAW, so we
 * define it as 108 here.  If OpenBSD picks up this file, it should
 * define DLT_LOOP as 12 in its version, as per the comment above -
 * and should not use 108 for any purpose.
 */
pub const DLT_LOOP: libc::c_uint = 108;


#[allow(non_camel_case_types)]
#[cfg(target_pointer_width = "32")]
pub type BPF_TIMEVAL = libc::timeval32;
#[allow(non_camel_case_types)]
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


#[allow(non_snake_case)]
pub fn BPF_WORDALIGN(x: isize) -> isize {
    let bpf_alignment = BPF_ALIGNMENT as isize;
    (x + (bpf_alignment - 1)) & !(bpf_alignment - 1)
}


/**
DataLink Type:

macOS: https://github.com/apple/darwin-xnu/blob/master/bsd/net/bpf.h#L276

Linux: http://man7.org/linux/man-pages/man7/packet.7.html

Note:
    https://wiki.wireshark.org/SLL
    http://www.tcpdump.org/linktypes.html
**/
pub enum DataLink {
    Loopback,
    Ethernet,
    ExperimentalEthernet,
    Unknow(libc::c_uint)
}


#[derive(Debug)]
pub struct Bpf {
    fd: libc::c_int
}

impl Bpf {
    pub fn open() -> Result<Bpf, io::Error> {
        if cfg!(target_os = "macos") {
            for i in 0..10 {
                let filename = CString::new(format!("/dev/bpf{}", i)).unwrap();
                unsafe {
                    let fd = libc::open(filename.as_ptr(), libc::O_RDWR);
                    if fd != -1 {
                        return Ok(Bpf {fd: fd});
                    } else {
                        let err = io::Error::last_os_error();
                        match err.kind() {
                            io::ErrorKind::PermissionDenied => {
                                libc::close(fd);
                                return Err(err);
                            },
                            io::ErrorKind::NotFound => { },
                            _ => { }
                        }
                    }
                    libc::close(fd);
                }
            }
        } else if cfg!(target_os = "freebsd") {
            let filename = CString::new("/dev/bpf").unwrap();
            unsafe {
                let fd = libc::open(filename.as_ptr(), libc::O_RDWR);
                if fd != -1 {
                    return Ok(Bpf {fd: fd});
                } else {
                    libc::close(fd);
                    return Err(io::Error::last_os_error());
                }
            }
        } else {
            unreachable!()
        }
        
        return Err(io::Error::last_os_error());
    }

    pub fn bind(&self, ifname: &str) -> Result<(), io::Error> {
        #[repr(C)]
        struct ifreq {
            pub ifr_name: [libc::c_char; libc::IF_NAMESIZE],
            pub ifru_addr: libc::sockaddr,
        }

        let mut iface: ifreq = unsafe { ::std::mem::zeroed() };
        for (i, byte) in ifname.bytes().enumerate() {
            iface.ifr_name[i] = byte as libc::c_char;
        }

        unsafe {
            if libc::ioctl(self.fd, BIOCSETIF, &iface) == -1 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    pub fn prepare(&self) -> Result<(), io::Error>{
        let enable: libc::uint32_t = 1;
        
        unsafe {
            // Set header complete mode
            if libc::ioctl(self.fd, BIOCSHDRCMPLT, &enable) < 0 {
                return Err(io::Error::last_os_error());
            }

            // Monitor packets sent from our interface
            if libc::ioctl(self.fd, BIOCSSEESENT, &enable) < 0 {
                return Err(io::Error::last_os_error());
            }

            // Return immediately when a packet received
            if libc::ioctl(self.fd, BIOCIMMEDIATE, &enable) < 0 {
                return Err(io::Error::last_os_error());
            }

            // set the timeout
            let tv_timeout: BPF_TIMEVAL = BPF_TIMEVAL {
                tv_sec: 3,
                tv_usec: 0
            };
            if libc::ioctl(self.fd, BIOCSRTIMEOUT, &tv_timeout) == -1 {
                return Err(io::Error::last_os_error());
            }

            // Enable nonblocking
            // if libc::fcntl(self.fd, libc::F_SETFL, libc::O_NONBLOCK) == -1 {
            //     return Err(io::Error::last_os_error());
            // }

            // let mut fd_set: libc::fd_set = ::std::mem::zeroed();
            // libc::FD_ZERO(&mut fd_set as *mut libc::fd_set);
            // libc::FD_SET(self.fd, &mut fd_set as *mut libc::fd_set);
        }
        Ok(())
    }

    pub fn datalink_type(&self) -> Result<libc::uint32_t, io::Error> {
        let dlt: libc::uint32_t = 0;
        // Ensure we are dumping the datalink we expect
        unsafe {
            if libc::ioctl(self.fd, BIOCGDLT, &dlt) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(dlt)
    }

    pub fn blen(&self) -> Result<usize, io::Error> {
        let blen: libc::size_t = 0;
        unsafe {
            if libc::ioctl(self.fd, BIOCGBLEN, &blen) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(blen)
    }

    pub fn read(&mut self) {
        const SIZE: usize = 4096;
        // let size = self.blen().unwrap();
        let mut buf: [u8; SIZE] = [0u8; 4096];
        // println!("{:?}", size);
        unsafe {
            let len = libc::read(self.fd, ::std::mem::transmute(buf.as_mut_ptr() as *mut libc::c_void), SIZE);
            if len < 0 {
                println!("[ERROR] {:?}", io::Error::last_os_error());
            } else if len > 0 {
                println!("{:?}", &buf[0..len as usize]);
            } else {
                // PASS
            }
        }
        
    }
}

impl Drop for Bpf {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}



fn main(){
    let mut bpf = Bpf::open().unwrap();
    bpf.bind("en0").unwrap();
    bpf.prepare().unwrap();

    if bpf.datalink_type().unwrap() == DLT_EN10MB {
        // ethernet
        loop {
            bpf.read();
        }
    } else {
        // unknow net packet
        // PASS
    }
    
}
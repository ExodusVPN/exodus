#![allow(non_camel_case_types, non_snake_case, dead_code)]

#![cfg(any(target_os = "macos", target_os = "freebsd"))]

extern crate libc;
extern crate smoltcp;

use smoltcp::wire::{ PrettyPrinter, EthernetFrame };


use std::ffi::CString;
use std::io;
use std::mem;


// macOS:
//     https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man4/bpf.4.html
//     https://github.com/apple/darwin-xnu/blob/master/bsd/net/bpf.h#L154
// FreeBSD:
//     https://www.freebsd.org/cgi/man.cgi?query=bpf&sektion=9
// 
// Using FreeBSD's BPF device with C/C++
//      http://bastian.rieck.ru/howtos/bpf/#index4h1

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

#[cfg(target_os = "freebsd")]
pub const BIOCFEEDBACK: libc::c_ulong = 0x8004427c;

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
pub const DLT_LOOP: libc::c_uint = 108;



#[cfg(all(target_os = "macos", target_pointer_width = "32"))]
pub type BPF_TIMEVAL = libc::timeval;
#[cfg(all(target_os = "macos", target_pointer_width = "64"))]
pub type BPF_TIMEVAL = libc::timeval32;
#[cfg(target_os = "freebsd")]
pub type BPF_TIMEVAL = libc::timeval;

#[cfg(target_os = "freebsd")]
pub const BPF_ALIGNMENT: libc::c_int = mem::size_of::<libc::c_long>() as libc::c_int;
#[cfg(target_os = "macos")]
pub const BPF_ALIGNMENT: libc::c_int = mem::size_of::<libc::int32_t>() as libc::c_int;

#[repr(C)]
pub struct bpf_hdr {
    pub bh_tstamp: BPF_TIMEVAL,
    pub bh_caplen: libc::uint32_t,
    pub bh_datalen: libc::uint32_t,
    pub bh_hdrlen: libc::c_ushort,
}

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
    #[cfg(target_os = "macos")]
    pub fn open() -> Result<Bpf, io::Error> {
        for i in 0..50 {
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
        return Err(io::Error::last_os_error());
    }

    #[cfg(target_os = "freebsd")]
    pub fn open() -> Result<Bpf, io::Error> {
        let filename = CString::new("/dev/bpf").unwrap();
        unsafe {
            let fd = libc::open(filename.as_ptr(), libc::O_RDWR);
            if fd != -1 {
                Ok(Bpf {fd: fd})
            } else {
                libc::close(fd);
                Err(io::Error::last_os_error())
            }
        }
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

    pub fn read(&mut self, buf: &mut [u8], blen: usize) {
        let buf_ptr = buf.as_mut_ptr();
        unsafe {
            let len = libc::read(
                            self.fd,
                            buf_ptr as *mut libc::c_void,
                            blen);
            if len < 0 {
                println!("[ERROR] {:?}", io::Error::last_os_error());
                return ();
            } 
            if len == 0 {
                return ();
            }

            // 20 (c),  kernel(18)
            // https://github.com/apple/darwin-xnu/blob/master/bsd/net/bpf.h#L231
            let bpf_hdr_size = mem::size_of::<bpf_hdr>();

            let mut start = 0usize;
            loop {
                if start >= len as usize {
                    break;
                }
                let bpf_buf = &buf[start..start+bpf_hdr_size];
                let bpf_packet: *const bpf_hdr = bpf_buf.as_ptr() as *const _;
                let bh_hdrlen = (*bpf_packet).bh_hdrlen as usize;
                let bh_datalen = (*bpf_packet).bh_datalen as usize;

                let data = &buf[start+bh_hdrlen..start+bh_hdrlen+bh_datalen];
                match EthernetFrame::new_checked(&data) {
                    Ok(frame) => {
                        match frame.check_len() {
                            Ok(_) => {
                                println!("{}", 
                                    &PrettyPrinter::<EthernetFrame<&[u8]>>::new("", &frame.into_inner()));
                            }
                            Err(_) => { }
                        }
                    },
                    Err(_) => {}
                }
                start += bh_datalen + bh_hdrlen;
            }
        }
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize, io::Error> {
        let ptr = buf.as_ptr();
        let size = buf.len();
        let ret = unsafe {
                    libc::write(
                            self.fd,
                            ptr as *mut libc::c_void,
                            size)
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(size)
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
    let interface_name = "en0";
    let mut bpf = Bpf::open().unwrap();
    bpf.bind(interface_name).unwrap();
    bpf.prepare().unwrap();

    match bpf.datalink_type() {
        Ok(datalink_type) => match datalink_type {
            DLT_EN10MB => {
                let blen = bpf.blen().unwrap();
                let mut read_buffer: Vec<u8> = vec![0u8; blen];
                loop {
                    bpf.read(&mut read_buffer, blen);
                }
            }
            _ => {}
        }
        Err(e) => {
            println!("{:?}", e);
        }
    }
}
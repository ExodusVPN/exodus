#![cfg(any(target_os = "macos", target_os = "freebsd", target_os = "linux"))]

use sys;

use std::io;
use std::mem;
use std::ptr;
use std::ffi::CString;
use std::time::Duration;
use std::os::unix::io::RawFd;
use std::os::unix::io::AsRawFd;


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkLayer {
    Null,
    Eth,
    Ip,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawSocket {
    fd: sys::c_int,
    dt: LinkLayer,
    blen: usize,
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    len: usize,
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    start: Option<usize>
}

#[cfg(target_os = "linux")]
impl RawSocket {
    pub fn open(ifname: &str) -> Result<RawSocket, io::Error> {
        let flags = sys::if_name_to_flags(ifname).unwrap();
        let link_layer = 
            if flags & sys::IFF_LOOPBACK != 0 {
                // Loopback: IFF_UP | IFF_LOOPBACK | IFF_RUNNING
                // LinkLayer::Loopback
                LinkLayer::Eth
            } else if flags & sys::IFF_BROADCAST != 0 {
                // TAP: IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST
                LinkLayer::Eth
            } else if flags & sys::IFF_POINTOPOINT != 0 {
                // TUN: POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP
                LinkLayer::Ip
            } else {
                // unknow interface
                return Err(io::Error::new(io::ErrorKind::Other, "link layer unknow"))
            };

        let protocol = match link_layer {
            // LinkLayer::Loopback => (sys::ETH_P_LOOP as u16).to_be(),
            LinkLayer::Eth | LinkLayer::Ip => (sys::ETH_P_ALL as u16).to_be(),
            // LinkLayer::Ip => (sys::ETH_P_IP as u16).to_be(),
            _ => return Err(io::Error::new(io::ErrorKind::Other, "link layer unknow"))
        };

        // let protocol = (sys::ETH_P_ALL as u16).to_be();
        let fd = unsafe {
            sys::socket(sys::AF_PACKET, sys::SOCK_RAW | sys::SOCK_NONBLOCK, protocol as i32)
        };

        if fd == -1 {
            return Err(io::Error::last_os_error())
        }
        
        let ifindex = sys::if_name_to_index(ifname);

        let sll = sys::sockaddr_ll {
            sll_family:   sys::AF_PACKET as u16,
            sll_protocol: protocol as u16,
            sll_ifindex:  ifindex as i32,
            sll_hatype:   1,
            sll_pkttype:  0,
            sll_halen:    6,
            sll_addr:     [0; 8]
        };
        
        let sa = &sll as *const sys::sockaddr_ll as *const sys::sockaddr;
        let ret = unsafe { sys::bind(fd, sa, mem::size_of::<sys::sockaddr_ll>() as u32) };

        if ret == -1 {
            unsafe { sys::close(fd) };
            return Err(io::Error::last_os_error())
        }
        
        let mtu = sys::if_name_to_mtu(ifname).unwrap();


        Ok(RawSocket { fd: fd, dt: link_layer, blen: mtu })

    }

    pub fn link_layer(&self) -> LinkLayer {
        // https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_ether.h#L46
        // http://man7.org/linux/man-pages/man7/packet.7.html
        // ETH_P_ALL   0x0003
        // ETH_P_LOOP  0x0060
        // ETH_P_IP    0x0800
        // ETH_P_ARP   0x0806
        self.dt
    }

    pub fn blen(&self) -> usize {
        self.blen
    }

    pub fn recv(&mut self, buffer: &mut [u8]) -> Result<usize, io::Error> {
        let len = unsafe {
            sys::recv(self.fd, 
                      buffer.as_mut_ptr() as *mut sys::c_void,
                      buffer.len(), 0)
        };
        
        if len == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(len as usize)
        }
    }

    pub fn send(&mut self, buffer: &[u8]) -> Result<usize, io::Error> {
        let len = unsafe {
            sys::send(self.fd,
                      buffer.as_ptr() as *const sys::c_void,
                      buffer.len(),
                      0)
        };

        if len == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(len as usize)
        }
    }

    pub fn await(&self, millis: Option<u64>) -> Result<(), io::Error> {
        unsafe {
            let mut readfds = mem::uninitialized::<sys::fd_set>();
            sys::FD_ZERO(&mut readfds);
            sys::FD_SET(self.fd, &mut readfds);

            let mut writefds = mem::uninitialized::<sys::fd_set>();
            sys::FD_ZERO(&mut writefds);

            let mut exceptfds = mem::uninitialized::<sys::fd_set>();
            sys::FD_ZERO(&mut exceptfds);

            let mut timeout = sys::timeval { tv_sec: 0, tv_usec: 0 };
            let timeout_ptr =
                if let Some(millis) = millis {
                    timeout.tv_usec = (millis * 1_000) as sys::suseconds_t;
                    &mut timeout as *mut _
                } else {
                    ptr::null_mut()
                };

            let res = sys::select(self.fd + 1, &mut readfds, &mut writefds, &mut exceptfds, timeout_ptr);
            if res == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
}


#[cfg(any(target_os = "macos", target_os = "freebsd"))]
impl RawSocket {
    #[cfg(target_os = "macos")]
    pub fn open_bpf() -> Result<sys::c_int, io::Error> {
        for i in 0..50 {
            let filename = CString::new(format!("/dev/bpf{}", i)).unwrap();
            let fd = unsafe { sys::open(filename.as_ptr(), sys::O_RDWR) };
            if fd < 0 {
                let err = io::Error::last_os_error();
                match err.kind() {
                    io::ErrorKind::PermissionDenied => {
                        unsafe { sys::close(fd) };
                        return Err(err);
                    },
                    io::ErrorKind::NotFound => { },
                    _ => { }
                }
            } else {
                return Ok(fd);
            }
            unsafe { sys::close(fd) };
        }
        Err(io::Error::last_os_error())
    }

    #[cfg(target_os = "freebsd")]
    pub fn open_bpf() -> Result<sys::c_int, io::Error> {
        let filename = CString::new("/dev/bpf").unwrap();
        let fd = unsafe { sys::open(filename.as_ptr(), sys::O_RDWR) };
        if fd < 0 {
            unsafe { sys::close(fd) };
            Err(io::Error::last_os_error())
        } else {
            Ok(fd)
        }
    }

    fn set_option(fd: sys::c_int, option: sys::c_ulong, value: sys::uint32_t) -> Result<(), io::Error>{
        let ret = unsafe { sys::ioctl(fd, option, &value) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn set_timeout(fd: sys::c_int, duration: Duration) -> Result<(), io::Error> {
        let tv_timeout = sys::BPF_TIMEVAL {
            tv_sec: duration.as_secs() as sys::BPF_TIMEVAL_SEC_T,
            tv_usec: 0
        };

        let ret = unsafe { sys::ioctl(fd, sys::BIOCSRTIMEOUT, &tv_timeout) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn get_link_layer(fd: sys::c_int) -> Result<sys::uint32_t, io::Error> {
        let dlt: sys::uint32_t = 0;

        let ret = unsafe { sys::ioctl(fd, sys::BIOCGDLT, &dlt) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(dlt)
        }
    }

    fn set_link_layer(fd: sys::c_int, dlt: sys::uint32_t) -> Result<(), io::Error> {
        let ret = unsafe { sys::ioctl(fd, sys::BIOCSDLT, &dlt) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn get_blen(fd: sys::c_int) -> Result<usize, io::Error> {
        let blen: sys::size_t = 0;

        let ret = unsafe { sys::ioctl(fd, sys::BIOCGBLEN, &blen) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(blen)
        }
    }

    pub fn open(ifname: &str) -> Result<RawSocket, io::Error> {
        match RawSocket::open_bpf() {
            Ok(bpf_fd) => {
                // Set header complete mode
                RawSocket::set_option(bpf_fd, sys::BIOCSHDRCMPLT, 1).unwrap();
                // Monitor packets sent from our interface
                RawSocket::set_option(bpf_fd, sys::BIOCSSEESENT, 1).unwrap();
                // Return immediately when a packet received
                RawSocket::set_option(bpf_fd, sys::BIOCIMMEDIATE, 1).unwrap();
                // Set buffer length ( 100 KB )
                RawSocket::set_option(bpf_fd, sys::BIOCSBLEN, 1024*100).unwrap();
                // set the timeout
                RawSocket::set_timeout(bpf_fd, Duration::from_secs(3)).unwrap();
                // bind to netif
                #[repr(C)]
                struct ifreq {
                    pub ifr_name: [sys::c_char; sys::IF_NAMESIZE],
                    pub ifru_addr: sys::sockaddr,
                }

                let mut iface: ifreq = unsafe { mem::zeroed() };
                for (i, byte) in ifname.bytes().enumerate() {
                    iface.ifr_name[i] = byte as sys::c_char;
                }

                if unsafe { sys::ioctl(bpf_fd, sys::BIOCSETIF, &iface) } < 0 {
                    return Err(io::Error::last_os_error());
                }
                
                // match RawSocket::get_link_layer(bpf_fd).unwrap() {
                //     // loopback or utun
                //     // Change Link-Layer type.
                //     sys::DLT_NULL => RawSocket::set_link_layer(bpf_fd, sys::DLT_RAW).unwrap(),
                //     // Ethernet frame
                //     sys::DLT_EN10MB => { },
                //     // IPv4/IPv6
                //     sys::DLT_RAW => { },
                //     // unsupport link layer
                //     _ => return Err(io::Error::new(io::ErrorKind::Other, "unsupport datalink layer"))
                // };
                
                let link_layer = match RawSocket::get_link_layer(bpf_fd).unwrap() {
                    sys::DLT_NULL => LinkLayer::Null,
                    sys::DLT_EN10MB => LinkLayer::Eth,
                    sys::DLT_RAW => LinkLayer::Ip,
                    _ => return Err(io::Error::new(io::ErrorKind::Other, "set datalink layer failure."))
                };
                let blen = RawSocket::get_blen(bpf_fd).unwrap();
                Ok(RawSocket { fd: bpf_fd, dt: link_layer, blen: blen, len: 0, start: None })
            },
            Err(e) => Err(e)
        }
    }

    pub fn link_layer(&self) -> LinkLayer {
        // https://github.com/apple/darwin-xnu/blob/master/bsd/net/bpf.h#L276
        self.dt
    }

    pub fn blen(&self) -> usize {
        self.blen
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<Option<(usize, usize)>, io::Error> {
        let buf_ptr = buf.as_mut_ptr();
        match self.start {
            None => {
                let len = unsafe { sys::read(self.fd, buf_ptr as *mut sys::c_void, self.blen) };
                if len < 0 {
                    return Err(io::Error::last_os_error());
                } else if len == 0 {
                    return Ok(None);
                } else {
                    self.len = len as usize;
                    self.start = Some(0);
                    return Ok(None);
                }
            },
            Some(start) => {
                // c (20), kernel (18)
                // https://github.com/apple/darwin-xnu/blob/master/bsd/net/bpf.h#L231
                let bpf_hdr_size = mem::size_of::<sys::bpf_hdr>();

                let len = self.len;
                if start >= len  {
                    self.len = 0;
                    self.start = None;
                    return Ok(None);
                } else {
                    let bpf_buf = &buf[start..start+bpf_hdr_size];
                    let bpf_packet = bpf_buf.as_ptr() as *const sys::bpf_hdr;
                    let bh_hdrlen = unsafe { (*bpf_packet).bh_hdrlen } as usize ;
                    let bh_datalen = unsafe { (*bpf_packet).bh_datalen } as usize;
                    
                    if bh_datalen + bh_hdrlen > len as usize {
                        self.len = 0;
                        self.start = None;
                        return Ok(None);
                    } else {
                        self.start = Some(start + sys::BPF_WORDALIGN((bh_datalen + bh_hdrlen) as isize) as usize);
                        let packet_pos = (start+bh_hdrlen, start+bh_hdrlen+bh_datalen);
                        return Ok(Some(packet_pos));
                    }
                }
            }
        }
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize, io::Error> {
        let ptr = buf.as_ptr();
        let size = buf.len();
        
        let ret = unsafe { sys::write(self.fd, ptr as *mut sys::c_void, size) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(size)
        }
    }
}

impl AsRawFd for RawSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        unsafe { sys::close(self.fd) };
    }
}

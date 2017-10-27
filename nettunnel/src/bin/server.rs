#![allow(unused_imports, dead_code, unused_mut, unused_must_use, unused_variables)]

extern crate taptun;
extern crate netpacket;
extern crate crypto;

extern crate futures;

#[macro_use(try_nb)]
extern crate tokio_core;
extern crate tokio_io;
extern crate byteorder;

#[allow(unused_imports)]
#[macro_use(trace, debug, info, warn, error, log)]
extern crate logging;



use std::fmt;
use std::convert::AsMut;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use tokio_core::net::{TcpStream, TcpListener};
use tokio_io::io::{read_exact, read_to_end, read, write_all, Window, copy};

use futures::stream;
use futures::future;
use futures::{Future, Stream, Poll, Async};
use byteorder::{BigEndian, ReadBytesExt, ByteOrder};

use taptun::tun;


/**
    sudo route add 10.0.0.1/24 -interface utun10
    curl "10.0.0.50:80"
    ping 10.0.0.50
    ping 10.0.0.1
    
    sudo route get default
    sudo route delete default
    sudo route add default -interface utun10
    netstat -nr
**/

pub struct Packet([u8; 1500]);

impl AsMut<[u8]> for Packet{
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[{}]", self.0.iter().map(|n| n.to_string() ).collect::<Vec<String>>().join(", "))
    }
}


#[derive(Debug, PartialEq, Eq)]
pub enum Method {
    GetPeers,
    Transfer
}




use std::sync::{Arc, Mutex};
use std::cell::Cell;
use std::cell::RefCell;
use std::rc::Rc;
use std::borrow::BorrowMut;
use std::borrow::Borrow;
use std::cell::RefMut;
use std::thread;

use ::futures::sync::oneshot;
use std::collections::HashMap;

pub struct Vpn<'a, 'b> {
    registry : Arc<Mutex<HashMap<u32, TcpStream>>>,
    best_ip  : Arc<Mutex<u32>>,
    iface_hub_sender  : futures::sync::oneshot::Sender<&'a [u8]>,
    iface_hub_receiver: futures::sync::oneshot::Receiver<&'b [u8]>
}

impl<'a, 'b> Vpn<'a, 'b> {
    pub fn new() -> Result<Vpn<'a, 'b>, ::std::io::Error> {
        
        let registry: Arc<Mutex<HashMap<u32, TcpStream>>> = Arc::new(Mutex::new(HashMap::new()));
        let best_ip = Arc::new(Mutex::new(u32::from(Ipv4Addr::new(10, 0, 0, 10))));

        let (sender, receiver) = oneshot::channel::<&[u8]>();

        Ok(Vpn {
            registry: registry,
            best_ip : best_ip,
            iface_hub_sender  : unsafe { ::std::mem::transmute(sender) },
            iface_hub_receiver: unsafe { ::std::mem::transmute(receiver) }
        })
    }

    pub fn ip_gen(&self) -> Option<Ipv4Addr> {
        let mut best_ip_clone = self.best_ip.lock().unwrap();
        *best_ip_clone += 1;
        Some(Ipv4Addr::from(*best_ip_clone))
    }

    pub fn add_peer(&mut self, peer: TcpStream, ipv4_addr: ::std::net::Ipv4Addr) -> bool {
        let peer_id = u32::from(ipv4_addr);
        let mut registry = self.registry.lock().unwrap();

        registry.insert(peer_id, peer).is_none()
    }
}

fn on_connection(handle: tokio_core::reactor::Handle,
                stream : TcpStream, 
                addr   : ::std::net::SocketAddr,
                device_clone: Arc<Mutex<tun::Device>>) 
                            -> Box<future::Future<Item=(), Error=()>> {
        Box::new(read_exact(stream, [0u8; 4])
            .and_then(|(stream, buf)|{
                let size = BigEndian::read_u16(&buf);

                info!("size: {:?}  ", size);
                read(stream, vec![0u8; size as usize]).and_then(move |(stream, data, size)|{
                    info!("buf: {:?}", &buf[..2]);
                    info!("packet: {:?}  ", &data[..size]);
                    let mut device = device_clone.lock().unwrap();
                    device.write(&data[..size]);
                    future::ok(())
                })
            })
            .or_else(|_| {
                future::err(())
            }))
    }


fn main () {
    logging::init(Some("info")).unwrap();

    let mut lp = tokio_core::reactor::Core::new().unwrap();
    let handle = lp.handle();

    let addr = "127.0.0.1:9000".parse::<::std::net::SocketAddr>().unwrap();
    let listener: TcpListener = TcpListener::bind(&addr, &handle).unwrap();
    info!("Server will running on {:?} ...", addr);

    let mut vpn = Vpn::new().unwrap();
    let fut1 = listener.incoming()
        .and_then(move |(stream, addr)| {
            let ip = vpn.ip_gen().unwrap();
            vpn.add_peer(stream, ip);
            let registry = vpn.registry.lock().unwrap();
            warn!("Registry Keys: {:?}", registry.keys());
            future::ok(())
        })
        .or_else(|_| future::err(()))
        .for_each(|a| Ok(()));

    lp.handle().spawn(fut1);


    let mut config = tun::Configuration::default();
        config.address(Ipv4Addr::new(10, 0, 0, 1))
               .netmask(Ipv4Addr::new(255, 255, 255, 0))
               .destination(Ipv4Addr::new(0, 0, 0, 0))
               .mtu(1500)
               .name("utun10")
               .up();
        
    let dev_res = tun::create(&config);
    if dev_res.is_err() {
        error!("虚拟网络设备创建失败: {:?}", dev_res);
        // return Err(::std::io::Error::new(::std::io::ErrorKind::Other, "Oh, no ...."));
        return ();
    }

    // let mut tokio_device = tun::tokio::Device::new(dev_res.unwrap(), &handle.clone()).unwrap();
    let mut device = dev_res.unwrap();
    let mut buf = [0u8; 1500];

    thread::spawn(move || {
        loop {
            match device.read(&mut buf) {
                Ok(size) => {
                    info!("Read: {:?} ", &buf[..size]);
                },
                Err(e) => {
                    error!("{:?}", e);
                }
            };
        }
    });

    thread::spawn(move ||{

    });


    loop {
        lp.turn(None);
    }
}
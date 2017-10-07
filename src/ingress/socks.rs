
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate futures;
#[macro_use]
extern crate tokio_core;
extern crate tokio_io;
extern crate trust_dns;

use std::cell::RefCell;
use std::env;
use std::io::{self, Read, Write};
use std::net::{Shutdown, IpAddr};
use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::rc::Rc;
use std::str;
use std::time::Duration;

use futures::future;
use futures::{Future, Stream, Poll, Async};
use tokio_io::io::{read_exact, write_all, Window};
use tokio_core::net::{TcpStream, TcpListener};
use tokio_core::reactor::{Core, Handle, Timeout};
use trust_dns::client::{ClientFuture, BasicClientHandle, ClientHandle};
use trust_dns::op::{Message, ResponseCode};
use trust_dns::rr::{DNSClass, Name, RData, RecordType};
use trust_dns::udp::UdpClientStream;

fn main() {
    drop(env_logger::init());

    // Take the first command line argument as an address to listen on, or fall
    // back to just some localhost default.
    let addr = env::args().nth(1).unwrap_or("127.0.0.1:8080".to_string());
    let addr = addr.parse::<SocketAddr>().unwrap();

    // Initialize the various data structures we're going to use in our server.
    // Here we create the event loop, the global buffer that all threads will
    // read/write into, and the bound TCP listener itself.
    let mut lp = Core::new().unwrap();
    let buffer = Rc::new(RefCell::new(vec![0; 64 * 1024]));
    let handle = lp.handle();
    let listener = TcpListener::bind(&addr, &handle).unwrap();

    // This is the address of the DNS server we'll send queries to. If
    // external servers can't be used in your environment, you can substitue
    // your own.
    let dns = "8.8.8.8:53".parse().unwrap();
    let (stream, sender) = UdpClientStream::new(dns, handle.clone());
    let client = ClientFuture::new(stream, sender, handle.clone(), None);

    // Construct a future representing our server. This future processes all
    // incoming connections and spawns a new task for each client which will do
    // the proxy work.
    //
    // This essentially means that for all incoming connections, those received
    // from `listener`, we'll create an instance of `Client` and convert it to a
    // future representing the completion of handling that client. This future
    // itself is then *spawned* onto the event loop to ensure that it can
    // progress concurrently with all other connections.
    println!("Listening for socks5 proxy connections on {}", addr);
    let clients = listener.incoming().map(move |(socket, addr)| {
        (Client {
            buffer: buffer.clone(),
            dns: client.clone(),
            handle: handle.clone(),
        }.serve(socket), addr)
    });
    let handle = lp.handle();
    let server = clients.for_each(|(client, addr)| {
        handle.spawn(client.then(move |res| {
            match res {
                Ok((a, b)) => {
                    println!("proxied {}/{} bytes for {}", a, b, addr)
                }
                Err(e) => println!("error for {}: {}", addr, e),
            }
            future::ok(())
        }));
        Ok(())
    });

    // Now that we've got our server as a future ready to go, let's run it!
    //
    // This `run` method will return the resolution of the future itself, but
    // our `server` futures will resolve to `io::Result<()>`, so we just want to
    // assert that it didn't hit an error.
    lp.run(server).unwrap();
}

// Data used to when processing a client to perform various operations over its
// lifetime.
struct Client {
    buffer: Rc<RefCell<Vec<u8>>>,
    dns: BasicClientHandle,
    handle: Handle,
}

impl Client {
    fn serve(self, conn: TcpStream)
              -> Box<Future<Item=(u64, u64), Error=io::Error>> {
        Box::new(read_exact(conn, [0u8]).and_then(|(conn, buf)| {
            match buf[0] {
                v5::VERSION => self.serve_v5(conn),
                v4::VERSION => self.serve_v4(conn),

                // If we hit an unknown version, we return a "terminal future"
                // which represents that this future has immediately failed. In
                // this case the type of the future is `io::Error`, so we use a
                // helper function, `other`, to create an error quickly.
                _ => ::std::boxed::Box::new(future::err(other("unknown version"))),
            }
        }))
    }

    /// Current SOCKSv4 is not implemented, but v5 below has more fun details!
    fn serve_v4(self, _conn: TcpStream)
                -> Box<Future<Item=(u64, u64), Error=io::Error>> {
        ::std::boxed::Box::new(future::err(other("unimplemented")))
    }
    fn serve_v5(self, conn: TcpStream)
                -> Box<Future<Item=(u64, u64), Error=io::Error>> {
        let num_methods = read_exact(conn, [0u8]);
        let authenticated = ::std::boxed::Box::new(num_methods.and_then(|(conn, buf)| {
            read_exact(conn, vec![0u8; buf[0] as usize])
        }).and_then(|(conn, buf)| {
            if buf.contains(&v5::METH_NO_AUTH) {
                Ok(conn)
            } else {
                Err(other("no supported method given"))
            }
        }));

        // After we've concluded that one of the client's supported methods is
        // `METH_NO_AUTH`, we "ack" this to the client by sending back that
        // information. Here we make use of the `write_all` combinator which
        // works very similarly to the `read_exact` combinator.
        let part1 = ::std::boxed::Box::new(authenticated.and_then(|conn| {
            write_all(conn, [v5::VERSION, v5::METH_NO_AUTH])
        }));

        // Next up, we get a selected protocol version back from the client, as
        // well as a command indicating what they'd like to do. We just verify
        // that the version is still v5, and then we only implement the
        // "connect" command so we ensure the proxy sends that.
        //
        // As above, we're using `and_then` not only for chaining "blocking
        // computations", but also to perform fallible computations.
        let ack = ::std::boxed::Box::new(part1.and_then(|(conn, _)| {
            read_exact(conn, [0u8]).and_then(|(conn, buf)| {
                if buf[0] == v5::VERSION {
                    Ok(conn)
                } else {
                    Err(other("didn't confirm with v5 version"))
                }
            })
        }));
        let command = ::std::boxed::Box::new(ack.and_then(|conn| {
            read_exact(conn, [0u8]).and_then(|(conn, buf)| {
                if buf[0] == v5::CMD_CONNECT {
                    Ok(conn)
                } else {
                    Err(other("unsupported command"))
                }
            })
        }));

        // After we've negotiated a command, there's one byte which is reserved
        // for future use, so we read it and discard it. The next part of the
        // protocol is to read off the address that we're going to proxy to.
        // This address can come in a number of forms, so we read off a byte
        // which indicates the address type (ATYP).
        //
        // Depending on the address type, we then delegate to different futures
        // to implement that particular address format.
        let mut dns = self.dns.clone();
        let resv = command.and_then(|c| read_exact(c, [0u8]).map(|c| c.0));
        let atyp = resv.and_then(|c| read_exact(c, [0u8]));
        let addr = mybox(atyp.and_then(move |(c, buf)| {
            match buf[0] {
                // For IPv4 addresses, we read the 4 bytes for the address as
                // well as 2 bytes for the port.
                v5::ATYP_IPV4 => {
                    mybox(read_exact(c, [0u8; 6]).map(|(c, buf)| {
                        let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                        let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
                        let addr = SocketAddrV4::new(addr, port);
                        (c, SocketAddr::V4(addr))
                    }))
                }

                // For IPv6 addresses there's 16 bytes of an address plus two
                // bytes for a port, so we read that off and then keep going.
                v5::ATYP_IPV6 => {
                    mybox(read_exact(c, [0u8; 18]).map(|(conn, buf)| {
                        let a = ((buf[0] as u16) << 8) | (buf[1] as u16);
                        let b = ((buf[2] as u16) << 8) | (buf[3] as u16);
                        let c = ((buf[4] as u16) << 8) | (buf[5] as u16);
                        let d = ((buf[6] as u16) << 8) | (buf[7] as u16);
                        let e = ((buf[8] as u16) << 8) | (buf[9] as u16);
                        let f = ((buf[10] as u16) << 8) | (buf[11] as u16);
                        let g = ((buf[12] as u16) << 8) | (buf[13] as u16);
                        let h = ((buf[14] as u16) << 8) | (buf[15] as u16);
                        let addr = Ipv6Addr::new(a, b, c, d, e, f, g, h);
                        let port = ((buf[16] as u16) << 8) | (buf[17] as u16);
                        let addr = SocketAddrV6::new(addr, port, 0, 0);
                        (conn, SocketAddr::V6(addr))
                    }))
                }

                // The SOCKSv5 protocol not only supports proxying to specific
                // IP addresses, but also arbitrary hostnames. This allows
                // clients to perform hostname lookups within the context of the
                // proxy server rather than the client itself.
                //
                // Since the first publication of this code, several
                // futures-based DNS libraries appeared, and as a demonstration
                // of integrating third-party asynchronous code into our chain,
                // we will use one of them, TRust-DNS.
                //
                // The protocol here is to have the next byte indicate how many
                // bytes the hostname contains, followed by the hostname and two
                // bytes for the port. To read this data, we execute two
                // respective `read_exact` operations to fill up a buffer for
                // the hostname.
                //
                // Finally, to perform the "interesting" part, we process the
                // buffer and pass the retrieved hostname to a query future if
                // it wasn't already recognized as an IP address. The query is
                // very basic: it asks for an IPv4 address with a timeout of
                // five seconds. We're using TRust-DNS at the protocol level,
                // so we don't have the functionality normally expected from a
                // stub resolver, such as sorting of answers according to RFC
                // 6724, more robust timeout handling, or resolving CNAME
                // lookups.
                v5::ATYP_DOMAIN => {
                    mybox(read_exact(c, [0u8]).and_then(|(conn, buf)| {
                        read_exact(conn, vec![0u8; buf[0] as usize + 2])
                    }).and_then(move |(conn, buf)| {
                        let (name, port) = match name_port(&buf) {
                            Ok(UrlHost::Name(name, port)) => (name, port),
                            Ok(UrlHost::Addr(addr)) => {
                                return mybox(future::ok((conn, addr)))
                            }
                            Err(e) => return mybox(future::err(e)),
                        };
                        println!("DNS Query: {:?}:{:?}", name, port);

                        let ipv4 = dns.query(name, DNSClass::IN, RecordType::A)
                                      .map_err(|e| other(&format!("dns error: {}", e)))
                                      .and_then(move |r| get_addr(r, port));
                        
                        mybox(ipv4.map(|addr| {
                            println!("\t{:?}", addr);
                            (conn, addr)
                        }))
                    }))
                }

                n => {
                    let msg = format!("unknown ATYP received: {}", n);
                    mybox(future::err(other(&msg)))
                }
            }
        }));

        // Now that we've got a socket address to connect to, let's actually
        // create a connection to that socket!
        //
        // To do this, we use our `handle` field, a handle to the event loop, to
        // issue a connection to the address we've figured out we're going to
        // connect to. Note that this `tcp_connect` method itself returns a
        // future resolving to a `TcpStream`, representing how long it takes to
        // initiate a TCP connection to the remote.
        //
        // We wait for the TCP connect to get fully resolved before progressing
        // to the next stage of the SOCKSv5 handshake, but we keep ahold of any
        // possible error in the connection phase to handle it in a moment.
        let handle = self.handle.clone();
        let connected = mybox(addr.and_then(move |(c, addr)| {
            debug!("proxying to {}", addr);
            TcpStream::connect(&addr, &handle).then(move |c2| Ok((c, c2, addr)))
        }));

        // Once we've gotten to this point, we're ready for the final part of
        // the SOCKSv5 handshake. We've got in our hands (c2) the client we're
        // going to proxy data to, so we write out relevant information to the
        // original client (c1) the "response packet" which is the final part of
        // this handshake.
        let handshake_finish = mybox(connected.and_then(|(c1, c2, addr)| {
            let mut resp = [0u8; 32];

            // VER - protocol version
            resp[0] = 5;

            // REP - "reply field" -- what happened with the actual connect.
            //
            // In theory this should reply back with a bunch more kinds of
            // errors if possible, but for now we just recognize a few concrete
            // errors.
            resp[1] = match c2 {
                Ok(..) => 0,
                Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused => 5,
                Err(..) => 1,
            };

            // RSV - reserved
            resp[2] = 0;

            // ATYP, BND.ADDR, and BND.PORT
            //
            // These three fields, when used with a "connect" command
            // (determined above), indicate the address that our proxy
            // connection was bound to remotely. There's a variable length
            // encoding of what's actually written depending on whether we're
            // using an IPv4 or IPv6 address, but otherwise it's pretty
            // standard.
            let addr = match c2.as_ref().map(|r| r.local_addr()) {
                Ok(Ok(addr)) => addr,
                Ok(Err(..)) |
                Err(..) => addr,
            };
            let pos = match addr {
                SocketAddr::V4(ref a) => {
                    resp[3] = 1;
                    resp[4..8].copy_from_slice(&a.ip().octets()[..]);
                    8
                }
                SocketAddr::V6(ref a) => {
                    resp[3] = 4;
                    let mut pos = 4;
                    for &segment in a.ip().segments().iter() {
                        resp[pos] = (segment >> 8) as u8;
                        resp[pos + 1] = segment as u8;
                        pos += 2;
                    }
                    pos
                }
            };
            resp[pos] = (addr.port() >> 8) as u8;
            resp[pos + 1] = addr.port() as u8;

            // Slice our 32-byte `resp` buffer to the actual size, as it's
            // variable depending on what address we just encoding. Once that's
            // done, write out the whole buffer to our client.
            //
            // The returned type of the future here will be `(TcpStream,
            // TcpStream)` representing the client half and the proxy half of
            // the connection.
            let mut w = Window::new(resp);
            w.set_end(pos + 2);
            write_all(c1, w).and_then(|(c1, _)| {
                c2.map(|c2| (c1, c2))
            })
        }));

        // Phew! If you've gotten this far, then we're now entirely done with
        // the entire SOCKSv5 handshake!
        //
        // In order to handle ill-behaved clients, however, we have an added
        // feature here where we'll time out any initial connect operations
        // which take too long.
        //
        // Here we create a timeout future, using the `Timeout::new` method,
        // which will create a future that will resolve to `()` in 10 seconds.
        // We then apply this timeout to the entire handshake all at once by
        // performing a `select` between the timeout and the handshake itself.
        let timeout = Timeout::new(Duration::new(10, 0), &self.handle).unwrap();
        let pair = mybox(handshake_finish.map(Ok).select(timeout.map(Err)).then(|res| {
            match res {
                // The handshake finished before the timeout fired, so we
                // drop the future representing the timeout, canceling the
                // timeout, and then return the pair of connections the
                // handshake resolved with.
                Ok((Ok(pair), _timeout)) => Ok(pair),

                // The timeout fired before the handshake finished. In this
                // case we drop the future representing the handshake, which
                // cleans up the associated connection and all other
                // resources.
                //
                // This automatically "cancels" any I/O associated with the
                // handshake: reads, writes, TCP connects, etc. All of those
                // I/O resources are owned by the future, so if we drop the
                // future they're all released!
                Ok((Err(()), _handshake)) => {
                    Err(other("timeout during handshake"))
                }

                // One of the futures (handshake or timeout) hit an error
                // along the way. We're not entirely sure which at this
                // point, but in any case that shouldn't happen, so we just
                // keep propagating along the error.
                Err((e, _other)) => Err(e),
            }
        }));

        // At this point we've *actually* finished the handshake. Not only have
        // we read/written all the relevant bytes, but we've also managed to
        // complete in under our allotted timeout.
        //
        // At this point the remainder of the SOCKSv5 proxy is shuttle data back
        // and for between the two connections. That is, data is read from `c1`
        // and written to `c2`, and vice versa.
        //
        // To accomplish this, we put both sockets into their own `Rc` and then
        // create two independent `Transfer` futures representing each half of
        // the connection. These two futures are `join`ed together to represent
        // the proxy operation happening.
        let buffer = self.buffer.clone();
        mybox(pair.and_then(|(c1, c2)| {
            let c1 = Rc::new(c1);
            let c2 = Rc::new(c2);

            let half1 = Transfer::new(c1.clone(), c2.clone(), buffer.clone());
            let half2 = Transfer::new(c2, c1, buffer);
            half1.join(half2)
        }))
    }
}

fn mybox<F: Future + 'static>(f: F) -> Box<Future<Item=F::Item, Error=F::Error>> {
    Box::new(f)
}

/// A future representing reading all data from one side of a proxy connection
/// and writing it to another.
///
/// This future, unlike the handshake performed above, is implemented via a
/// custom implementation of the `Future` trait rather than with combinators.
/// This is intended to show off how the combinators are not all that can be
/// done with futures, but rather more custom (or optimized) implementations can
/// be implemented with just a trait impl!
struct Transfer {
    // The two I/O objects we'll be reading.
    reader: Rc<TcpStream>,
    writer: Rc<TcpStream>,

    // The shared global buffer that all connections on our server are using.
    buf: Rc<RefCell<Vec<u8>>>,

    // The number of bytes we've written so far.
    amt: u64,
}

impl Transfer {
    fn new(reader: Rc<TcpStream>,
           writer: Rc<TcpStream>,
           buffer: Rc<RefCell<Vec<u8>>>) -> Transfer {
        Transfer {
            reader: reader,
            writer: writer,
            buf: buffer,
            amt: 0,
        }
    }
}

// Here we implement the `Future` trait for `Transfer` directly. This does not
// use any combinators, and shows how you might implement it in custom
// situations if needed.
impl Future for Transfer {
    // Our future resolves to the number of bytes transferred, or an I/O error
    // that happens during the connection, if any.
    type Item = u64;
    type Error = io::Error;

    /// Attempts to drive this future to completion, checking if it's ready to
    /// be completed.
    ///
    /// This method is the core foundation of completing a future over time. It
    /// is intended to never block and return "quickly" to ensure that it
    /// doesn't block the event loop.
    ///
    /// Completion for our `Transfer` future is defined when one side hits EOF
    /// and we've written all remaining data to the other side of the
    /// connection. The behavior of `Future::poll` is in general not specified
    /// after a future resolves (e.g. in this case returns an error or how many
    /// bytes were transferred), so we don't need to maintain state beyond that
    /// point.
    fn poll(&mut self) -> Poll<u64, io::Error> {
        let mut buffer = self.buf.borrow_mut();

        // Here we loop over the two TCP halves, reading all data from one
        // connection and writing it to another. The crucial performance aspect
        // of this server, however, is that we wait until both the read half and
        // the write half are ready on the connection, allowing the buffer to
        // only be temporarily used in a small window for all connections.
        loop {
            let read_ready = self.reader.poll_read().is_ready();
            let write_ready = self.writer.poll_write().is_ready();
            if !read_ready || !write_ready {
                return Ok(Async::NotReady)
            }

            // TODO: This exact logic for reading/writing amounts may need an
            //       update
            //
            // Right now the `buffer` is actually pretty big, 64k, and it could
            // be the case that one end of the connection can far outpace
            // another. For example we may be able to always read 64k from the
            // read half but only be able to write 5k to the client. This is a
            // pretty bad situation because we've got data in a buffer that's
            // intended to be ephemeral!
            //
            // Ideally here we'd actually adapt the rate of reads to match the
            // rate of writes. That is, we'd prefer to have some form of
            // adaptive algorithm which keeps track of how many bytes are
            // written and match the read rate to the write rate. It's possible
            // for connections to have an even smaller (and optional) buffer on
            // the side representing the "too much data they read" if that
            // happens, and then the next call to `read` could compensate by not
            // reading so much again.
            //
            // In any case, though, this is easily implementable in terms of
            // adding fields to `Transfer` and is complicated enough to
            // otherwise detract from the example in question here. As a result,
            // we simply read into the global buffer and then assert that we
            // write out exactly the same amount.
            //
            // This means that we may trip the assert below, but it should be
            // relatively easily fixable with the strategy above!

            let n = try_nb!((&*self.reader).read(&mut buffer));
            if n == 0 {
                try!(self.writer.shutdown(Shutdown::Write));
                return Ok(self.amt.into())
            }
            self.amt += n as u64;

            // Unlike above, we don't handle `WouldBlock` specially, because
            // that would play into the logic mentioned above (tracking read
            // rates and write rates), so we just ferry along that error for
            // now.
            let m = try!((&*self.writer).write(&buffer[..n]));
            // assert_eq!(n, m);
            if n != m {
                println!("[ERROR] Left({}) != Right{}", n, m);
            }
        }
    }
}

fn other(desc: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, desc)
}

enum UrlHost {
    Name(Name, u16),
    Addr(SocketAddr),
}

// Extracts the name and port from addr_buf and returns them, converting
// the name to the form that the trust-dns client can use. If the original
// name can be parsed as an IP address, makes a SocketAddr from that
// address and the port and returns it; we skip DNS resolution in that
// case.
fn name_port(addr_buf: &[u8]) -> io::Result<UrlHost> {
    // The last two bytes of the buffer are the port, and the other parts of it
    // are the hostname.
    let hostname = &addr_buf[..addr_buf.len() - 2];
    let hostname = try!(str::from_utf8(hostname).map_err(|_e| {
        other("hostname buffer provided was not valid utf-8")
    }));
    let pos = addr_buf.len() - 2;
    let port = ((addr_buf[pos] as u16) << 8) | (addr_buf[pos + 1] as u16);

    if let Ok(ip) = hostname.parse() {
        return Ok(UrlHost::Addr(SocketAddr::new(ip, port)))
    }
    let name = try!(Name::parse(hostname, Some(&Name::root())).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, e.to_string())
    }));
    Ok(UrlHost::Name(name, port))
}

// Extracts the first IP address from the response.
fn get_addr(response: Message, port: u16) -> io::Result<SocketAddr> {
    if response.get_response_code() != ResponseCode::NoError {
        return Err(other("resolution failed"));
    }
    let addr = response.get_answers().iter().filter_map(|ans| {
        match *ans.get_rdata() {
            RData::A(addr) => Some(IpAddr::V4(addr)),
            RData::AAAA(addr) => Some(IpAddr::V6(addr)),
            _ => None,
        }
    }).next();

    match addr {
        Some(addr) => Ok(SocketAddr::new(addr, port)),
        None => Err(other("no address records in response")),
    }
}

// Various constants associated with the SOCKS protocol

#[allow(dead_code)]
mod v5 {
    pub const VERSION: u8 = 5;

    pub const METH_NO_AUTH: u8 = 0;
    pub const METH_GSSAPI: u8 = 1;
    pub const METH_USER_PASS: u8 = 2;

    pub const CMD_CONNECT: u8 = 1;
    pub const CMD_BIND: u8 = 2;
    pub const CMD_UDP_ASSOCIATE: u8 = 3;

    pub const ATYP_IPV4: u8 = 1;
    pub const ATYP_IPV6: u8 = 4;
    pub const ATYP_DOMAIN: u8 = 3;
}

#[allow(dead_code)]
mod v4 {
    pub const VERSION: u8 = 4;

    pub const CMD_CONNECT: u8 = 1;
    pub const CMD_BIND: u8 = 2;
}

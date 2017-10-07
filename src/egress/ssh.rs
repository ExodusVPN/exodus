extern crate ssh2;

use std::io::{Write, Read};
use std::net::{ToSocketAddrs, SocketAddr};
use std::net::TcpStream;
use std::io::{Error, ErrorKind};



#[derive(Debug, Clone)]
pub struct PublicKey {
    hexstr : String,
    comment: String
}

pub struct SSH {
    #[allow(dead_code)]
    tcp    : TcpStream,
    session: ssh2::Session,
}

impl SSH {
    pub fn connect<A: ToSocketAddrs>(addr: A) -> Result<SSH, Error> {
        match TcpStream::connect(addr) {
            Ok(tcp) => match ssh2::Session::new() {
                Some(mut session) => {
                    session.handshake(&tcp).unwrap();
                    Ok(SSH{ tcp: tcp, session: session })
                },
                None => Err(Error::new(ErrorKind::Other, "Oh, no ..."))
            },
            Err(_) => Err(Error::new(ErrorKind::Other, "Oh, no ..."))
        }
    }

    pub fn auth(&self, username: &str) -> Result<(), Error> {
        match self.session.userauth_agent(username) {
            Ok(_) => {
                match self.session.authenticated() {
                    true  => Ok(()),
                    false => Err(Error::new(ErrorKind::Other, "Oh, no ..."))
                }
            },
            Err(_) => Err(Error::new(ErrorKind::Other, "Oh, no ..."))
        }
    }

    pub fn relay<A: ToSocketAddrs>(&self, addr: A) -> Result<ssh2::Channel, Error>{
        // SSH 支持域名传递，由于我们需要对 IP 进行判断，所以这里统一传递的是 IP.
        match addr.to_socket_addrs() {
            Ok(addr) => {
                let addrs = addr.collect::<Vec<SocketAddr>>();
                if addrs.len() >= 1 {
                    let ip = addrs[0].ip().to_string();
                    let port= addrs[0].port();
                    match self.session.channel_direct_tcpip(&ip, port, None) {
                        Ok(channel) => Ok(channel),
                        Err(_) => Err(Error::new(ErrorKind::Other, "Oh, no ..."))
                    }
                } else {
                    Err(Error::new(ErrorKind::Other, "Oh, no ..."))
                }
            },
            Err(_) => Err(Error::new(ErrorKind::Other, "Oh, no ..."))
        }
    }

    pub fn disconnect(&self) -> Result<(), Error> {
        match self.session.disconnect(Some(ssh2::DisconnectCode::ByApplication), "Bye, SSH-Net-Tunnel", Some("zh-CN")) {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::new(ErrorKind::Other, "Oh, no ..."))
        }
    }

    pub fn identities(&self) -> Result<Vec<PublicKey>, Error>{
        match self.session.agent() {
            Ok(mut agent) => {
                agent.connect().unwrap();
                match agent.list_identities() {
                    Ok(_) => {
                        let _identities = agent.identities()
                                            .filter(|item| item.is_ok())
                                            .map(|item| {
                                                let pubkey = item.unwrap();
                                                PublicKey {
                                                    hexstr: pubkey.blob().iter()
                                                            .map(|b| format!("{:02X}", b))
                                                            .collect::<Vec<String>>()
                                                            .join(""),
                                                    comment: pubkey.comment().to_string()
                                                }
                                            })
                                            .collect::<Vec<PublicKey>>();
                        let _ = agent.disconnect();
                        Ok(_identities)
                    },
                    Err(_) => Err(Error::new(ErrorKind::Other, "Oh, no ..."))
                }
            },
            Err(_) => Err(Error::new(ErrorKind::Other, "Oh, no ..."))
        }
    }
}

fn main (){
    match SSH::connect("35.194.146.161:22") {
        Ok(ssh) => {
            match ssh.auth("luozijun") {
                Ok(_) => {
                    match ssh.identities() {
                        Ok(identities) => println!("{:?}", identities),
                        Err(e) => println!("{:?}", e)
                    };

                    match ssh.relay("74.125.203.138:80") {
                        Ok(mut channel) => {
                            let _ = channel.write(b"GET / HTTP/1.1\r\nHost: youtube.com\r\n\r\n");
                            let _ = channel.send_eof();

                            let mut s = String::new();
                            channel.read_to_string(&mut s).unwrap();
                            println!("{}", s);
                            let _ = channel.close().unwrap();

                            ssh.disconnect().unwrap();
                        },
                        Err(e) => {
                            println!("{:?}", e);
                        }
                    }
                },
                Err(e) => println!("{:?}", e)
            }
        },
        Err(e) => println!("{:?}", e)
    };
}


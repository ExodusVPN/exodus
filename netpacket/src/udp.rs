
use byteorder::{BigEndian, ReadBytesExt};

use std::mem::transmute;


/// https://en.wikipedia.org/wiki/User_Datagram_Protocol#Packet_structure
#[derive(Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    src_port: u16,
    dst_port: u16,
    length  : u16,     // specifies the length in bytes of the UDP header and UDP data
    checksum: u16,
    payload : &'a [u8]
}

impl <'a>Packet<'a> {

    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        if payload.len() < 8 {
            return Err(::std::io::Error::new(::std::io::ErrorKind::Other, "size error ..."));
        }

        let mut src_port_bytes = &payload[0..2];
        let src_port: u16 = src_port_bytes.read_u16::<BigEndian>().unwrap();
        let mut dst_port_bytes = &payload[2..4];
        let dst_port: u16 = dst_port_bytes.read_u16::<BigEndian>().unwrap();

        let mut length_bytes = &payload[4..6];
        let length: u16 = length_bytes.read_u16::<BigEndian>().unwrap();

        let mut checksum_bytes = &payload[6..8];
        let checksum: u16 = checksum_bytes.read_u16::<BigEndian>().unwrap();

        if payload.len() != length as usize {
            return Err(::std::io::Error::new(::std::io::ErrorKind::Other, "size error ..."));
        }
        
        Ok(Packet {
            src_port: src_port,
            dst_port: dst_port,
            length  : length,
            checksum: checksum,
            payload : unsafe { transmute(&payload[8..]) }
        })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        
        bytes.push( (self.src_port >> 8) as u8 );
        bytes.push( (self.src_port & 0xff) as u8 );
        
        bytes.push( (self.dst_port >> 8) as u8 );
        bytes.push( (self.dst_port & 0xff) as u8 );
        
        bytes.push( (self.length >> 8) as u8 );
        bytes.push( (self.length & 0xff) as u8 );

        bytes.push( (self.checksum >> 8) as u8 );
        bytes.push( (self.checksum & 0xff) as u8 );
        
        bytes.extend_from_slice(self.payload);
        bytes
    }
    
    pub fn src_port(&self) -> u16 {
        self.src_port
    }
    pub fn dst_port(&self) -> u16 {
        self.dst_port
    }
    pub fn length(&self) -> u16 {
        self.length
    }
    pub fn checksum(&self) -> u16 {
        self.checksum
    }
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
    
}

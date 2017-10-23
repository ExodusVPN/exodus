
use std::mem::transmute;

// #[derive(Debug, PartialEq, Eq)]
// #[allow(non_camel_case_types)]
// pub enum Flag {
//     NS,
//     CWR,
//     ECE,
//     URG,
//     ACK,
//     PSH,
//     RST,
//     SYN,
//     FIN
// }

#[derive(Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub struct Flags {
    pub ns:  bool,
    pub cwr: bool,
    pub ece: bool,
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
}

#[derive(Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum Operation {
    LISTEN,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    CLOSING,
    LAST_ACK,
    TIME_WAIT,
    CLOSED
}

/// Connection establishment
/// 
/// * SYN
/// * SYN-ACK
/// * ACK
/// 
/// https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
#[derive(Debug, PartialEq, Eq)]
pub struct Packet<'a, 'b> {
    src_port: u16,              // 16 bits
    dst_port: u16,              // 16 bits
    sequence_number: u32,       // 32 bits
    acknowledgment_number: u32, // 32 bits , if ACK set
    data_offset: u8,            //  4 bits
    reserved: u8,               //  3 bits
    flags   : Flags,            //  9 bits, NS/CWR/ECE/URG/ACK/PSH/RST/SYN/FIN
    window_size: u16,           // 16 bits
    checksum: u16,              // 16 bits
    urgent_pointer: u16,        // 16 bits , if URG set
    options: &'a [u8],          // .. bits , if data offset > 5. Padded at the end with "0" bytes if necessary
    payload: &'b [u8],          // .. bits
}

impl <'a, 'b>Packet<'a, 'b> {
    #[allow(unused_variables)]
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        
        println!("tcp payload length: {:?}", payload.len());
        println!("{:?}", payload);


        if payload.len() < 20 {
            return Err(::std::io::Error::new(::std::io::ErrorKind::Other, "size error ..."));
        }
        
        let src_port: u16 = (payload[0] as u16) << 8 | (payload[1] as u16);
        let dst_port: u16 = (payload[2] as u16) << 8 | (payload[3] as u16);
        let sequence_number: u32 = (payload[4] as u32) << 24 | (payload[5] as u32) << 16 | (payload[6] as u32) << 8 | (payload[7] as u32);
        let acknowledgment_number: u32 = (payload[8] as u32) << 24 | (payload[9] as u32) << 16 | (payload[10] as u32) << 8 | (payload[11] as u32);
        let data_offset = payload[12] >> 4;
        let reserved = payload[12] >> 3;

        let flags = Flags {
            ns: (payload[12] & 0b00000001) != 0,
            cwr: (payload[13] >> 7 & 0b00000001) != 0,
            ece: (payload[13] >> 6 & 0b00000001) != 0,
            urg: (payload[13] >> 5 & 0b00000001) != 0,
            ack: (payload[13] >> 4 & 0b00000001) != 0,
            psh: (payload[13] >> 3 & 0b00000001) != 0,
            rst: (payload[13] >> 2 & 0b00000001) != 0,
            syn: (payload[13] >> 1 & 0b00000001) != 0,
            fin: (payload[13] >> 0 & 0b00000001) != 0,
        };

        let window_size = (payload[14] as u16) << 8 | (payload[15] as u16);
        let checksum    = (payload[16] as u16) << 8 | (payload[17] as u16);
        let urgent_pointer = (payload[18] as u16) << 8 | (payload[19] as u16);
        
        // if data_offset > 5 {
        
        // }
        let options_end = (data_offset * 4) as usize;

        Ok(Packet{
            src_port: src_port,
            dst_port: dst_port,
            sequence_number: sequence_number,
            acknowledgment_number: acknowledgment_number,
            data_offset: data_offset,
            reserved   : reserved,
            flags: flags,
            window_size: window_size,
            checksum: checksum,
            urgent_pointer: urgent_pointer,
            options: unsafe {transmute(&payload[20..options_end])},
            payload: unsafe {transmute(&payload[20+options_end..])}
        })
    }
    
    pub fn as_bytes(&self) -> &[u8] {
        unimplemented!();
    }
    
    pub fn payload(&self) -> &'b [u8] {
        self.payload
    }
}


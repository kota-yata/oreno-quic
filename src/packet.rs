use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Initial = 0x00,
    ZeroRtt = 0x01,
    Handshake = 0x02,
    Retry = 0x03,
    Short = 0x04,
}

#[derive(Debug, Clone)]
pub struct ConnectionId {
    pub data: Vec<u8>,
}

impl ConnectionId {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
    
    pub fn random(len: usize) -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
        Self { data }
    }
    
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct LongHeader {
    pub packet_type: PacketType,
    pub version: u32,
    pub dest_conn_id: ConnectionId,
    pub src_conn_id: ConnectionId,
    pub packet_number: u64,
}

#[derive(Debug, Clone)]
pub struct ShortHeader {
    pub dest_conn_id: ConnectionId,
    pub packet_number: u64,
}

#[derive(Debug, Clone)]
pub enum PacketHeader {
    Long(LongHeader),
    Short(ShortHeader),
}

impl PacketHeader {
    pub fn encode(&self, buf: &mut BytesMut) -> Result<(), PacketError> {
        match self {
            PacketHeader::Long(header) => {
                let first_byte = 0x80 | (header.packet_type as u8) << 4;
                buf.put_u8(first_byte);
                buf.put_u32(header.version);
                
                buf.put_u8(header.dest_conn_id.len() as u8);
                buf.put_slice(&header.dest_conn_id.data);
                
                buf.put_u8(header.src_conn_id.len() as u8);
                buf.put_slice(&header.src_conn_id.data);
                
                encode_packet_number(buf, header.packet_number);
            }
            PacketHeader::Short(header) => {
                let first_byte = 0x40;
                buf.put_u8(first_byte);
                buf.put_slice(&header.dest_conn_id.data);
                encode_packet_number(buf, header.packet_number);
            }
        }
        Ok(())
    }
    
    pub fn decode(buf: &mut Bytes) -> Result<Self, PacketError> {
        if buf.is_empty() {
            return Err(PacketError::InvalidFormat);
        }
        
        let first_byte = buf[0];
        
        if first_byte & 0x80 != 0 {
            buf.advance(1);
            
            let packet_type = match (first_byte >> 4) & 0x03 {
                0x00 => PacketType::Initial,
                0x01 => PacketType::ZeroRtt,
                0x02 => PacketType::Handshake,
                0x03 => PacketType::Retry,
                _ => return Err(PacketError::InvalidFormat),
            };
            
            if buf.remaining() < 4 {
                return Err(PacketError::InvalidFormat);
            }
            let version = buf.get_u32();
            
            if buf.is_empty() {
                return Err(PacketError::InvalidFormat);
            }
            let dest_conn_id_len = buf.get_u8() as usize;
            if buf.remaining() < dest_conn_id_len {
                return Err(PacketError::InvalidFormat);
            }
            let dest_conn_id = ConnectionId::new(buf.copy_to_bytes(dest_conn_id_len).to_vec());
            
            if buf.is_empty() {
                return Err(PacketError::InvalidFormat);
            }
            let src_conn_id_len = buf.get_u8() as usize;
            if buf.remaining() < src_conn_id_len {
                return Err(PacketError::InvalidFormat);
            }
            let src_conn_id = ConnectionId::new(buf.copy_to_bytes(src_conn_id_len).to_vec());
            
            let packet_number = decode_packet_number(buf)?;
            
            Ok(PacketHeader::Long(LongHeader {
                packet_type,
                version,
                dest_conn_id,
                src_conn_id,
                packet_number,
            }))
        } else {
            buf.advance(1);
            
            let dest_conn_id = ConnectionId::new(buf.copy_to_bytes(8).to_vec());
            let packet_number = decode_packet_number(buf)?;
            
            Ok(PacketHeader::Short(ShortHeader {
                dest_conn_id,
                packet_number,
            }))
        }
    }
}

fn encode_packet_number(buf: &mut BytesMut, packet_number: u64) {
    if packet_number < 0x40 {
        buf.put_u8(packet_number as u8);
    } else if packet_number < 0x4000 {
        buf.put_u16(0x8000 | packet_number as u16);
    } else if packet_number < 0x40000000 {
        buf.put_u32(0xC0000000 | packet_number as u32);
    } else {
        buf.put_u64(packet_number);
    }
}

fn decode_packet_number(buf: &mut Bytes) -> Result<u64, PacketError> {
    if buf.is_empty() {
        return Err(PacketError::InvalidFormat);
    }
    
    let first_byte = buf[0];
    let len = (first_byte >> 6) + 1;
    
    if buf.remaining() < len as usize {
        return Err(PacketError::InvalidFormat);
    }
    
    match len {
        1 => Ok(buf.get_u8() as u64),
        2 => Ok((buf.get_u16() & 0x3FFF) as u64),
        4 => Ok((buf.get_u32() & 0x3FFFFFFF) as u64),
        8 => Ok(buf.get_u64()),
        _ => Err(PacketError::InvalidFormat),
    }
}

#[derive(Debug)]
pub enum PacketError {
    InvalidFormat,
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketError::InvalidFormat => write!(f, "Invalid packet format"),
        }
    }
}

impl std::error::Error for PacketError {}
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
            
            // For short header, we need to know the connection ID length
            // For simplicity, assume 8 bytes (this should be configurable in real implementation)
            if buf.remaining() < 8 {
                return Err(PacketError::InvalidFormat);
            }
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
        buf.put_u8(packet_number as u8);                           // 00xxxxxx
    } else if packet_number < 0x4000 {
        buf.put_u16(0x4000 | packet_number as u16);               // 01xxxxxx xxxxxxxx
    } else if packet_number < 0x40000000 {
        buf.put_u32(0x80000000 | packet_number as u32);           // 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
    } else {
        buf.put_u64(0xC000000000000000 | packet_number);          // 11xxxxxx x64 bits
    }
}

fn decode_packet_number(buf: &mut Bytes) -> Result<u64, PacketError> {
    if buf.is_empty() {
        return Err(PacketError::InvalidFormat);
    }
    
    let first_byte = buf[0];
    let len_bits = first_byte >> 6;
    let len = 1 << len_bits;
    
    if buf.remaining() < len {
        return Err(PacketError::InvalidFormat);
    }
    
    match len_bits {
        0 => Ok((buf.get_u8() & 0x3F) as u64),           // 1 byte (00)
        1 => Ok((buf.get_u16() & 0x3FFF) as u64),        // 2 bytes (01)
        2 => Ok((buf.get_u32() & 0x3FFFFFFF) as u64),    // 4 bytes (10)
        3 => Ok(buf.get_u64() & 0x3FFFFFFFFFFFFFFF),     // 8 bytes (11)
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

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_connection_id_creation() {
        let data = vec![1, 2, 3, 4];
        let conn_id = ConnectionId::new(data.clone());
        assert_eq!(conn_id.data, data);
        assert_eq!(conn_id.len(), 4);
        assert!(!conn_id.is_empty());
    }

    #[test]
    fn test_connection_id_random() {
        let conn_id1 = ConnectionId::random(8);
        let conn_id2 = ConnectionId::random(8);
        assert_eq!(conn_id1.len(), 8);
        assert_eq!(conn_id2.len(), 8);
        assert_ne!(conn_id1.data, conn_id2.data);
    }

    #[test]
    fn test_connection_id_empty() {
        let conn_id = ConnectionId::new(vec![]);
        assert!(conn_id.is_empty());
        assert_eq!(conn_id.len(), 0);
    }

    #[test]
    fn test_long_header_encode_decode() {
        let header = PacketHeader::Long(LongHeader {
            packet_type: PacketType::Initial,
            version: 1,
            dest_conn_id: ConnectionId::new(vec![1, 2, 3, 4]),
            src_conn_id: ConnectionId::new(vec![5, 6, 7, 8]),
            packet_number: 42,
        });

        let mut buf = BytesMut::new();
        header.encode(&mut buf).unwrap();

        let mut bytes = buf.freeze();
        let decoded = PacketHeader::decode(&mut bytes).unwrap();

        match decoded {
            PacketHeader::Long(decoded_header) => {
                assert_eq!(decoded_header.packet_type, PacketType::Initial);
                assert_eq!(decoded_header.version, 1);
                assert_eq!(decoded_header.dest_conn_id.data, vec![1, 2, 3, 4]);
                assert_eq!(decoded_header.src_conn_id.data, vec![5, 6, 7, 8]);
                assert_eq!(decoded_header.packet_number, 42);
            }
            _ => panic!("Expected Long header"),
        }
    }

    #[test]
    fn test_short_header_encode_decode() {
        let header = PacketHeader::Short(ShortHeader {
            dest_conn_id: ConnectionId::new(vec![1, 2, 3, 4, 5, 6, 7, 8]),
            packet_number: 123,
        });

        let mut buf = BytesMut::new();
        header.encode(&mut buf).unwrap();

        let mut bytes = buf.freeze();
        let decoded = PacketHeader::decode(&mut bytes).unwrap();

        match decoded {
            PacketHeader::Short(decoded_header) => {
                assert_eq!(decoded_header.dest_conn_id.data, vec![1, 2, 3, 4, 5, 6, 7, 8]);
                assert_eq!(decoded_header.packet_number, 123);
            }
            _ => panic!("Expected Short header"),
        }
    }

    #[test]
    fn test_packet_number_encoding() {
        let test_cases = vec![
            (0, 1),                 // 1 byte
            (63, 1),                // 1 byte max
            (64, 2),                // 2 bytes
            (16383, 2),             // 2 bytes max
            (16384, 4),             // 4 bytes
            (1073741823, 4),        // 4 bytes max
            (1073741824, 8),        // 8 bytes
        ];

        for (packet_num, expected_len) in test_cases {
            let mut buf = BytesMut::new();
            encode_packet_number(&mut buf, packet_num);
            assert_eq!(buf.len(), expected_len, "Packet number {} should encode to {} bytes", packet_num, expected_len);

            let mut bytes = buf.freeze();
            let decoded = decode_packet_number(&mut bytes).unwrap();
            assert_eq!(decoded, packet_num, "Packet number {} should decode correctly", packet_num);
        }
    }

    #[test]
    fn test_invalid_packet_decode() {
        let mut empty_bytes = Bytes::new();
        assert!(PacketHeader::decode(&mut empty_bytes).is_err());

        let mut invalid_bytes = Bytes::from_static(&[0x80]); // Long header but truncated
        assert!(PacketHeader::decode(&mut invalid_bytes).is_err());
    }

    #[test]
    fn test_packet_types() {
        let types = vec![
            (PacketType::Initial, 0x00),
            (PacketType::ZeroRtt, 0x01),
            (PacketType::Handshake, 0x02),
            (PacketType::Retry, 0x03),
            (PacketType::Short, 0x04),
        ];

        for (packet_type, expected_value) in types {
            assert_eq!(packet_type as u8, expected_value);
        }
    }

    #[test]
    fn test_long_header_different_packet_types() {
        let packet_types = vec![
            PacketType::Initial,
            PacketType::ZeroRtt,
            PacketType::Handshake,
            PacketType::Retry,
        ];

        for packet_type in packet_types {
            let header = PacketHeader::Long(LongHeader {
                packet_type,
                version: 1,
                dest_conn_id: ConnectionId::new(vec![1, 2]),
                src_conn_id: ConnectionId::new(vec![3, 4]),
                packet_number: 1,
            });

            let mut buf = BytesMut::new();
            header.encode(&mut buf).unwrap();

            let mut bytes = buf.freeze();
            let decoded = PacketHeader::decode(&mut bytes).unwrap();

            match decoded {
                PacketHeader::Long(decoded_header) => {
                    assert_eq!(decoded_header.packet_type, packet_type);
                }
                _ => panic!("Expected Long header"),
            }
        }
    }
}
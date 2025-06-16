use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameType {
    Padding = 0x00,
    Ping = 0x01,
    ConnectionClose = 0x1c,
}

#[derive(Debug, Clone)]
pub enum Frame {
    Padding { length: usize },
    Ping,
    ConnectionClose { error_code: u64, reason: String },
}

impl Frame {
    pub fn encode(&self, buf: &mut BytesMut) -> Result<(), FrameError> {
        match self {
            Frame::Padding { length } => {
                for _ in 0..*length {
                    buf.put_u8(0x00);
                }
            }
            Frame::Ping => {
                buf.put_u8(FrameType::Ping as u8);
            }
            Frame::ConnectionClose { error_code, reason } => {
                buf.put_u8(FrameType::ConnectionClose as u8);
                encode_varint(buf, *error_code);
                encode_varint(buf, 0); // frame type
                let reason_bytes = reason.as_bytes();
                encode_varint(buf, reason_bytes.len() as u64);
                buf.put_slice(reason_bytes);
            }
        }
        Ok(())
    }
    
    pub fn decode(buf: &mut Bytes) -> Result<Self, FrameError> {
        if buf.is_empty() {
            return Err(FrameError::InvalidFormat);
        }
        
        let frame_type = buf.get_u8();
        
        match frame_type {
            0x00 => {
                let mut length = 1;
                while !buf.is_empty() && buf[0] == 0x00 {
                    buf.advance(1);
                    length += 1;
                }
                Ok(Frame::Padding { length })
            }
            0x01 => Ok(Frame::Ping),
            0x1c => {
                let error_code = decode_varint(buf)?;
                let _frame_type = decode_varint(buf)?;
                let reason_length = decode_varint(buf)? as usize;
                
                if buf.remaining() < reason_length {
                    return Err(FrameError::InvalidFormat);
                }
                
                let reason_bytes = buf.copy_to_bytes(reason_length);
                let reason = String::from_utf8(reason_bytes.to_vec())
                    .map_err(|_| FrameError::InvalidFormat)?;
                
                Ok(Frame::ConnectionClose { error_code, reason })
            }
            _ => Err(FrameError::UnknownFrameType(frame_type)),
        }
    }
}

fn encode_varint(buf: &mut BytesMut, value: u64) {
    if value < 0x40 {
        buf.put_u8(value as u8);                           // 00xxxxxx
    } else if value < 0x4000 {
        buf.put_u16(0x4000 | value as u16);               // 01xxxxxx xxxxxxxx
    } else if value < 0x40000000 {
        buf.put_u32(0x80000000 | value as u32);           // 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
    } else {
        buf.put_u64(0xC000000000000000 | value);          // 11xxxxxx x64 bits
    }
}

fn decode_varint(buf: &mut Bytes) -> Result<u64, FrameError> {
    if buf.is_empty() {
        return Err(FrameError::InvalidFormat);
    }
    
    let first_byte = buf[0];
    let len_bits = first_byte >> 6;
    let len = 1 << len_bits;
    
    if buf.remaining() < len {
        return Err(FrameError::InvalidFormat);
    }
    
    match len_bits {
        0 => Ok((buf.get_u8() & 0x3F) as u64),           // 1 byte (00)
        1 => Ok((buf.get_u16() & 0x3FFF) as u64),        // 2 bytes (01)
        2 => Ok((buf.get_u32() & 0x3FFFFFFF) as u64),    // 4 bytes (10)
        3 => Ok(buf.get_u64() & 0x3FFFFFFFFFFFFFFF),     // 8 bytes (11)
        _ => Err(FrameError::InvalidFormat),
    }
}

#[derive(Debug)]
pub enum FrameError {
    InvalidFormat,
    UnknownFrameType(u8),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::InvalidFormat => write!(f, "Invalid frame format"),
            FrameError::UnknownFrameType(t) => write!(f, "Unknown frame type: {}", t),
        }
    }
}

impl std::error::Error for FrameError {}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_padding_frame_encode_decode() {
        let frame = Frame::Padding { length: 5 };
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.as_ref(), &[0, 0, 0, 0, 0]);
        
        let mut bytes = buf.freeze();
        let decoded = Frame::decode(&mut bytes).unwrap();
        
        match decoded {
            Frame::Padding { length } => assert_eq!(length, 5),
            _ => panic!("Expected Padding frame"),
        }
    }

    #[test]
    fn test_ping_frame_encode_decode() {
        let frame = Frame::Ping;
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        
        assert_eq!(buf.len(), 1);
        assert_eq!(buf[0], 0x01);
        
        let mut bytes = buf.freeze();
        let decoded = Frame::decode(&mut bytes).unwrap();
        
        match decoded {
            Frame::Ping => {},
            _ => panic!("Expected Ping frame"),
        }
    }

    #[test]
    fn test_connection_close_frame_encode_decode() {
        let frame = Frame::ConnectionClose {
            error_code: 42,
            reason: "Test reason".to_string(),
        };
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        
        let mut bytes = buf.freeze();
        let decoded = Frame::decode(&mut bytes).unwrap();
        
        match decoded {
            Frame::ConnectionClose { error_code, reason } => {
                assert_eq!(error_code, 42);
                assert_eq!(reason, "Test reason");
            }
            _ => panic!("Expected ConnectionClose frame"),
        }
    }

    #[test]
    fn test_connection_close_empty_reason() {
        let frame = Frame::ConnectionClose {
            error_code: 0,
            reason: "".to_string(),
        };
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        
        let mut bytes = buf.freeze();
        let decoded = Frame::decode(&mut bytes).unwrap();
        
        match decoded {
            Frame::ConnectionClose { error_code, reason } => {
                assert_eq!(error_code, 0);
                assert_eq!(reason, "");
            }
            _ => panic!("Expected ConnectionClose frame"),
        }
    }

    #[test]
    fn test_varint_encoding() {
        let test_cases = vec![
            (0, 1),                 // 1 byte
            (63, 1),                // 1 byte max
            (64, 2),                // 2 bytes
            (16383, 2),             // 2 bytes max
            (16384, 4),             // 4 bytes
            (1073741823, 4),        // 4 bytes max
            (1073741824, 8),        // 8 bytes
        ];

        for (value, expected_len) in test_cases {
            let mut buf = BytesMut::new();
            encode_varint(&mut buf, value);
            assert_eq!(buf.len(), expected_len, "Value {} should encode to {} bytes", value, expected_len);

            let mut bytes = buf.freeze();
            let decoded = decode_varint(&mut bytes)
                .unwrap_or_else(|e| panic!("Failed to decode value {}: {:?}", value, e));
            assert_eq!(decoded, value, "Value {} should decode correctly", value);
        }
    }

    #[test]
    fn test_frame_types() {
        assert_eq!(FrameType::Padding as u8, 0x00);
        assert_eq!(FrameType::Ping as u8, 0x01);
        assert_eq!(FrameType::ConnectionClose as u8, 0x1c);
    }

    #[test]
    fn test_invalid_frame_decode() {
        let mut empty_bytes = Bytes::new();
        assert!(Frame::decode(&mut empty_bytes).is_err());

        let mut unknown_frame = Bytes::from_static(&[0xFF]);
        match Frame::decode(&mut unknown_frame) {
            Err(FrameError::UnknownFrameType(0xFF)) => {},
            _ => panic!("Expected UnknownFrameType error"),
        }
    }

    #[test]
    fn test_truncated_connection_close() {
        let mut truncated = Bytes::from_static(&[0x1c, 0x00]); // CONNECTION_CLOSE but truncated
        assert!(Frame::decode(&mut truncated).is_err());
    }

    #[test]
    fn test_multiple_padding_frames() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x00, 0x00, 0x00]);
        
        let mut bytes = buf.freeze();
        let decoded = Frame::decode(&mut bytes).unwrap();
        
        match decoded {
            Frame::Padding { length } => assert_eq!(length, 3),
            _ => panic!("Expected Padding frame"),
        }
        
        assert!(bytes.is_empty());
    }

    #[test]
    fn test_connection_close_with_unicode() {
        let frame = Frame::ConnectionClose {
            error_code: 123,
            reason: "Test with 🚀 emoji".to_string(),
        };
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        
        let mut bytes = buf.freeze();
        let decoded = Frame::decode(&mut bytes).unwrap();
        
        match decoded {
            Frame::ConnectionClose { error_code, reason } => {
                assert_eq!(error_code, 123);
                assert_eq!(reason, "Test with 🚀 emoji");
            }
            _ => panic!("Expected ConnectionClose frame"),
        }
    }

    #[test]
    fn test_large_error_code() {
        // Use a large value that fits in the maximum encodable range
        let large_value = 0x3FFFFFFFFFFFFFFF; // Maximum value for 8-byte varint
        let frame = Frame::ConnectionClose {
            error_code: large_value,
            reason: "Max error code".to_string(),
        };
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        
        let mut bytes = buf.freeze();
        let decoded = Frame::decode(&mut bytes).unwrap();
        
        match decoded {
            Frame::ConnectionClose { error_code, reason } => {
                assert_eq!(error_code, large_value);
                assert_eq!(reason, "Max error code");
            }
            _ => panic!("Expected ConnectionClose frame"),
        }
    }
}
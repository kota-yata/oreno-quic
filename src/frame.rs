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
        buf.put_u8(value as u8);
    } else if value < 0x4000 {
        buf.put_u16(0x8000 | value as u16);
    } else if value < 0x40000000 {
        buf.put_u32(0xC0000000 | value as u32);
    } else {
        buf.put_u64(0xC000000000000000 | value);
    }
}

fn decode_varint(buf: &mut Bytes) -> Result<u64, FrameError> {
    if buf.is_empty() {
        return Err(FrameError::InvalidFormat);
    }
    
    let first_byte = buf[0];
    let len = 1 << (first_byte >> 6);
    
    if buf.remaining() < len {
        return Err(FrameError::InvalidFormat);
    }
    
    match len {
        1 => Ok(buf.get_u8() as u64),
        2 => Ok((buf.get_u16() & 0x3FFF) as u64),
        4 => Ok((buf.get_u32() & 0x3FFFFFFF) as u64),
        8 => Ok(buf.get_u64() & 0x3FFFFFFFFFFFFFFF),
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
use oreno_quic::frame::{Frame, FrameType, FrameError};
use bytes::{Bytes, BytesMut};

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
fn test_varint_encoding_through_connection_close() {
    // Test varint encoding by using different error codes in CONNECTION_CLOSE frames
    let test_cases = vec![
        (0, "1 byte varint"),                 // 1 byte
        (63, "1 byte max varint"),            // 1 byte max
        (64, "2 byte varint"),                // 2 bytes
        (16383, "2 byte max varint"),         // 2 bytes max
        (16384, "4 byte varint"),             // 4 bytes
        (1073741823, "4 byte max varint"),    // 4 bytes max
        (1073741824, "8 byte varint"),        // 8 bytes
    ];

    for (value, description) in test_cases {
        let frame = Frame::ConnectionClose {
            error_code: value,
            reason: description.to_string(),
        };
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        
        let mut bytes = buf.freeze();
        let decoded = Frame::decode(&mut bytes)
            .unwrap_or_else(|e| panic!("Failed to decode value {}: {:?}", value, e));
            
        match decoded {
            Frame::ConnectionClose { error_code, reason } => {
                assert_eq!(error_code, value, "Value {} should decode correctly", value);
                assert_eq!(reason, description);
            }
            _ => panic!("Expected ConnectionClose frame"),
        }
    }
}

#[test]
fn test_frame_types() {
    assert_eq!(FrameType::Padding as u8, 0x00);
    assert_eq!(FrameType::Ping as u8, 0x01);
    assert_eq!(FrameType::Crypto as u8, 0x06);
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

#[test]
fn test_crypto_frame_encode_decode() {
    let crypto_data = Bytes::from_static(b"Hello, TLS handshake data!");
    let frame = Frame::Crypto {
        offset: 42,
        data: crypto_data.clone(),
    };
    
    let mut buf = BytesMut::new();
    frame.encode(&mut buf).unwrap();
    
    let mut bytes = buf.freeze();
    let decoded = Frame::decode(&mut bytes).unwrap();
    
    match decoded {
        Frame::Crypto { offset, data } => {
            assert_eq!(offset, 42);
            assert_eq!(data, crypto_data);
        }
        _ => panic!("Expected Crypto frame"),
    }
}

#[test]
fn test_crypto_frame_empty_data() {
    let frame = Frame::Crypto {
        offset: 0,
        data: Bytes::new(),
    };
    
    let mut buf = BytesMut::new();
    frame.encode(&mut buf).unwrap();
    
    let mut bytes = buf.freeze();
    let decoded = Frame::decode(&mut bytes).unwrap();
    
    match decoded {
        Frame::Crypto { offset, data } => {
            assert_eq!(offset, 0);
            assert_eq!(data.len(), 0);
        }
        _ => panic!("Expected Crypto frame"),
    }
}

#[test]
fn test_crypto_frame_large_offset() {
    let crypto_data = Bytes::from_static(b"TLS data");
    let large_offset = 0x3FFFFFFFFFFFFFFF; // Max varint value
    let frame = Frame::Crypto {
        offset: large_offset,
        data: crypto_data.clone(),
    };
    
    let mut buf = BytesMut::new();
    frame.encode(&mut buf).unwrap();
    
    let mut bytes = buf.freeze();
    let decoded = Frame::decode(&mut bytes).unwrap();
    
    match decoded {
        Frame::Crypto { offset, data } => {
            assert_eq!(offset, large_offset);
            assert_eq!(data, crypto_data);
        }
        _ => panic!("Expected Crypto frame"),
    }
}
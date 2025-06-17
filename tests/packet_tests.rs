use oreno_quic::packet::{ConnectionId, PacketHeader, LongHeader, ShortHeader, PacketType};
use bytes::{Bytes, BytesMut};

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
    // We need to test the internal functions, but they're private.
    // Instead, we'll test through the public API by encoding/decoding headers with different packet numbers
    let test_cases = vec![
        (0, 1),                 // 1 byte
        (63, 1),                // 1 byte max
        (64, 2),                // 2 bytes
        (16383, 2),             // 2 bytes max
        (16384, 4),             // 4 bytes
        (1073741823, 4),        // 4 bytes max
        (1073741824, 8),        // 8 bytes
    ];

    for (packet_num, _expected_len) in test_cases {
        let header = PacketHeader::Long(LongHeader {
            packet_type: PacketType::Initial,
            version: 1,
            dest_conn_id: ConnectionId::new(vec![1, 2, 3, 4]),
            src_conn_id: ConnectionId::new(vec![5, 6, 7, 8]),
            packet_number: packet_num,
        });

        let mut buf = BytesMut::new();
        header.encode(&mut buf).unwrap();

        let mut bytes = buf.freeze();
        let decoded = PacketHeader::decode(&mut bytes).unwrap();

        match decoded {
            PacketHeader::Long(decoded_header) => {
                assert_eq!(decoded_header.packet_number, packet_num, "Packet number {} should decode correctly", packet_num);
            }
            _ => panic!("Expected Long header"),
        }
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
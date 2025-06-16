use oreno_quic::connection::{Connection, ConnectionState};
use oreno_quic::frame::Frame;
use oreno_quic::packet::{ConnectionId, PacketHeader};
use bytes::Bytes;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn test_client_server_ping_pong() {
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server_socket = UdpSocket::bind(server_addr).await.unwrap();
    let actual_server_addr = server_socket.local_addr().unwrap();

    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_socket.local_addr().unwrap();

    // Create client connection
    let mut client_conn = Connection::new_client(actual_server_addr);
    
    // Send PING from client
    let ping_packet = client_conn.create_initial_packet(vec![Frame::Ping]).unwrap();
    client_socket.send_to(&ping_packet, actual_server_addr).await.unwrap();

    // Server receives and processes packet
    let mut buf = vec![0u8; 1500];
    let (len, peer_addr) = timeout(Duration::from_millis(100), server_socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    
    assert_eq!(peer_addr, client_addr);
    
    let mut packet_data = Bytes::copy_from_slice(&buf[..len]);
    let header = PacketHeader::decode(&mut packet_data).unwrap();
    
    // Extract connection ID for server
    let src_conn_id = match &header {
        PacketHeader::Long(h) => h.src_conn_id.clone(),
        _ => panic!("Expected long header"),
    };
    
    // Create server connection
    let mut server_conn = Connection::new_server(peer_addr, src_conn_id);
    
    // Decode frame
    let frame = Frame::decode(&mut packet_data).unwrap();
    assert!(matches!(frame, Frame::Ping));
    
    // Server sends PING response
    let pong_packet = server_conn.create_initial_packet(vec![Frame::Ping]).unwrap();
    server_socket.send_to(&pong_packet, peer_addr).await.unwrap();
    
    // Client receives response
    let (len, _) = timeout(Duration::from_millis(100), client_socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    
    let mut response_data = Bytes::copy_from_slice(&buf[..len]);
    let _response_header = PacketHeader::decode(&mut response_data).unwrap();
    let response_frame = Frame::decode(&mut response_data).unwrap();
    
    assert!(matches!(response_frame, Frame::Ping));
}

#[tokio::test]
async fn test_connection_close() {
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server_socket = UdpSocket::bind(server_addr).await.unwrap();
    let actual_server_addr = server_socket.local_addr().unwrap();

    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_socket.local_addr().unwrap();

    // Create client connection
    let mut client_conn = Connection::new_client(actual_server_addr);
    
    // Send CONNECTION_CLOSE from client
    let close_packet = client_conn.close("Client disconnect".to_string()).unwrap();
    client_socket.send_to(&close_packet, actual_server_addr).await.unwrap();

    // Server receives and processes packet
    let mut buf = vec![0u8; 1500];
    let (len, peer_addr) = timeout(Duration::from_millis(100), server_socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    
    assert_eq!(peer_addr, client_addr);
    
    let mut packet_data = Bytes::copy_from_slice(&buf[..len]);
    let header = PacketHeader::decode(&mut packet_data).unwrap();
    
    // Extract connection ID for server
    let src_conn_id = match &header {
        PacketHeader::Long(h) => h.src_conn_id.clone(),
        _ => panic!("Expected long header"),
    };
    
    // Create server connection
    let mut server_conn = Connection::new_server(peer_addr, src_conn_id);
    
    // Decode frame
    let frame = Frame::decode(&mut packet_data).unwrap();
    match frame {
        Frame::ConnectionClose { error_code, reason } => {
            assert_eq!(error_code, 0);
            assert_eq!(reason, "Client disconnect");
        }
        _ => panic!("Expected ConnectionClose frame"),
    }
    
    // Verify client is in closing state
    assert_eq!(client_conn.state, ConnectionState::Closing);
    
    // Server responds with its own CONNECTION_CLOSE
    server_conn.handle_state_transition(ConnectionState::Closed);
    let server_close = server_conn.close("Server acknowledged".to_string()).unwrap();
    server_socket.send_to(&server_close, peer_addr).await.unwrap();
}

#[tokio::test]
async fn test_packet_with_multiple_frames() {
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server_socket = UdpSocket::bind(server_addr).await.unwrap();
    let actual_server_addr = server_socket.local_addr().unwrap();

    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Create client connection
    let mut client_conn = Connection::new_client(actual_server_addr);
    
    // Send packet with multiple frames
    let frames = vec![
        Frame::Padding { length: 5 },
        Frame::Ping,
        Frame::Padding { length: 3 },
    ];
    let packet = client_conn.create_initial_packet(frames).unwrap();
    client_socket.send_to(&packet, actual_server_addr).await.unwrap();

    // Server receives and processes packet
    let mut buf = vec![0u8; 1500];
    let (len, _) = timeout(Duration::from_millis(100), server_socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    
    let mut packet_data = Bytes::copy_from_slice(&buf[..len]);
    let _header = PacketHeader::decode(&mut packet_data).unwrap();
    
    // Decode all frames
    let mut frame_count = 0;
    let mut found_ping = false;
    let mut total_padding = 0;
    
    while !packet_data.is_empty() {
        let frame = Frame::decode(&mut packet_data).unwrap();
        frame_count += 1;
        
        match frame {
            Frame::Ping => found_ping = true,
            Frame::Padding { length } => total_padding += length,
            _ => {}
        }
    }
    
    assert_eq!(frame_count, 3);
    assert!(found_ping);
    assert_eq!(total_padding, 8); // 5 + 3
}

#[tokio::test]
async fn test_invalid_packet_handling() {
    let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let actual_server_addr = server_socket.local_addr().unwrap();

    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Send invalid packet (too short)
    let invalid_packet = vec![0x80]; // Long header flag but truncated
    client_socket.send_to(&invalid_packet, actual_server_addr).await.unwrap();

    // Server receives packet
    let mut buf = vec![0u8; 1500];
    let (len, _) = timeout(Duration::from_millis(100), server_socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    
    let mut packet_data = Bytes::copy_from_slice(&buf[..len]);
    
    // Should fail to decode
    assert!(PacketHeader::decode(&mut packet_data).is_err());
}

#[tokio::test]
async fn test_large_connection_id() {
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server_socket = UdpSocket::bind(server_addr).await.unwrap();
    let actual_server_addr = server_socket.local_addr().unwrap();

    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Create client connection with large connection ID
    let mut client_conn = Connection::new_client(actual_server_addr);
    client_conn.remote_conn_id = Some(ConnectionId::new(vec![1; 20])); // 20 byte conn ID
    
    let ping_packet = client_conn.create_initial_packet(vec![Frame::Ping]).unwrap();
    client_socket.send_to(&ping_packet, actual_server_addr).await.unwrap();

    // Server receives and processes packet
    let mut buf = vec![0u8; 1500];
    let (len, _) = timeout(Duration::from_millis(100), server_socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    
    let mut packet_data = Bytes::copy_from_slice(&buf[..len]);
    let header = PacketHeader::decode(&mut packet_data).unwrap();
    
    match header {
        PacketHeader::Long(h) => {
            assert_eq!(h.dest_conn_id.len(), 20);
            assert_eq!(h.src_conn_id.len(), 8); // Client's local conn ID
        }
        _ => panic!("Expected long header"),
    }
}

#[test]
fn test_connection_id_operations() {
    let conn_id1 = ConnectionId::new(vec![1, 2, 3, 4]);
    let conn_id2 = ConnectionId::random(8);
    let empty_conn_id = ConnectionId::new(vec![]);
    
    assert_eq!(conn_id1.len(), 4);
    assert_eq!(conn_id2.len(), 8);
    assert_eq!(empty_conn_id.len(), 0);
    
    assert!(!conn_id1.is_empty());
    assert!(!conn_id2.is_empty());
    assert!(empty_conn_id.is_empty());
    
    // Random IDs should be different
    let random1 = ConnectionId::random(16);
    let random2 = ConnectionId::random(16);
    assert_ne!(random1.data, random2.data);
}

#[test]
fn test_frame_roundtrip() {
    let frames = vec![
        Frame::Ping,
        Frame::Padding { length: 10 },
        Frame::ConnectionClose {
            error_code: 12345,
            reason: "Test error message".to_string(),
        },
    ];
    
    for original_frame in frames {
        let mut buf = bytes::BytesMut::new();
        original_frame.encode(&mut buf).unwrap();
        
        let mut bytes = buf.freeze();
        let decoded_frame = Frame::decode(&mut bytes).unwrap();
        
        assert_eq!(std::mem::discriminant(&original_frame), std::mem::discriminant(&decoded_frame));
        
        match (&original_frame, &decoded_frame) {
            (Frame::Ping, Frame::Ping) => {},
            (Frame::Padding { length: l1 }, Frame::Padding { length: l2 }) => {
                assert_eq!(l1, l2);
            },
            (
                Frame::ConnectionClose { error_code: e1, reason: r1 },
                Frame::ConnectionClose { error_code: e2, reason: r2 }
            ) => {
                assert_eq!(e1, e2);
                assert_eq!(r1, r2);
            },
            _ => panic!("Frame type mismatch"),
        }
    }
}
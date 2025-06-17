use oreno_quic::connection::{Connection, ConnectionManager, ConnectionState, ConnectionError};
use oreno_quic::frame::Frame;
use oreno_quic::packet::ConnectionId;
use std::net::SocketAddr;

fn get_test_addr() -> SocketAddr {
    "127.0.0.1:8080".parse().unwrap()
}

#[test]
fn test_connection_new_client() {
    let addr = get_test_addr();
    let conn = Connection::new_client(addr);
    
    assert_eq!(conn.state, ConnectionState::Initial);
    assert_eq!(conn.remote_addr, addr);
    assert_eq!(conn.local_conn_id.len(), 8);
    assert!(conn.remote_conn_id.is_none());
    assert_eq!(conn.packet_number, 0);
    assert_eq!(conn.version, 1);
}

#[test]
fn test_connection_new_server() {
    let addr = get_test_addr();
    let remote_conn_id = ConnectionId::new(vec![1, 2, 3, 4]);
    let conn = Connection::new_server(addr, remote_conn_id.clone());
    
    assert_eq!(conn.state, ConnectionState::Initial);
    assert_eq!(conn.remote_addr, addr);
    assert_eq!(conn.local_conn_id.len(), 8);
    assert_eq!(conn.remote_conn_id.unwrap().data, remote_conn_id.data);
    assert_eq!(conn.packet_number, 0);
    assert_eq!(conn.version, 1);
}

#[test]
fn test_packet_number_increment() {
    let mut conn = Connection::new_client(get_test_addr());
    
    assert_eq!(conn.next_packet_number(), 0);
    assert_eq!(conn.next_packet_number(), 1);
    assert_eq!(conn.next_packet_number(), 2);
    assert_eq!(conn.packet_number, 3);
}

#[test]
fn test_connection_state_transitions() {
    let mut conn = Connection::new_client(get_test_addr());
    
    assert_eq!(conn.state, ConnectionState::Initial);
    assert!(!conn.is_closed());
    
    conn.handle_state_transition(ConnectionState::Handshake);
    assert_eq!(conn.state, ConnectionState::Handshake);
    assert!(!conn.is_closed());
    
    conn.handle_state_transition(ConnectionState::Established);
    assert_eq!(conn.state, ConnectionState::Established);
    assert!(!conn.is_closed());
    
    conn.handle_state_transition(ConnectionState::Closing);
    assert_eq!(conn.state, ConnectionState::Closing);
    assert!(!conn.is_closed());
    
    conn.handle_state_transition(ConnectionState::Closed);
    assert_eq!(conn.state, ConnectionState::Closed);
    assert!(conn.is_closed());
}

#[test]
fn test_create_initial_packet() {
    let mut conn = Connection::new_client(get_test_addr());
    conn.remote_conn_id = Some(ConnectionId::new(vec![5, 6, 7, 8]));
    
    let frames = vec![Frame::Ping];
    let packet = conn.create_initial_packet(frames).unwrap();
    
    assert!(!packet.is_empty());
    assert_eq!(conn.packet_number, 1); // Should increment
}

#[test]
fn test_create_handshake_packet() {
    let mut conn = Connection::new_client(get_test_addr());
    conn.remote_conn_id = Some(ConnectionId::new(vec![5, 6, 7, 8]));
    
    let frames = vec![Frame::Ping];
    let packet = conn.create_handshake_packet(frames).unwrap();
    
    assert!(!packet.is_empty());
    assert_eq!(conn.packet_number, 1); // Should increment
}

#[test]
fn test_close_connection() {
    let mut conn = Connection::new_client(get_test_addr());
    conn.remote_conn_id = Some(ConnectionId::new(vec![1, 2, 3, 4]));
    
    let close_packet = conn.close("Test close".to_string()).unwrap();
    
    assert!(!close_packet.is_empty());
    assert_eq!(conn.state, ConnectionState::Closing);
}

#[test]
fn test_connection_manager() {
    let mut manager = ConnectionManager::new();
    let addr = get_test_addr();
    let conn_id = vec![1, 2, 3, 4];
    let conn = Connection::new_client(addr);
    
    // Add connection
    manager.add_connection(conn_id.clone(), conn);
    assert!(manager.get_connection(&conn_id).is_some());
    
    // Test connection retrieval
    {
        let retrieved_conn = manager.get_connection(&conn_id).unwrap();
        assert_eq!(retrieved_conn.remote_addr, addr);
        assert_eq!(retrieved_conn.state, ConnectionState::Initial);
    }
    
    // Remove connection
    manager.remove_connection(&conn_id);
    assert!(manager.get_connection(&conn_id).is_none());
}

#[test]
fn test_connection_manager_multiple_connections() {
    let mut manager = ConnectionManager::new();
    let addr1 = get_test_addr();
    let addr2 = "127.0.0.1:8081".parse().unwrap();
    
    let conn_id1 = vec![1, 2, 3, 4];
    let conn_id2 = vec![5, 6, 7, 8];
    
    let conn1 = Connection::new_client(addr1);
    let conn2 = Connection::new_client(addr2);
    
    manager.add_connection(conn_id1.clone(), conn1);
    manager.add_connection(conn_id2.clone(), conn2);
    
    assert!(manager.get_connection(&conn_id1).is_some());
    assert!(manager.get_connection(&conn_id2).is_some());
    
    // Verify they are different connections
    let addr1 = manager.get_connection(&conn_id1).unwrap().remote_addr;
    let addr2 = manager.get_connection(&conn_id2).unwrap().remote_addr;
    assert_ne!(addr1, addr2);
}

#[test]
fn test_encode_packet_with_multiple_frames() {
    let mut conn = Connection::new_client(get_test_addr());
    conn.remote_conn_id = Some(ConnectionId::new(vec![1, 2, 3, 4]));
    
    let frames = vec![
        Frame::Ping,
        Frame::Padding { length: 10 },
        Frame::ConnectionClose {
            error_code: 0,
            reason: "Test".to_string(),
        },
    ];
    
    let packet = conn.create_initial_packet(frames).unwrap();
    assert!(!packet.is_empty());
    // Should contain all frames encoded
    assert!(packet.len() > 20); // Header + frames should be significant size
}

#[test]
fn test_connection_without_remote_conn_id() {
    let mut conn = Connection::new_client(get_test_addr());
    // Don't set remote_conn_id
    
    let frames = vec![Frame::Ping];
    let packet = conn.create_initial_packet(frames).unwrap();
    
    assert!(!packet.is_empty());
    // Should work with empty destination connection ID
}

#[test]
fn test_connection_states_enum() {
    let states = vec![
        ConnectionState::Initial,
        ConnectionState::Handshake,
        ConnectionState::Established,
        ConnectionState::Closing,
        ConnectionState::Closed,
    ];
    
    // Test that all states are different
    for (i, state1) in states.iter().enumerate() {
        for (j, state2) in states.iter().enumerate() {
            if i != j {
                assert_ne!(state1, state2);
            }
        }
    }
}

#[test]
fn test_connection_error_display() {
    let errors = vec![
        ConnectionError::PacketEncoding,
        ConnectionError::FrameEncoding,
        ConnectionError::InvalidState,
        ConnectionError::TlsSetupFailed,
        ConnectionError::TlsHandshakeFailed,
        ConnectionError::TlsNotSetup,
    ];
    
    for error in errors {
        let error_string = error.to_string();
        assert!(!error_string.is_empty());
    }
}
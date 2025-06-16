use crate::packet::{ConnectionId, PacketHeader, LongHeader, PacketType};
use crate::frame::Frame;
use crate::tls::{TlsConfig, QuicClientTls, QuicServerTls};
use crate::crypto::QuicCrypto;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use bytes::{BytesMut, Bytes};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Initial,
    Handshake,
    Established,
    Closing,
    Closed,
}

#[derive(Debug)]
pub struct Connection {
    pub local_conn_id: ConnectionId,
    pub remote_conn_id: Option<ConnectionId>,
    pub state: ConnectionState,
    pub remote_addr: SocketAddr,
    pub packet_number: u64,
    pub version: u32,
    pub is_client: bool,
    pub crypto: QuicCrypto,
    pub tls_config: Option<Arc<TlsConfig>>,
    pub client_tls: Option<QuicClientTls>,
    pub server_tls: Option<QuicServerTls>,
}

impl Connection {
    pub fn new_client(remote_addr: SocketAddr) -> Self {
        let mut crypto = QuicCrypto::new();
        let local_conn_id = ConnectionId::random(8);
        
        // Setup initial encryption keys
        let _ = crypto.setup_initial_keys(&local_conn_id.data, true);
        
        Self {
            local_conn_id,
            remote_conn_id: None,
            state: ConnectionState::Initial,
            remote_addr,
            packet_number: 0,
            version: 1,
            is_client: true,
            crypto,
            tls_config: None,
            client_tls: None,
            server_tls: None,
        }
    }
    
    pub fn new_server(remote_addr: SocketAddr, remote_conn_id: ConnectionId) -> Self {
        let mut crypto = QuicCrypto::new();
        let local_conn_id = ConnectionId::random(8);
        
        // Setup initial encryption keys
        let _ = crypto.setup_initial_keys(&remote_conn_id.data, false);
        
        Self {
            local_conn_id,
            remote_conn_id: Some(remote_conn_id),
            state: ConnectionState::Initial,
            remote_addr,
            packet_number: 0,
            version: 1,
            is_client: false,
            crypto,
            tls_config: None,
            client_tls: None,
            server_tls: None,
        }
    }
    
    pub fn next_packet_number(&mut self) -> u64 {
        let pn = self.packet_number;
        self.packet_number += 1;
        pn
    }
    
    pub fn create_initial_packet(&mut self, frames: Vec<Frame>) -> Result<Vec<u8>, ConnectionError> {
        let header = PacketHeader::Long(LongHeader {
            packet_type: PacketType::Initial,
            version: self.version,
            dest_conn_id: self.remote_conn_id.clone().unwrap_or_else(|| ConnectionId::new(vec![])),
            src_conn_id: self.local_conn_id.clone(),
            packet_number: self.next_packet_number(),
        });
        
        self.encode_packet(header, frames)
    }
    
    pub fn create_handshake_packet(&mut self, frames: Vec<Frame>) -> Result<Vec<u8>, ConnectionError> {
        let header = PacketHeader::Long(LongHeader {
            packet_type: PacketType::Handshake,
            version: self.version,
            dest_conn_id: self.remote_conn_id.clone().unwrap_or_else(|| ConnectionId::new(vec![])),
            src_conn_id: self.local_conn_id.clone(),
            packet_number: self.next_packet_number(),
        });
        
        self.encode_packet(header, frames)
    }
    
    fn encode_packet(&self, header: PacketHeader, frames: Vec<Frame>) -> Result<Vec<u8>, ConnectionError> {
        let mut buf = BytesMut::new();
        
        header.encode(&mut buf).map_err(|_| ConnectionError::PacketEncoding)?;
        
        for frame in frames {
            frame.encode(&mut buf).map_err(|_| ConnectionError::FrameEncoding)?;
        }
        
        Ok(buf.to_vec())
    }
    
    pub fn handle_state_transition(&mut self, new_state: ConnectionState) {
        println!("Connection state: {:?} -> {:?}", self.state, new_state);
        self.state = new_state;
    }
    
    pub fn is_closed(&self) -> bool {
        matches!(self.state, ConnectionState::Closed)
    }
    
    pub fn setup_tls(&mut self, tls_config: Arc<TlsConfig>) -> Result<(), ConnectionError> {
        self.tls_config = Some(tls_config.clone());
        
        if self.is_client {
            let client_tls = QuicClientTls::new(tls_config.client_config.clone(), "localhost")
                .map_err(|_| ConnectionError::TlsSetupFailed)?;
            self.client_tls = Some(client_tls);
        } else {
            let server_tls = QuicServerTls::new(tls_config.server_config.clone())
                .map_err(|_| ConnectionError::TlsSetupFailed)?;
            self.server_tls = Some(server_tls);
        }
        
        Ok(())
    }
    
    pub fn start_tls_handshake(&mut self) -> Result<Vec<u8>, ConnectionError> {
        if self.is_client {
            if let Some(ref mut client_tls) = self.client_tls {
                let handshake_data = client_tls.get_handshake_data()
                    .map_err(|_| ConnectionError::TlsHandshakeFailed)?;
                
                if !handshake_data.is_empty() {
                    let crypto_frame = Frame::Crypto {
                        offset: 0,
                        data: Bytes::from(handshake_data),
                    };
                    
                    return self.create_initial_packet(vec![crypto_frame]);
                }
            }
        } else {
            if let Some(ref mut server_tls) = self.server_tls {
                let handshake_data = server_tls.get_handshake_data()
                    .map_err(|_| ConnectionError::TlsHandshakeFailed)?;
                
                if !handshake_data.is_empty() {
                    let crypto_frame = Frame::Crypto {
                        offset: 0,
                        data: Bytes::from(handshake_data),
                    };
                    
                    return self.create_initial_packet(vec![crypto_frame]);
                }
            }
        }
        
        Err(ConnectionError::TlsNotSetup)
    }
    
    pub fn process_crypto_frame(&mut self, crypto_frame: &Frame) -> Result<Option<Vec<u8>>, ConnectionError> {
        if let Frame::Crypto { offset: _, data } = crypto_frame {
            if self.is_client {
                if let Some(ref mut client_tls) = self.client_tls {
                    client_tls.process_handshake_data(data)
                        .map_err(|_| ConnectionError::TlsHandshakeFailed)?;
                    
                    if client_tls.is_handshake_complete() {
                        self.handle_state_transition(ConnectionState::Established);
                        return Ok(None);
                    }
                    
                    let response_data = client_tls.get_handshake_data()
                        .map_err(|_| ConnectionError::TlsHandshakeFailed)?;
                    
                    if !response_data.is_empty() {
                        let crypto_frame = Frame::Crypto {
                            offset: 0,
                            data: Bytes::from(response_data),
                        };
                        
                        let packet = self.create_handshake_packet(vec![crypto_frame])?;
                        return Ok(Some(packet));
                    }
                }
            } else {
                if let Some(ref mut server_tls) = self.server_tls {
                    server_tls.process_handshake_data(data)
                        .map_err(|_| ConnectionError::TlsHandshakeFailed)?;
                    
                    if server_tls.is_handshake_complete() {
                        self.handle_state_transition(ConnectionState::Established);
                        return Ok(None);
                    }
                    
                    let response_data = server_tls.get_handshake_data()
                        .map_err(|_| ConnectionError::TlsHandshakeFailed)?;
                    
                    if !response_data.is_empty() {
                        let crypto_frame = Frame::Crypto {
                            offset: 0,
                            data: Bytes::from(response_data),
                        };
                        
                        let packet = self.create_handshake_packet(vec![crypto_frame])?;
                        return Ok(Some(packet));
                    }
                }
            }
        }
        
        Ok(None)
    }
    
    pub fn is_tls_handshake_complete(&self) -> bool {
        if self.is_client {
            self.client_tls.as_ref().map_or(false, |tls| tls.is_handshake_complete())
        } else {
            self.server_tls.as_ref().map_or(false, |tls| tls.is_handshake_complete())
        }
    }
    
    pub fn close(&mut self, reason: String) -> Result<Vec<u8>, ConnectionError> {
        let frame = Frame::ConnectionClose {
            error_code: 0,
            reason,
        };
        
        self.handle_state_transition(ConnectionState::Closing);
        
        match self.state {
            ConnectionState::Initial | ConnectionState::Handshake => {
                self.create_initial_packet(vec![frame])
            }
            _ => {
                let header = PacketHeader::Long(LongHeader {
                    packet_type: PacketType::Initial,
                    version: self.version,
                    dest_conn_id: self.remote_conn_id.clone().unwrap_or_else(|| ConnectionId::new(vec![])),
                    src_conn_id: self.local_conn_id.clone(),
                    packet_number: self.next_packet_number(),
                });
                self.encode_packet(header, vec![frame])
            }
        }
    }
}

#[derive(Debug)]
pub struct ConnectionManager {
    connections: HashMap<Vec<u8>, Connection>,
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }
    
    pub fn get_connection(&mut self, conn_id: &[u8]) -> Option<&mut Connection> {
        self.connections.get_mut(conn_id)
    }
    
    pub fn add_connection(&mut self, conn_id: Vec<u8>, connection: Connection) {
        self.connections.insert(conn_id, connection);
    }
    
    pub fn remove_connection(&mut self, conn_id: &[u8]) {
        self.connections.remove(conn_id);
    }
}

#[derive(Debug)]
pub enum ConnectionError {
    PacketEncoding,
    FrameEncoding,
    InvalidState,
    TlsSetupFailed,
    TlsHandshakeFailed,
    TlsNotSetup,
}

impl std::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionError::PacketEncoding => write!(f, "Packet encoding error"),
            ConnectionError::FrameEncoding => write!(f, "Frame encoding error"),
            ConnectionError::InvalidState => write!(f, "Invalid connection state"),
            ConnectionError::TlsSetupFailed => write!(f, "TLS setup failed"),
            ConnectionError::TlsHandshakeFailed => write!(f, "TLS handshake failed"),
            ConnectionError::TlsNotSetup => write!(f, "TLS not setup"),
        }
    }
}

impl std::error::Error for ConnectionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::Frame;
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
        ];
        
        for error in errors {
            let error_string = error.to_string();
            assert!(!error_string.is_empty());
        }
    }
}
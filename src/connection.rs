use crate::packet::{ConnectionId, PacketHeader, LongHeader, PacketType};
use crate::frame::Frame;
use std::collections::HashMap;
use std::net::SocketAddr;
use bytes::BytesMut;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Initial,
    Handshake,
    Established,
    Closing,
    Closed,
}

#[derive(Debug, Clone)]
pub struct Connection {
    pub local_conn_id: ConnectionId,
    pub remote_conn_id: Option<ConnectionId>,
    pub state: ConnectionState,
    pub remote_addr: SocketAddr,
    pub packet_number: u64,
    pub version: u32,
}

impl Connection {
    pub fn new_client(remote_addr: SocketAddr) -> Self {
        Self {
            local_conn_id: ConnectionId::random(8),
            remote_conn_id: None,
            state: ConnectionState::Initial,
            remote_addr,
            packet_number: 0,
            version: 1,
        }
    }
    
    pub fn new_server(remote_addr: SocketAddr, remote_conn_id: ConnectionId) -> Self {
        Self {
            local_conn_id: ConnectionId::random(8),
            remote_conn_id: Some(remote_conn_id),
            state: ConnectionState::Initial,
            remote_addr,
            packet_number: 0,
            version: 1,
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
}

impl std::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionError::PacketEncoding => write!(f, "Packet encoding error"),
            ConnectionError::FrameEncoding => write!(f, "Frame encoding error"),
            ConnectionError::InvalidState => write!(f, "Invalid connection state"),
        }
    }
}

impl std::error::Error for ConnectionError {}
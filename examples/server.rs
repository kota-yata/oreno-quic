use oreno_quic::connection::{Connection, ConnectionManager, ConnectionState};
use oreno_quic::frame::Frame;
use oreno_quic::packet::PacketHeader;
use oreno_quic::tls::TlsConfig;
use bytes::Bytes;
use tokio::net::UdpSocket;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting QUIC server with TLS 1.3...");
    
    // Setup TLS configuration with self-signed certificates
    let tls_config = Arc::new(TlsConfig::new()?);
    println!("Generated self-signed certificate for localhost");
    
    let socket = UdpSocket::bind("127.0.0.1:4433").await?;
    let local_addr = socket.local_addr()?;
    println!("QUIC server listening on {}", local_addr);
    println!("Waiting for clients...");
    
    let mut connection_manager = ConnectionManager::new();
    let mut buf = vec![0u8; 1500];
    
    loop {
        let (len, peer_addr) = socket.recv_from(&mut buf).await?;
        println!("\n[{}] Received {} bytes", peer_addr, len);
        
        let mut packet_data = Bytes::copy_from_slice(&buf[..len]);
        
        match PacketHeader::decode(&mut packet_data) {
            Ok(header) => {
                println!("[{}] Decoded packet header: {:?}", peer_addr, header);
                
                let conn_id = match &header {
                    PacketHeader::Long(h) => &h.src_conn_id,
                    PacketHeader::Short(h) => &h.dest_conn_id,
                };
                
                let connection_exists = connection_manager.get_connection(&conn_id.data).is_some();
                
                if !connection_exists {
                    println!("[{}] Creating new connection with TLS", peer_addr);
                    let mut new_connection = Connection::new_server(peer_addr, conn_id.clone());
                    
                    // Setup TLS for the new connection
                    if let Err(e) = new_connection.setup_tls(tls_config.clone()) {
                        println!("[{}] Failed to setup TLS: {}", peer_addr, e);
                        continue;
                    }
                    
                    connection_manager.add_connection(conn_id.data.clone(), new_connection);
                }
                
                let connection = connection_manager.get_connection(&conn_id.data).unwrap();
                
                while !packet_data.is_empty() {
                    match Frame::decode(&mut packet_data) {
                        Ok(frame) => {
                            println!("[{}] Decoded frame: {:?}", peer_addr, frame);
                            
                            match frame {
                                Frame::Ping => {
                                    println!("[{}] Received PING, sending PONG", peer_addr);
                                    let pong_packet = connection.create_initial_packet(vec![Frame::Ping])?;
                                    socket.send_to(&pong_packet, peer_addr).await?;
                                    println!("[{}] Sent PONG response", peer_addr);
                                }
                                Frame::ConnectionClose { error_code, reason } => {
                                    println!("[{}] Connection close received: code={}, reason=\"{}\"", 
                                        peer_addr, error_code, reason);
                                    connection.handle_state_transition(ConnectionState::Closed);
                                    connection_manager.remove_connection(&conn_id.data);
                                    println!("[{}] Connection closed and removed", peer_addr);
                                    break;
                                }
                                Frame::Padding { length } => {
                                    println!("[{}] Received {} bytes of padding", peer_addr, length);
                                }
                                Frame::Crypto { offset, ref data } => {
                                    println!("[{}] Received CRYPTO frame: offset={}, data_len={}", peer_addr, offset, data.len());
                                    
                                    // Process TLS handshake data
                                    match connection.process_crypto_frame(&frame) {
                                        Ok(Some(response_packet)) => {
                                            println!("[{}] Sending TLS handshake response", peer_addr);
                                            socket.send_to(&response_packet, peer_addr).await?;
                                        }
                                        Ok(None) => {
                                            if connection.is_tls_handshake_complete() {
                                                println!("[{}] TLS handshake completed successfully!", peer_addr);
                                            }
                                        }
                                        Err(e) => {
                                            println!("[{}] TLS handshake error: {}", peer_addr, e);
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            println!("[{}] Frame decode error: {}", peer_addr, e);
                            break;
                        }
                    }
                }
                
                // Connection is already in the manager, no need to re-add
            }
            Err(e) => {
                println!("[{}] Packet decode error: {}", peer_addr, e);
            }
        }
    }
}
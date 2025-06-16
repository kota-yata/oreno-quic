mod packet;
mod connection;
mod frame;

use crate::connection::{Connection, ConnectionManager, ConnectionState};
use crate::frame::Frame;
use crate::packet::PacketHeader;
use bytes::Bytes;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting minimal QUIC implementation...");
    
    let socket = UdpSocket::bind("127.0.0.1:4433").await?;
    let local_addr = socket.local_addr()?;
    println!("QUIC server listening on {}", local_addr);
    
    let mut connection_manager = ConnectionManager::new();
    let mut buf = vec![0u8; 1500];
    
    loop {
        let (len, peer_addr) = socket.recv_from(&mut buf).await?;
        println!("Received {} bytes from {}", len, peer_addr);
        
        let mut packet_data = Bytes::copy_from_slice(&buf[..len]);
        
        match PacketHeader::decode(&mut packet_data) {
            Ok(header) => {
                println!("Decoded packet header: {:?}", header);
                
                let conn_id = match &header {
                    PacketHeader::Long(h) => &h.src_conn_id,
                    PacketHeader::Short(h) => &h.dest_conn_id,
                };
                
                let mut connection = connection_manager
                    .get_connection(&conn_id.data)
                    .map(|c| c.clone())
                    .unwrap_or_else(|| {
                        println!("Creating new connection for peer {}", peer_addr);
                        Connection::new_server(peer_addr, conn_id.clone())
                    });
                
                while !packet_data.is_empty() {
                    match Frame::decode(&mut packet_data) {
                        Ok(frame) => {
                            println!("Decoded frame: {:?}", frame);
                            
                            match frame {
                                Frame::Ping => {
                                    println!("Received PING, sending PONG");
                                    let pong_packet = connection.create_initial_packet(vec![Frame::Ping])?;
                                    socket.send_to(&pong_packet, peer_addr).await?;
                                }
                                Frame::ConnectionClose { .. } => {
                                    println!("Connection close received");
                                    connection.handle_state_transition(ConnectionState::Closed);
                                    connection_manager.remove_connection(&conn_id.data);
                                    break;
                                }
                                Frame::Padding { .. } => {
                                    // Just padding, ignore
                                }
                            }
                        }
                        Err(e) => {
                            println!("Frame decode error: {}", e);
                            break;
                        }
                    }
                }
                
                if !connection.is_closed() {
                    connection_manager.add_connection(conn_id.data.clone(), connection);
                }
            }
            Err(e) => {
                println!("Packet decode error: {}", e);
            }
        }
    }
}
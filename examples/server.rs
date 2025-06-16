use oreno_quic::connection::{Connection, ConnectionManager, ConnectionState};
use oreno_quic::frame::Frame;
use oreno_quic::packet::PacketHeader;
use bytes::Bytes;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting QUIC server...");
    
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
                
                let mut connection = connection_manager
                    .get_connection(&conn_id.data)
                    .map(|c| c.clone())
                    .unwrap_or_else(|| {
                        println!("[{}] Creating new connection", peer_addr);
                        Connection::new_server(peer_addr, conn_id.clone())
                    });
                
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
                            }
                        }
                        Err(e) => {
                            println!("[{}] Frame decode error: {}", peer_addr, e);
                            break;
                        }
                    }
                }
                
                if !connection.is_closed() {
                    connection_manager.add_connection(conn_id.data.clone(), connection);
                }
            }
            Err(e) => {
                println!("[{}] Packet decode error: {}", peer_addr, e);
            }
        }
    }
}
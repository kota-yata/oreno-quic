use oreno_quic::connection::Connection;
use oreno_quic::frame::Frame;
use oreno_quic::tls::TlsConfig;
use oreno_quic::packet::PacketHeader;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_addr: SocketAddr = "127.0.0.1:4433".parse()?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;
    
    println!("QUIC client started on {}", local_addr);
    println!("Connecting to server at {} with TLS 1.3", server_addr);
    
    // Setup TLS configuration
    let tls_config = Arc::new(TlsConfig::new()?);
    println!("Client TLS configuration ready");
    
    let mut connection = Connection::new_client(server_addr);
    
    // Setup TLS for the connection
    connection.setup_tls(tls_config)?;
    println!("TLS setup completed for client connection");
    
    // Start TLS handshake
    println!("Starting TLS handshake...");
    let handshake_packet = connection.start_tls_handshake()?;
    socket.send_to(&handshake_packet, server_addr).await?;
    println!("Sent TLS ClientHello");
    
    // Wait for TLS response
    let mut buf = vec![0u8; 1500];
    let (len, peer_addr) = socket.recv_from(&mut buf).await?;
    println!("Received {} bytes from {}", len, peer_addr);
    
    // Process the server's response
    let mut packet_data = Bytes::copy_from_slice(&buf[..len]);
    match PacketHeader::decode(&mut packet_data) {
        Ok(header) => {
            println!("Decoded packet header: {:?}", header);
            
            while !packet_data.is_empty() {
                match Frame::decode(&mut packet_data) {
                    Ok(frame) => {
                        println!("Decoded frame: {:?}", frame);
                        
                        if let Frame::Crypto { .. } = frame {
                            match connection.process_crypto_frame(&frame) {
                                Ok(Some(response_packet)) => {
                                    println!("Sending TLS handshake response");
                                    socket.send_to(&response_packet, server_addr).await?;
                                }
                                Ok(None) => {
                                    if connection.is_tls_handshake_complete() {
                                        println!("TLS handshake completed successfully!");
                                    }
                                }
                                Err(e) => {
                                    println!("TLS handshake error: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        println!("Frame decode error: {}", e);
                        break;
                    }
                }
            }
        }
        Err(e) => {
            println!("Packet decode error: {}", e);
        }
    }
    
    // Send a PING after TLS handshake
    println!("Sending PING over TLS-protected connection");
    let ping_packet = connection.create_initial_packet(vec![Frame::Ping])?;
    socket.send_to(&ping_packet, server_addr).await?;
    println!("Sent PING to server");
    
    // Wait for PING response
    let (len, peer_addr) = socket.recv_from(&mut buf).await?;
    println!("Received {} bytes PING response from {}", len, peer_addr);
    
    // Send connection close
    let close_packet = connection.close("Client disconnecting".to_string())?;
    socket.send_to(&close_packet, server_addr).await?;
    println!("Sent CONNECTION_CLOSE to server");
    
    Ok(())
}
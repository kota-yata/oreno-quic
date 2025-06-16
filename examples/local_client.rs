use oreno_quic::connection::Connection;
use oreno_quic::frame::Frame;
use oreno_quic::tls::TlsConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_addr: SocketAddr = "127.0.0.1:4433".parse()?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;
    
    println!("QUIC local client with TLS started on {}", local_addr);
    println!("Connecting to local server at {} with TLS 1.3", server_addr);
    
    // Setup TLS configuration
    let tls_config = Arc::new(TlsConfig::new()?);
    println!("Client TLS configuration ready");
    
    let mut connection = Connection::new_client(server_addr);
    
    // Setup TLS for the connection
    connection.setup_tls(tls_config)?;
    println!("TLS setup completed for client connection");
    
    // Start TLS handshake first
    println!("Starting TLS handshake...");
    let handshake_packet = connection.start_tls_handshake()?;
    socket.send_to(&handshake_packet, server_addr).await?;
    println!("TLS ClientHello sent");
    
    // Wait for TLS handshake response
    println!("Waiting for TLS ServerHello...");
    let mut buf = vec![0u8; 1500];
    let (len, peer_addr) = socket.recv_from(&mut buf).await?;
    println!("Received {} bytes TLS response from {}", len, peer_addr);
    
    // Now send PING frame
    println!("Sending PING to server...");
    let ping_packet = connection.create_initial_packet(vec![Frame::Ping])?;
    socket.send_to(&ping_packet, server_addr).await?;
    println!("PING sent");
    
    // Wait for PING response
    println!("Waiting for PONG response...");
    let (len, peer_addr) = socket.recv_from(&mut buf).await?;
    println!("Received {} bytes PONG from {}", len, peer_addr);
    
    // Give some time before closing
    sleep(Duration::from_millis(100)).await;
    
    // Send connection close
    println!("Sending CONNECTION_CLOSE to server...");
    let close_packet = connection.close("Local client disconnecting".to_string())?;
    socket.send_to(&close_packet, server_addr).await?;
    println!("CONNECTION_CLOSE sent");
    
    println!("Client finished successfully");
    Ok(())
}
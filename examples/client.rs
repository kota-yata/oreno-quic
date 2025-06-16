use oreno_quic::connection::Connection;
use oreno_quic::frame::Frame;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_addr: SocketAddr = "127.0.0.1:4433".parse()?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;
    
    println!("QUIC client started on {}", local_addr);
    println!("Connecting to server at {}", server_addr);
    
    let mut connection = Connection::new_client(server_addr);
    
    // Send initial packet with PING frame
    let ping_packet = connection.create_initial_packet(vec![Frame::Ping])?;
    socket.send_to(&ping_packet, server_addr).await?;
    println!("Sent PING to server");
    
    // Wait for response
    let mut buf = vec![0u8; 1500];
    let (len, peer_addr) = socket.recv_from(&mut buf).await?;
    println!("Received {} bytes from {}", len, peer_addr);
    
    // Send connection close
    let close_packet = connection.close("Client disconnecting".to_string())?;
    socket.send_to(&close_packet, server_addr).await?;
    println!("Sent CONNECTION_CLOSE to server");
    
    Ok(())
}
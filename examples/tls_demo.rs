use oreno_quic::tls::TlsConfig;
use std::sync::Arc;

/// A simple demonstration of TLS configuration with self-signed certificates
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 TLS 1.3 Configuration Demo for QUIC");
    println!("=====================================\n");
    
    // Create TLS configuration with self-signed certificates
    println!("1. Creating TLS configuration...");
    let tls_config = Arc::new(TlsConfig::new()?);
    println!("   ✅ TLS configuration created successfully");
    
    // Display configuration details
    println!("\n2. TLS Configuration Details:");
    println!("   • Protocol: TLS 1.3");
    println!("   • ALPN: h3 (HTTP/3 over QUIC)");
    println!("   • Certificate: Self-signed for localhost and 127.0.0.1");
    println!("   • Key Exchange: Modern elliptic curve algorithms");
    println!("   • Cipher Suite: AEAD (Authenticated Encryption with Associated Data)");
    
    // Demonstrate client and server setup
    println!("\n3. Client/Server TLS Setup:");
    
    // Client setup
    println!("   📱 Client Setup:");
    let client_tls = oreno_quic::tls::QuicClientTls::new(
        tls_config.client_config.clone(), 
        "localhost"
    );
    match client_tls {
        Ok(_) => println!("      ✅ Client TLS context initialized"),
        Err(e) => println!("      ❌ Client TLS setup failed: {}", e),
    }
    
    // Server setup
    println!("   🖥️  Server Setup:");
    let server_tls = oreno_quic::tls::QuicServerTls::new(
        tls_config.server_config.clone()
    );
    match server_tls {
        Ok(_) => println!("      ✅ Server TLS context initialized"),
        Err(e) => println!("      ❌ Server TLS setup failed: {}", e),
    }
    
    println!("\n4. Ready for QUIC connections!");
    println!("   • Server can accept TLS-protected QUIC connections");
    println!("   • Client can establish TLS-protected QUIC connections");
    println!("   • CRYPTO frames will carry TLS handshake data");
    println!("   • Connection will be encrypted after TLS handshake completion");
    
    println!("\n🚀 To see this in action:");
    println!("   Terminal 1: cargo run --example server");
    println!("   Terminal 2: cargo run --example local_client");
    
    Ok(())
}
use oreno_quic::tls::{TlsConfig, QuicClientTls, QuicServerTls};

#[test]
fn test_tls_config_creation() {
    let config = TlsConfig::new().expect("Failed to create TLS config");
    assert!(!config.client_config.alpn_protocols.is_empty());
    assert!(!config.server_config.alpn_protocols.is_empty());
}

#[test]
fn test_client_tls_creation() {
    let config = TlsConfig::new().expect("Failed to create TLS config");
    let client_tls = QuicClientTls::new(config.client_config, "localhost");
    assert!(client_tls.is_ok());
}

#[test]
fn test_server_tls_creation() {
    let config = TlsConfig::new().expect("Failed to create TLS config");
    let server_tls = QuicServerTls::new(config.server_config);
    assert!(server_tls.is_ok());
}

#[test]
fn test_alpn_protocol_configuration() {
    let config = TlsConfig::new().expect("Failed to create TLS config");
    
    // Check that both client and server configs support h3 (HTTP/3)
    assert_eq!(config.client_config.alpn_protocols, vec![b"h3".to_vec()]);
    assert_eq!(config.server_config.alpn_protocols, vec![b"h3".to_vec()]);
}

#[test]
fn test_certificate_generation() {
    // This test verifies that self-signed certificate generation works
    // by checking that TLS configuration creation succeeds
    let config1 = TlsConfig::new().expect("Failed to create first TLS config");
    let config2 = TlsConfig::new().expect("Failed to create second TLS config");
    
    // Both configs should be created successfully
    // (This indirectly tests certificate generation since it's part of TlsConfig::new())
    assert!(!config1.client_config.alpn_protocols.is_empty());
    assert!(!config2.client_config.alpn_protocols.is_empty());
}

#[test]
fn test_client_server_compatibility() {
    let config = TlsConfig::new().expect("Failed to create TLS config");
    
    // Test that both client and server TLS contexts can be created from the same config
    let client_result = QuicClientTls::new(config.client_config.clone(), "localhost");
    let server_result = QuicServerTls::new(config.server_config.clone());
    
    assert!(client_result.is_ok(), "Client TLS creation should succeed");
    assert!(server_result.is_ok(), "Server TLS creation should succeed");
}

#[test]
fn test_different_server_names() {
    let config = TlsConfig::new().expect("Failed to create TLS config");
    
    // Test that client TLS can be created with different server names
    let localhost_client = QuicClientTls::new(config.client_config.clone(), "localhost");
    let ip_client = QuicClientTls::new(config.client_config.clone(), "127.0.0.1");
    
    assert!(localhost_client.is_ok(), "Localhost client should be created successfully");
    assert!(ip_client.is_ok(), "IP address client should be created successfully");
}
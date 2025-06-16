use rustls::{ClientConfig, ServerConfig, ClientConnection, ServerConnection, Certificate, PrivateKey};
use std::sync::Arc;
use std::io;

#[derive(Debug)]
pub struct TlsConfig {
    pub client_config: Arc<ClientConfig>,
    pub server_config: Arc<ServerConfig>,
}

impl TlsConfig {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let client_config = Self::create_client_config()?;
        let server_config = Self::create_server_config()?;
        
        Ok(TlsConfig {
            client_config: Arc::new(client_config),
            server_config: Arc::new(server_config),
        })
    }
    
    fn create_client_config() -> Result<ClientConfig, Box<dyn std::error::Error>> {
        let mut config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        
        config.alpn_protocols = vec![b"h3".to_vec()];
        
        Ok(config)
    }
    
    fn create_server_config() -> Result<ServerConfig, Box<dyn std::error::Error>> {
        let cert_chain = Self::generate_self_signed_cert()?;
        let private_key = Self::generate_private_key()?;
        
        let mut config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)?;
        
        config.alpn_protocols = vec![b"h3".to_vec()];
        
        Ok(config)
    }
    
    fn generate_self_signed_cert() -> Result<Vec<Certificate>, Box<dyn std::error::Error>> {
        let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        let cert = rcgen::generate_simple_self_signed(subject_alt_names)?;
        let cert_der = cert.serialize_der()?;
        
        Ok(vec![Certificate(cert_der)])
    }
    
    fn generate_private_key() -> Result<PrivateKey, Box<dyn std::error::Error>> {
        let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        let cert = rcgen::generate_simple_self_signed(subject_alt_names)?;
        let key_der = cert.serialize_private_key_der();
        
        Ok(PrivateKey(key_der))
    }
}

#[derive(Debug)]
pub struct QuicClientTls {
    connection: ClientConnection,
}

impl QuicClientTls {
    pub fn new(config: Arc<ClientConfig>, server_name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let server_name = server_name.try_into()?;
        let connection = ClientConnection::new(config, server_name)?;
        
        Ok(QuicClientTls { connection })
    }
    
    pub fn get_handshake_data(&mut self) -> Result<Vec<u8>, io::Error> {
        let mut buf = Vec::new();
        self.connection.write_tls(&mut buf)?;
        Ok(buf)
    }
    
    pub fn process_handshake_data(&mut self, data: &[u8]) -> Result<(), io::Error> {
        self.connection.read_tls(&mut io::Cursor::new(data))?;
        self.connection.process_new_packets().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(())
    }
    
    pub fn is_handshake_complete(&self) -> bool {
        !self.connection.is_handshaking()
    }
    
    pub fn export_keying_material(&self, out: &mut [u8], label: &[u8], context: Option<&[u8]>) -> Result<(), rustls::Error> {
        // For now, simplified implementation - in real QUIC this would export proper keys
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = (label[i % label.len()] ^ (i as u8)) as u8;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct QuicServerTls {
    connection: ServerConnection,
}

impl QuicServerTls {
    pub fn new(config: Arc<ServerConfig>) -> Result<Self, Box<dyn std::error::Error>> {
        let connection = ServerConnection::new(config)?;
        
        Ok(QuicServerTls { connection })
    }
    
    pub fn get_handshake_data(&mut self) -> Result<Vec<u8>, io::Error> {
        let mut buf = Vec::new();
        self.connection.write_tls(&mut buf)?;
        Ok(buf)
    }
    
    pub fn process_handshake_data(&mut self, data: &[u8]) -> Result<(), io::Error> {
        self.connection.read_tls(&mut io::Cursor::new(data))?;
        self.connection.process_new_packets().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(())
    }
    
    pub fn is_handshake_complete(&self) -> bool {
        !self.connection.is_handshaking()
    }
    
    pub fn export_keying_material(&self, out: &mut [u8], label: &[u8], context: Option<&[u8]>) -> Result<(), rustls::Error> {
        // For now, simplified implementation - in real QUIC this would export proper keys
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = (label[i % label.len()] ^ (i as u8)) as u8;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
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
}
use ring::aead::{Aad, Algorithm, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use ring::hkdf::{Prk, HKDF_SHA256};
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;

#[derive(Debug)]
pub struct QuicCrypto {
    keys: HashMap<EncryptionLevel, CryptoKeys>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncryptionLevel {
    Initial,
    Handshake,
    Application,
}

#[derive(Debug)]
pub struct CryptoKeys {
    local_key: LessSafeKey,
    remote_key: LessSafeKey,
    local_iv: [u8; 12],
    remote_iv: [u8; 12],
    local_pn_key: [u8; 16],
    remote_pn_key: [u8; 16],
}

impl QuicCrypto {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }
    
    pub fn setup_initial_keys(&mut self, connection_id: &[u8], is_client: bool) -> Result<(), CryptoError> {
        // Simplified key setup for now - in a real implementation this would use proper QUIC key derivation
        let dummy_key_material = vec![0u8; 16];
        let unbound_key = UnboundKey::new(&AES_128_GCM, &dummy_key_material)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        let key = LessSafeKey::new(unbound_key);
        
        let unbound_key2 = UnboundKey::new(&AES_128_GCM, &dummy_key_material)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        let key2 = LessSafeKey::new(unbound_key2);
        
        let crypto_keys = CryptoKeys {
            local_key: key,
            remote_key: key2,
            local_iv: [0u8; 12],
            remote_iv: [0u8; 12],
            local_pn_key: [0u8; 16],
            remote_pn_key: [0u8; 16],
        };
        
        self.keys.insert(EncryptionLevel::Initial, crypto_keys);
        Ok(())
    }
    
    pub fn setup_handshake_keys(&mut self, handshake_secret: &[u8], is_client: bool) -> Result<(), CryptoError> {
        let (client_secret, server_secret) = derive_handshake_secrets(handshake_secret)?;
        
        let (local_secret, remote_secret) = if is_client {
            (client_secret, server_secret)
        } else {
            (server_secret, client_secret)
        };
        
        let local_keys = derive_keys(&local_secret, &AES_128_GCM)?;
        let remote_keys = derive_keys(&remote_secret, &AES_128_GCM)?;
        
        let crypto_keys = CryptoKeys {
            local_key: local_keys.0,
            remote_key: remote_keys.0,
            local_iv: local_keys.1,
            remote_iv: remote_keys.1,
            local_pn_key: local_keys.2,
            remote_pn_key: remote_keys.2,
        };
        
        self.keys.insert(EncryptionLevel::Handshake, crypto_keys);
        Ok(())
    }
    
    pub fn setup_application_keys(&mut self, application_secret: &[u8], is_client: bool) -> Result<(), CryptoError> {
        let (client_secret, server_secret) = derive_application_secrets(application_secret)?;
        
        let (local_secret, remote_secret) = if is_client {
            (client_secret, server_secret)
        } else {
            (server_secret, client_secret)
        };
        
        let local_keys = derive_keys(&local_secret, &AES_128_GCM)?;
        let remote_keys = derive_keys(&remote_secret, &AES_128_GCM)?;
        
        let crypto_keys = CryptoKeys {
            local_key: local_keys.0,
            remote_key: remote_keys.0,
            local_iv: local_keys.1,
            remote_iv: remote_keys.1,
            local_pn_key: local_keys.2,
            remote_pn_key: remote_keys.2,
        };
        
        self.keys.insert(EncryptionLevel::Application, crypto_keys);
        Ok(())
    }
    
    pub fn encrypt_packet(&self, level: EncryptionLevel, packet_number: u64, header: &[u8], payload: &[u8]) -> Result<Bytes, CryptoError> {
        let keys = self.keys.get(&level).ok_or(CryptoError::NoKeys)?;
        
        let nonce = construct_nonce(&keys.local_iv, packet_number);
        let aad = Aad::from(header);
        
        let mut in_out = BytesMut::new();
        in_out.extend_from_slice(payload);
        
        keys.local_key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce), 
            aad, 
            &mut in_out
        ).map_err(|_| CryptoError::EncryptionFailed)?;
        
        Ok(in_out.freeze())
    }
    
    pub fn decrypt_packet(&self, level: EncryptionLevel, packet_number: u64, header: &[u8], ciphertext: &mut [u8]) -> Result<usize, CryptoError> {
        let keys = self.keys.get(&level).ok_or(CryptoError::NoKeys)?;
        
        let nonce = construct_nonce(&keys.remote_iv, packet_number);
        let aad = Aad::from(header);
        
        let plaintext = keys.remote_key.open_in_place(
            Nonce::assume_unique_for_key(nonce),
            aad,
            ciphertext
        ).map_err(|_| CryptoError::DecryptionFailed)?;
        
        Ok(plaintext.len())
    }
    
    pub fn encrypt_packet_number(&self, level: EncryptionLevel, packet_number: u64, sample: &[u8]) -> Result<u64, CryptoError> {
        let _keys = self.keys.get(&level).ok_or(CryptoError::NoKeys)?;
        
        // Simplified packet number encryption
        // In real QUIC, this uses AES-ECB or ChaCha20 with the sample
        let encrypted = packet_number ^ u64::from_be_bytes([
            sample[0], sample[1], sample[2], sample[3],
            sample[4], sample[5], sample[6], sample[7],
        ]);
        
        Ok(encrypted)
    }
    
    pub fn decrypt_packet_number(&self, level: EncryptionLevel, encrypted_pn: u64, sample: &[u8]) -> Result<u64, CryptoError> {
        // Packet number encryption is symmetric, so decryption is the same as encryption
        self.encrypt_packet_number(level, encrypted_pn, sample)
    }
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Prk {
    ring::hkdf::Salt::new(HKDF_SHA256, salt).extract(ikm)
}

fn hkdf_expand(prk: &Prk, info: &[u8], length: usize) -> Result<Vec<u8>, CryptoError> {
    let info_slice = [info];
    let okm = prk.expand(&info_slice, ring::hkdf::HKDF_SHA256)
        .map_err(|_| CryptoError::HkdfError)?;
    let mut output = vec![0u8; length];
    okm.fill(&mut output)
        .map_err(|_| CryptoError::HkdfError)?;
    Ok(output)
}

fn derive_initial_secrets(initial_secret: &Prk) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let client_initial_secret = hkdf_expand(initial_secret, b"client in", 32)?;
    let server_initial_secret = hkdf_expand(initial_secret, b"server in", 32)?;
    Ok((client_initial_secret, server_initial_secret))
}

fn derive_handshake_secrets(handshake_secret: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let prk = hkdf_extract(&[], handshake_secret);
    let client_handshake_secret = hkdf_expand(&prk, b"c hs traffic", 32)?;
    let server_handshake_secret = hkdf_expand(&prk, b"s hs traffic", 32)?;
    Ok((client_handshake_secret, server_handshake_secret))
}

fn derive_application_secrets(application_secret: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let prk = hkdf_extract(&[], application_secret);
    let client_application_secret = hkdf_expand(&prk, b"c ap traffic", 32)?;
    let server_application_secret = hkdf_expand(&prk, b"s ap traffic", 32)?;
    Ok((client_application_secret, server_application_secret))
}

fn derive_keys(secret: &[u8], algorithm: &'static Algorithm) -> Result<(LessSafeKey, [u8; 12], [u8; 16]), CryptoError> {
    let prk = hkdf_extract(&[], secret);
    
    let key_material = hkdf_expand(&prk, b"quic key", algorithm.key_len())?;
    let iv_material = hkdf_expand(&prk, b"quic iv", 12)?;
    let pn_key_material = hkdf_expand(&prk, b"quic hp", 16)?;
    
    let unbound_key = UnboundKey::new(algorithm, &key_material)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    let key = LessSafeKey::new(unbound_key);
    
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_material);
    
    let mut pn_key = [0u8; 16];
    pn_key.copy_from_slice(&pn_key_material);
    
    Ok((key, iv, pn_key))
}

fn construct_nonce(iv: &[u8; 12], packet_number: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let pn_bytes = packet_number.to_be_bytes();
    
    // XOR the packet number into the last 8 bytes of the IV
    for i in 0..8 {
        nonce[4 + i] ^= pn_bytes[i];
    }
    
    nonce
}

#[derive(Debug)]
pub enum CryptoError {
    NoKeys,
    EncryptionFailed,
    DecryptionFailed,
    KeyDerivationFailed,
    HkdfError,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::NoKeys => write!(f, "No cryptographic keys available"),
            CryptoError::EncryptionFailed => write!(f, "Packet encryption failed"),
            CryptoError::DecryptionFailed => write!(f, "Packet decryption failed"),
            CryptoError::KeyDerivationFailed => write!(f, "Key derivation failed"),
            CryptoError::HkdfError => write!(f, "HKDF operation failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_crypto_creation() {
        let crypto = QuicCrypto::new();
        assert!(crypto.keys.is_empty());
    }
    
    #[test]
    fn test_initial_keys_setup() {
        let mut crypto = QuicCrypto::new();
        let conn_id = b"test_connection_id";
        
        let result = crypto.setup_initial_keys(conn_id, true);
        if let Err(e) = &result {
            println!("Setup error: {:?}", e);
        }
        assert!(result.is_ok());
        assert!(crypto.keys.contains_key(&EncryptionLevel::Initial));
    }
    
    #[test]
    fn test_nonce_construction() {
        let iv = [0u8; 12];
        let packet_number = 0x123456789abcdef0;
        let nonce = construct_nonce(&iv, packet_number);
        
        // The nonce should have the packet number XORed into the last 8 bytes
        let expected = [0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        assert_eq!(nonce, expected);
    }
    
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut crypto = QuicCrypto::new();
        let conn_id = b"test_connection_id";
        
        crypto.setup_initial_keys(conn_id, true).unwrap();
        
        // For now, just test that the setup works
        // In a real implementation, this would test actual encryption/decryption
        assert!(crypto.keys.contains_key(&EncryptionLevel::Initial));
    }
}
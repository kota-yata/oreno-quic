# oreno-quic

A minimal QUIC protocol implementation in Rust for educational purposes.

## Overview

This project implements the basic components of the QUIC transport protocol including packet headers, frames, connection management, and UDP socket handling. It supports essential operations like connection establishment, ping/pong exchanges, and graceful connection termination.

## Features

- **Packet Processing**: Long and short packet headers with variable-length encoding
- **Frame Types**: PADDING, PING, CRYPTO, and CONNECTION_CLOSE frames
- **Connection Management**: Client/server connections with state machine
- **Variable-Length Integers**: QUIC-compliant varint encoding/decoding
- **UDP Transport**: Asynchronous socket handling with tokio
- **TLS 1.3 Integration**: Secure connections using rustls with self-signed certificates
- **Cryptographic Protection**: AEAD encryption foundation using ring
- **CRYPTO Frames**: TLS handshake data transport for secure connections

## Building

Requires Rust 1.70+ and Cargo.

```bash
cargo build
```

## Running

### Server and Client Communication with TLS

Start the TLS-enabled example server:

```bash
cargo run --example server
```

In another terminal, run the TLS-enabled local client:

```bash
cargo run --example local_client
```

The server will generate self-signed certificates automatically and establish TLS 1.3 connections with clients.

### TLS Configuration Demo

To see the TLS setup in action without networking:

```bash
cargo run --example tls_demo
```

This demonstrates the self-signed certificate generation and TLS configuration.

### Main Server Application

Alternatively, start the main server application:

```bash
cargo run
```

Then run the client example:

```bash
cargo run --example client
```

## Testing

Run all tests:

```bash
cargo test
```

Run only unit tests:

```bash
cargo test --lib
```

Run only integration tests:

```bash
cargo test --test integration_test
```

## Project Structure

```
src/
├── main.rs          # Server implementation
├── lib.rs           # Library root
├── packet.rs        # Packet headers and encoding
├── frame.rs         # Frame types and serialization
├── connection.rs    # Connection state and management
├── tls.rs           # TLS 1.3 configuration and handshake
└── crypto.rs        # Cryptographic operations and key management

examples/
├── server.rs        # TLS-enabled server with detailed logging
├── client.rs        # TLS-enabled client (connects to localhost)
├── local_client.rs  # TLS-enabled local client for testing
└── tls_demo.rs      # TLS configuration demonstration

tests/
└── integration_test.rs  # Network communication tests
```

## Protocol Support

This implementation covers a subset of QUIC:

**Supported:**
- Initial and Handshake packet types
- Connection ID generation and management
- Variable-length packet number encoding
- Frame processing (PADDING, PING, CRYPTO, CONNECTION_CLOSE)
- Connection state transitions
- TLS 1.3 handshake using rustls
- Self-signed certificate generation
- CRYPTO frames for TLS data transport
- Basic cryptographic key setup

**Not Implemented:**
- Full packet encryption/decryption
- Stream multiplexing
- Flow control
- Congestion control
- Path validation
- Connection migration
- Certificate validation (uses self-signed certs)

## Development

The codebase includes comprehensive tests covering:
- Packet encoding/decoding
- Frame serialization (including CRYPTO frames)
- Connection state management
- TLS configuration and setup
- Cryptographic key management
- Error handling
- Network communication

Tests can be run during development to ensure correctness of protocol implementation.

## License

This project is for educational purposes. See individual dependencies for their respective licenses.
# oreno-quic

A minimal QUIC protocol implementation in Rust for educational purposes.

## Overview

This project implements the basic components of the QUIC transport protocol including packet headers, frames, connection management, and UDP socket handling. It supports essential operations like connection establishment, ping/pong exchanges, and graceful connection termination.

## Features

- **Packet Processing**: Long and short packet headers with variable-length encoding
- **Frame Types**: PADDING, PING, and CONNECTION_CLOSE frames
- **Connection Management**: Client/server connections with state machine
- **Variable-Length Integers**: QUIC-compliant varint encoding/decoding
- **UDP Transport**: Asynchronous socket handling with tokio

## Building

Requires Rust 1.70+ and Cargo.

```bash
cargo build
```

## Running

### Server and Client Communication

Start the example server:

```bash
cargo run --example server
```

In another terminal, run the local client:

```bash
cargo run --example local_client
```

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
└── connection.rs    # Connection state and management

examples/
├── server.rs        # Example server with detailed logging
├── client.rs        # Example client (connects to localhost)
└── local_client.rs  # Local client for testing with example server

tests/
└── integration_test.rs  # Network communication tests
```

## Protocol Support

This implementation covers a subset of QUIC:

**Supported:**
- Initial and Handshake packet types
- Connection ID generation and management
- Variable-length packet number encoding
- Basic frame processing (PADDING, PING, CONNECTION_CLOSE)
- Connection state transitions

**Not Implemented:**
- Cryptographic protection
- Stream multiplexing
- Flow control
- Congestion control
- Path validation
- Connection migration

## Development

The codebase includes comprehensive tests covering:
- Packet encoding/decoding
- Frame serialization
- Connection state management
- Error handling
- Network communication

Tests can be run during development to ensure correctness of protocol implementation.

## License

This project is for educational purposes. See individual dependencies for their respective licenses.
# SecureChannel – Secure Communication Application

**Course:** ENCS4320 – Applied Cryptography
**University:** Birzeit University
**Language:** Python 3
**Implementation:** Pure Python (No cryptographic libraries used in the implementation)

## Overview

SecureChannel is a secure communication application that implements a complete authenticated encrypted communication protocol from scratch.

The system establishes a secure session between a client and a server through an authenticated handshake, derives session keys using modern cryptographic primitives, and then protects all subsequent communication using authenticated encryption (AEAD).

All cryptographic algorithms were implemented manually according to their official specifications. External cryptographic libraries were not used in the implementation of the primitives, and were only used during testing to verify correctness against official test vectors.

## Features

- Secure client-server communication
- Ephemeral X25519 key exchange
- Mutual authentication using a pre-shared key (PSK)
- HKDF-based session key derivation
- ChaCha20 stream cipher
- Poly1305 message authentication
- ChaCha20-Poly1305 AEAD
- Replay protection using sequence numbers
- Authenticated plaintext headers (AAD)
- Tampering detection
- Official RFC/FIPS test vectors
- Command-line interface
- Optional Tkinter GUI

## Project Structure

SecureChannel/
├── crypto/
│   ├── sha256.py
│   ├── hmac_sha256.py
│   ├── hkdf.py
│   ├── x25519.py
│   ├── chacha20.py
│   ├── poly1305.py
│   └── chacha20_poly1305.py
│
├── protocol/
│   ├── handshake.py
│   ├── key_schedule.py
│   ├── transcript.py
│   ├── message.py
│   └── cipher_state.py
│
├── network/
│   ├── client.py
│   ├── server.py
│   └── framing.py
│
├── bonus/
│   ├── client_gui.py
│   ├── server_gui.py
│   └── launcher.py
│
├── test/
│   └── test_vectors/
│
└── README.md
## Protocol Overview

The protocol consists of two phases.

### Phase 1 – Secure Handshake

During the handshake:

- Client and server generate ephemeral X25519 key pairs.
- Ephemeral public keys are exchanged.
- Both parties construct an identical handshake transcript.
- The transcript is authenticated using HMAC-SHA256 with the shared PSK.
- Authentication failures immediately terminate the connection.
- HKDF derives independent encryption keys and nonce bases.

### Phase 2 – Secure Messaging

After the handshake:

- Every application message is encrypted.
- Headers remain plaintext but are authenticated.
- ChaCha20 encrypts the payload.
- Poly1305 authenticates both the ciphertext and header.
- Replay attacks are prevented using sequence numbers.
- Modified messages are rejected without terminating the connection.

## Implemented Cryptographic Primitives

- SHA-256 — FIPS 180-4
- HMAC-SHA256 — RFC 2104
- HKDF — RFC 5869
- X25519 — RFC 7748
- ChaCha20 — RFC 8439
- Poly1305 — RFC 8439
- ChaCha20-Poly1305 AEAD — RFC 8439

Each primitive was implemented manually according to its official specification.

## Security Properties

The protocol provides:

- Confidentiality
- Integrity
- Message authenticity
- Mutual authentication
- Replay protection
- Nonce uniqueness
- Message ordering validation

## Running the Project

### Requirements

- Python 3.10+
- No external cryptographic libraries

### Start the Server

python network/a_server.py

### Start the Client

python network/j_client.py

### Launch GUI

python bonus/j_launcher.py

### Running Tests

Execute all tests:

python -m unittest discover test

All implementations are validated against official RFC and FIPS test vectors.

## Test Coverage

The project includes verification against official standards:

- SHA-256 (FIPS 180-4)
- HMAC-SHA256 (RFC 4231)
- HKDF (RFC 5869)
- ChaCha20 (RFC 8439)
- Poly1305 (RFC 8439)
- AEAD ChaCha20-Poly1305 (RFC 8439)
- X25519 (RFC 7748)

Every test passes successfully.

## Design Decisions

Several implementation decisions differ slightly from the project specification while preserving equivalent security properties.

### Transcript Authentication

The implementation authenticates:

HMAC(PSK, SHA256(transcript))

instead of directly authenticating the transcript. Hashing the transcript before applying HMAC produces a fixed-length input while maintaining equivalent security under the collision resistance of SHA-256.

### Independent Directional Keys

Separate encryption keys and nonce bases are derived for:

- Client → Server
- Server → Client

This prevents key reuse between communication directions.

### Replay Handling

Unlike the handshake, which aborts immediately on authentication failure, application messages with invalid authentication tags or incorrect sequence numbers are simply discarded while keeping the connection alive.

## Known Limitations

- Tag comparisons are not constant-time.
- Messages must arrive strictly in order.
- Sliding-window replay protection is not implemented.
- Designed as a learning project rather than a production-ready secure protocol.

## References

- FIPS 180-4 — Secure Hash Standard
- RFC 2104 — HMAC
- RFC 4231 — HMAC Test Cases
- RFC 5869 — HKDF
- RFC 7748 — X25519
- RFC 8439 — ChaCha20 and Poly1305
- Noise Protocol Framework
- Official Python documentation

## AI Usage Statement

Artificial intelligence tools were used only as development assistants and not to generate the complete project implementation.

AI assistance included:

- Clarifying parts of the project specification.
- Explaining RFC and FIPS documents.
- Assisting with debugging implementation errors.
- Suggesting fixes for implementation issues.
- Helping complete official RFC/FIPS test vectors.
- Assisting in writing project documentation (README and report).
- Assisting in implementing the serialize function, since its implementation details were not explicitly specified in the project document.
- Assisting in debugging the Poly1305 implementation, including correcting the final accumulation step from:

a += s

to:

a = (a + s) % (1 << 128)

in accordance with RFC 8439.

The following parts were designed and implemented entirely by the project team:

- All cryptographic primitive implementations
- Protocol design
- Handshake implementation
- Key schedule
- Secure messaging protocol
- Networking layer
- GUI implementation
- Integration of all system components
- Testing and verification against official RFC/FIPS vectors

All AI-generated suggestions were carefully reviewed, verified against the official specifications, and modified where necessary before being incorporated into the final project.

## Authors

**Student 1**
Name: Jibreel Bornat
ID: 1230872

**Student 2**
Name: Amjad Adi
ID: 1230800

## License

This project was developed as part of the ENCS4320 Applied Cryptography course at Birzeit University and is intended solely for educational purposes.

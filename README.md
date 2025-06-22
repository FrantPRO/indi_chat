# IndiChat - Secure CLI Chat Application

A minimal, independent CLI-based chat application with enterprise-grade end-to-end encryption, built in Go.

## Features

### 🔒 Security First
- **End-to-End Encryption**: RSA-2048 + AES-GCM encryption
- **Forward Secrecy**: ECDH ephemeral keys prevent retroactive decryption
- **Message Signing**: RSA digital signatures ensure authenticity
- **Tamper-Proof Logging**: SHA-256 hash chaining detects log tampering
- **Rate Limiting**: DoS protection for sensitive operations

### 💬 Chat Features
- **Private Messaging**: Secure 1-on-1 conversations
- **Group Chat**: Broadcast messages to all users
- **Key Management**: Trust-based public key verification
- **Session Management**: 24-hour forward secure sessions

### 🛡️ Advanced Security
- **Key Fingerprints**: SHA-256 fingerprints for key verification
- **Trust System**: Manual key verification and trust management
- **Key Rotation**: Secure RSA key updates with rate limiting
- **Audit Logs**: Cryptographically secured message history

## Quick Start

### Build
```bash
make build
# or
go build -o bin/server ./cmd/server
go build -o bin/client ./cmd/client
```

### Run Server
```bash
./bin/server -port 8080
```

### Connect Clients
```bash
./bin/client -name Alice -server localhost:8080
./bin/client -name Bob -server localhost:8080
```

## Commands

### Basic Commands
- `/help` - Show all available commands
- `/quit` - Leave the chat

### Messaging
- `<message>` - Send broadcast message to all users
- `/pm <user> <message>` - Send private RSA-encrypted message
- `/pms <user> <message>` - Send forward secure message (ECDH)

### Key Management
- `/keys` - Show all user keys and trust status
- `/trust <user>` - Trust a user's key after verification
- `/mykey` - Show your RSA key fingerprint
- `/updatekey` - Generate and broadcast new RSA key

### Security & Logging
- `/logging <on|off>` - Enable/disable message logging
- `/verify` - Verify message log integrity
- `/logs` - Show recent logged messages

## Security Indicators

### Message Types
- 🔒 **RSA Encrypted** - Traditional RSA+AES encryption
- 🔐 **Forward Secure** - ECDH ephemeral key encryption
- ⚠️ **Unencrypted** - No encryption (missing recipient key)

### Signature Verification
- ✅ **Valid Signature** - Message authentically signed
- ❌ **Invalid Signature** - Signature verification failed
- No icon - Unsigned message

### Key Status
- ✅ **Trusted** - Key manually verified and trusted
- ❌ **Not Trusted** - Key not yet verified
- 📋 **New Key** - First time seeing this key

## Architecture

### Components
```
indi_chat/
├── cmd/
│   ├── server/          # TCP server entry point
│   └── client/          # CLI client entry point
├── internal/
│   ├── crypto/          # Encryption & key management
│   ├── protocol/        # Message protocol definitions
│   ├── server/          # Server implementation
│   ├── client/          # Client implementation
│   └── security/        # Rate limiting & security
└── bin/                 # Compiled binaries
```

### Protocol
- **JSON-based** message protocol over TCP
- **TLS-ready** transport layer
- **Extensible** message types for future features

## Cryptographic Details

### Encryption Algorithms
- **RSA-2048** for key exchange and traditional encryption
- **ECDH P-256** for forward secure ephemeral keys  
- **AES-256-GCM** for symmetric encryption
- **SHA-256** for hashing and signatures

### Key Exchange Process
1. **Initial Handshake**: Exchange RSA public keys
2. **Key Distribution**: Server broadcasts keys to all clients
3. **Trust Establishment**: Manual key fingerprint verification
4. **Session Initiation**: ECDH ephemeral key exchange for forward secrecy

### Forward Secrecy Implementation
```
Alice                Server                Bob
  |                    |                    |
  |-- ECDH Public ---->|---> Forward ------>|
  |                    |                    |
  |<--- ECDH Public ---|<--- Forward -------|
  |                    |                    |
  |-- Encrypted Msg -->|---> Forward ------>|
  |   (Session Key)    |                    |
```

### Message Signing
1. **Generate**: SHA-256 hash of message content
2. **Sign**: RSA-PSS signature with sender's private key
3. **Verify**: Recipient validates signature with sender's public key
4. **Display**: Visual indicators show signature status

### Log Integrity
```
Block N-1            Block N              Block N+1
┌─────────────┐    ┌─────────────┐      ┌─────────────┐
│ Msg Content │    │ Msg Content │      │ Msg Content │
│ Timestamp   │    │ Timestamp   │      │ Timestamp   │
│ Signature   │    │ Signature   │      │ Signature   │
│ Prev Hash   │◄───│ Prev Hash   │◄─────│ Prev Hash   │
│ Hash N-1    │    │ Hash N      │      │ Hash N+1    │
└─────────────┘    └─────────────┘      └─────────────┘
```

## Security Considerations

### Threat Model
✅ **Protects Against**:
- Passive eavesdropping (encryption)
- Message forgery (digital signatures)
- Retroactive decryption (forward secrecy)
- Log tampering (hash chaining)
- DoS attacks (rate limiting)

⚠️ **Does Not Protect Against**:
- Endpoint compromise
- Side-channel attacks
- Traffic analysis
- Malicious server operators

### Best Practices
1. **Verify Key Fingerprints** out-of-band before trusting
2. **Use Forward Secure Messages** (`/pms`) for sensitive communications
3. **Regularly Update Keys** (`/updatekey`) if compromise suspected
4. **Monitor Log Integrity** (`/verify`) for tampering detection
5. **Secure Key Storage** - private keys stored in memory only

## Configuration

### Server Options
```bash
./bin/server -port <port>          # Default: 8080
```

### Client Options  
```bash
./bin/client -name <username> -server <address>
# Default server: localhost:8080
```

### File Locations
- **Message Logs**: `~/.indi_chat/logs/<username>.json`
- **No Persistent Keys**: All keys generated fresh per session

## Development

### Requirements
- Go 1.21+ (for crypto/ecdh support)
- No external dependencies

### Build Commands
```bash
make build       # Build both server and client
make clean       # Remove binaries
make run-server  # Run server in development
make test        # Run tests
make deps        # Download dependencies
```

### Testing
```bash
# Run in separate terminals:
make run-server
make run-client NAME=Alice  
make run-client NAME=Bob
```

## Rate Limiting

### Protected Operations
- **Key Updates**: 3 per 5 minutes per client
- **Future**: Message flooding protection

### Implementation
- **Sliding Window** algorithm
- **Per-client** tracking
- **Server-side** enforcement

## Troubleshooting

### Common Issues

**"No key for user"**
- Wait for key exchange to complete
- Check network connectivity
- Verify user is online

**"Invalid signature"**  
- Key may have been rotated
- Check for MITM attacks
- Re-verify key fingerprints

**"Log verification failed"**
- Log file may be corrupted
- Check file permissions
- Possible tampering detected

**"Rate limit exceeded"**
- Wait 5 minutes between key updates
- Indicates potential DoS attack

### Debug Mode
```bash
# Server with verbose logging
./bin/server -port 8080 -v

# Client with debug output  
./bin/client -name Alice -debug
```

## Contributing

1. **Security Focus**: All contributions must maintain security guarantees
2. **No Dependencies**: Keep the project dependency-free
3. **Test Coverage**: Include tests for new features
4. **Documentation**: Update README for new commands/features

## License

MIT License - See LICENSE file for details.

## Security Disclosure

For security vulnerabilities, please email: [security contact]

**Do not** open public issues for security bugs.

---

**IndiChat** - Where privacy meets simplicity. 🔒
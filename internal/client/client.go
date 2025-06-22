package client

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"indi_chat/internal/crypto"
	"indi_chat/internal/protocol"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

type Client struct {
	conn            net.Conn
	name            string
	keyPair         *crypto.KeyPair
	scanner         *bufio.Scanner
	writer          *bufio.Writer
	peers           map[string]*crypto.PeerKey
	trustedPeers    map[string]string
	sessions        map[string]*SessionInfo
	logChain        *crypto.LogChain
	loggingEnabled  bool
}

type SessionInfo struct {
	SessionKey    []byte
	EphemeralKey  *crypto.EphemeralKeyExchange
	Expiry        time.Time
	SessionID     string
}


func NewClient(name string) (*Client, error) {
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	logChain, err := crypto.NewLogChain(name)
	if err != nil {
		return nil, err
	}

	return &Client{
		name:           name,
		keyPair:        keyPair,
		peers:          make(map[string]*crypto.PeerKey),
		trustedPeers:   make(map[string]string),
		sessions:       make(map[string]*SessionInfo),
		logChain:       logChain,
		loggingEnabled: true,
	}, nil
}

func (c *Client) Connect(address string) error {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return err
	}

	c.conn = conn
	c.scanner = bufio.NewScanner(conn)
	c.writer = bufio.NewWriter(conn)

	publicKeyBytes, err := c.keyPair.PublicKeyBytes()
	if err != nil {
		return err
	}

	handshake := protocol.NewMessage(protocol.TypeHandshake, c.name, "", "")
	handshake.PublicKey = publicKeyBytes

	if err := c.sendMessage(handshake); err != nil {
		return err
	}

	joinMsg := protocol.NewMessage(protocol.TypeJoin, c.name, "", "")
	if err := c.sendMessage(joinMsg); err != nil {
		return err
	}

	go c.listenForMessages()

	return nil
}

func (c *Client) sendMessage(msg *protocol.Message) error {
	data, err := msg.ToJSON()
	if err != nil {
		return err
	}

	c.writer.WriteString(string(data) + "\n")
	return c.writer.Flush()
}

func (c *Client) listenForMessages() {
	for c.scanner.Scan() {
		line := c.scanner.Text()
		
		msg, err := protocol.MessageFromJSON([]byte(line))
		if err != nil {
			log.Printf("Error parsing message: %v", err)
			continue
		}

		switch msg.Type {
		case protocol.TypeJoin:
			if msg.From == "server" && msg.To == c.name {
				fmt.Printf("Connected users: %s\n", msg.Content)
			} else if msg.From != c.name {
				fmt.Printf("*** %s\n", msg.Content)
			}
		case protocol.TypeLeave:
			if msg.From != c.name {
				fmt.Printf("*** %s\n", msg.Content)
				delete(c.peers, msg.From)
				delete(c.trustedPeers, msg.From)
			}
		case protocol.TypeKeyExchange:
			c.handleKeyExchange(msg)
		case protocol.TypeEphemeralKey:
			c.handleEphemeralKey(msg)
		case protocol.TypeSessionRequest:
			c.handleSessionRequest(msg)
		case protocol.TypeChat:
			c.handleChatMessage(msg)
		}
	}
}

func (c *Client) handleChatMessage(msg *protocol.Message) {
	if msg.From == c.name {
		return
	}

	content := msg.Content
	encryptedIcon := ""
	signatureValid := false
	
	// Verify message signature if present
	if len(msg.Signature) > 0 {
		if peerKey, exists := c.peers[msg.From]; exists && peerKey.PublicKey != nil {
			// For encrypted messages, verify signature against original content after decryption
			// For now, verify against received content (will be corrected after decryption)
			messageData := []byte(msg.Content)
			if err := crypto.VerifySignature(messageData, msg.Signature, peerKey.PublicKey); err == nil {
				signatureValid = true
			} else {
				log.Printf("Invalid signature from %s: %v", msg.From, err)
			}
		} else {
			log.Printf("Cannot verify signature from %s: No public key available", msg.From)
		}
	}
	
	if msg.Encrypted {
		if msg.ForwardSecure {
			// Use session key for forward secrecy (ECDH)
			if session, exists := c.sessions[msg.SessionID]; exists {
				encryptedData, err := base64.StdEncoding.DecodeString(msg.Content)
				if err != nil {
					fmt.Printf("❌ Error decoding forward secure message from %s: %v\n", msg.From, err)
					return
				}
				
				decrypted, err := crypto.DecryptWithSessionKey(encryptedData, session.SessionKey)
				if err != nil {
					fmt.Printf("❌ Error decrypting forward secure message from %s: %v\n", msg.From, err)
					fmt.Printf("   Session may have expired or been corrupted\n")
					return
				}
				content = decrypted
				encryptedIcon = "🔐 "
				
				// Re-verify signature against decrypted content
				if len(msg.Signature) > 0 {
					if peerKey, exists := c.peers[msg.From]; exists && peerKey.PublicKey != nil {
						messageData := []byte(content)
						if err := crypto.VerifySignature(messageData, msg.Signature, peerKey.PublicKey); err == nil {
							signatureValid = true
						} else {
							signatureValid = false
							log.Printf("Invalid signature on decrypted content from %s: %v", msg.From, err)
						}
					}
				}
			} else {
				fmt.Printf("❌ No session key for forward secure message from %s (SessionID: %s)\n", msg.From, msg.SessionID)
				fmt.Printf("   Message cannot be decrypted - session may have expired\n")
				return
			}
		} else {
			// Traditional RSA+AES encryption
			encryptedData, err := base64.StdEncoding.DecodeString(msg.Content)
			if err != nil {
				fmt.Printf("❌ Error decoding encrypted message from %s: %v\n", msg.From, err)
				return
			}
			
			decrypted, err := c.keyPair.DecryptMessage(encryptedData)
			if err != nil {
				fmt.Printf("❌ Error decrypting message from %s: %v\n", msg.From, err)
				fmt.Printf("   This could indicate key mismatch or message corruption\n")
				return
			}
			content = decrypted
			encryptedIcon = "🔒 "
			
			// Re-verify signature against decrypted content
			if len(msg.Signature) > 0 {
				if peerKey, exists := c.peers[msg.From]; exists && peerKey.PublicKey != nil {
					messageData := []byte(content)
					if err := crypto.VerifySignature(messageData, msg.Signature, peerKey.PublicKey); err == nil {
						signatureValid = true
					} else {
						signatureValid = false
						log.Printf("Invalid signature on decrypted content from %s: %v", msg.From, err)
					}
				}
			}
		}
	}

	// Add signature verification indicator
	signatureIcon := ""
	if len(msg.Signature) > 0 {
		if signatureValid {
			signatureIcon = "✅ "
		} else {
			signatureIcon = "❌ "
		}
	} else {
		// Warn about unsigned messages
		signatureIcon = "⚠️ "
	}

	timestamp := msg.Timestamp.Format("15:04:05")
	if msg.To == "" {
		fmt.Printf("[%s] %s%s%s: %s\n", timestamp, encryptedIcon, signatureIcon, msg.From, content)
	} else {
		fmt.Printf("[%s] %s%s%s (private): %s\n", timestamp, encryptedIcon, signatureIcon, msg.From, content)
	}

	// Log message if logging is enabled
	if c.loggingEnabled {
		signatureStr := ""
		if len(msg.Signature) > 0 {
			signatureStr = base64.StdEncoding.EncodeToString(msg.Signature)
		}
		c.logChain.AddMessage(msg.From, msg.To, content, signatureStr)
	}
}

func (c *Client) handleKeyExchange(msg *protocol.Message) {
	if msg.From == c.name {
		return
	}

	publicKey, err := crypto.PublicKeyFromBytes(msg.PublicKey)
	if err != nil {
		log.Printf("Error parsing public key from %s: %v", msg.From, err)
		return
	}

	fingerprint := msg.KeyFingerprint
	if fingerprint == "" {
		fingerprint, err = crypto.GetKeyFingerprint(publicKey)
		if err != nil {
			log.Printf("Error getting fingerprint for %s: %v", msg.From, err)
			return
		}
	}

	trusted := false
	if storedFingerprint, exists := c.trustedPeers[msg.From]; exists {
		trusted = (storedFingerprint == fingerprint)
		if !trusted {
			fmt.Printf("⚠️  WARNING: %s's key fingerprint has changed!\n", msg.From)
			fmt.Printf("   Previous: %s\n", storedFingerprint)
			fmt.Printf("   Current:  %s\n", fingerprint)
		}
	}

	c.peers[msg.From] = &crypto.PeerKey{
		PublicKey:   publicKey,
		Fingerprint: fingerprint,
		Trusted:     trusted,
	}

	if !trusted {
		fmt.Printf("📋 New key for %s (fingerprint: %s) - use '/trust %s' to verify\n", 
			msg.From, fingerprint, msg.From)
	}
}

func (c *Client) StartChat() {
	fmt.Printf("Connected to chat as %s. Type '/help' for commands.\n", c.name)
	
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}

		if strings.HasPrefix(input, "/") {
			c.handleCommand(input)
		} else {
			c.sendChatMessage(input, "", false)
		}
	}

	c.disconnect()
}

func (c *Client) handleCommand(command string) {
	parts := strings.SplitN(command, " ", 3)
	cmd := parts[0]

	switch cmd {
	case "/help":
		fmt.Println("Commands:")
		fmt.Println("  /help - Show this help")
		fmt.Println("  /pm <user> <message> - Send private message")
		fmt.Println("  /pms <user> <message> - Send forward secure private message")
		fmt.Println("  /trust <user> - Trust a user's key")
		fmt.Println("  /keys - Show all user keys and trust status")
		fmt.Println("  /updatekey - Generate and broadcast new RSA key")
		fmt.Println("  /mykey - Show your key fingerprint")
		fmt.Println("  /logging <on|off> - Enable/disable message logging")
		fmt.Println("  /verify - Verify message log integrity")
		fmt.Println("  /logs - Show recent message logs")
		fmt.Println("  /quit - Leave the chat")
	case "/pm":
		if len(parts) < 3 {
			fmt.Println("Usage: /pm <user> <message>")
			return
		}
		c.sendSecureMessage(parts[2], parts[1], false)
	case "/pms":
		if len(parts) < 3 {
			fmt.Println("Usage: /pms <user> <message>")
			return
		}
		c.sendSecureMessage(parts[2], parts[1], true)
	case "/trust":
		if len(parts) < 2 {
			fmt.Println("Usage: /trust <user>")
			return
		}
		c.trustUser(parts[1])
	case "/keys":
		c.showKeys()
	case "/updatekey":
		c.updateKey()
	case "/mykey":
		c.showMyKey()
	case "/logging":
		if len(parts) < 2 {
			fmt.Println("Usage: /logging <on|off>")
			return
		}
		c.toggleLogging(parts[1])
	case "/verify":
		c.verifyLogs()
	case "/logs":
		c.showLogs()
	case "/quit":
		c.disconnect()
		os.Exit(0)
	default:
		fmt.Printf("Unknown command: %s\n", cmd)
	}
}

func (c *Client) sendChatMessage(content, to string, forwardSecure bool) {
	msg := protocol.NewMessage(protocol.TypeChat, c.name, to, content)
	
	// Sign the message
	messageData := []byte(content)
	signature, err := crypto.SignMessage(messageData, c.keyPair.PrivateKey)
	if err != nil {
		log.Printf("Error signing message: %v", err)
		return
	}
	msg.Signature = signature
	
	// Encrypt message if sending to specific recipient
	if to != "" {
		// Check if we have the recipient's key
		peerKey, keyExists := c.peers[to]
		if !keyExists || peerKey.PublicKey == nil {
			fmt.Printf("❌ Cannot send to %s: No public key available\n", to)
			fmt.Printf("   Wait for key exchange or check if user is online\n")
			return
		}

		// Check if key is trusted (for enhanced security)
		if !peerKey.Trusted {
			fmt.Printf("⚠️  Warning: %s's key is not trusted (fingerprint: %s)\n", to, peerKey.Fingerprint)
			fmt.Printf("   Use '/trust %s' to verify and trust this key\n", to)
			fmt.Printf("   Proceeding with encryption anyway...\n")
		}

		if forwardSecure {
			// Use forward secure encryption (ECDH)
			if session, exists := c.sessions[to]; exists && time.Now().Before(session.Expiry) {
				encryptedData, err := crypto.EncryptWithSessionKey(content, session.SessionKey)
				if err != nil {
					fmt.Printf("❌ Error encrypting forward secure message: %v\n", err)
					return
				}
				msg.Content = base64.StdEncoding.EncodeToString(encryptedData)
				msg.Encrypted = true
				msg.ForwardSecure = true
				msg.SessionID = session.SessionID
				fmt.Printf("[private to %s]: 🔐 %s\n", to, content)
			} else {
				fmt.Printf("🔐 No valid session with %s. Establishing new session...\n", to)
				c.initiateEphemeralKeyExchange(to)
				return
			}
		} else {
			// Traditional RSA+AES encryption
			encryptedData, err := crypto.EncryptMessage(content, peerKey.PublicKey)
			if err != nil {
				fmt.Printf("❌ Error encrypting message: %v\n", err)
				fmt.Printf("   This could indicate a key corruption or crypto error\n")
				return
			}
			msg.Content = base64.StdEncoding.EncodeToString(encryptedData)
			msg.Encrypted = true
			fmt.Printf("[private to %s]: 🔒 %s\n", to, content)
		}
	} else {
		// For broadcast messages, don't encrypt (would need to encrypt for each user separately)
		fmt.Printf("[broadcast]: ⚠️  %s (unencrypted)\n", content)
		fmt.Printf("   Note: Broadcast messages are not encrypted for security reasons\n")
	}

	if err := c.sendMessage(msg); err != nil {
		log.Printf("Error sending message: %v", err)
	}
}

func (c *Client) disconnect() {
	leaveMsg := protocol.NewMessage(protocol.TypeLeave, c.name, "", "")
	c.sendMessage(leaveMsg)
	
	if c.conn != nil {
		c.conn.Close()
	}
}

func (c *Client) trustUser(username string) {
	peerKey, exists := c.peers[username]
	if !exists {
		fmt.Printf("User %s not found or no key available\n", username)
		return
	}

	fmt.Printf("Trust key for %s?\n", username)
	fmt.Printf("Fingerprint: %s\n", peerKey.Fingerprint)
	fmt.Print("Type 'yes' to trust: ")
	
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() && strings.ToLower(strings.TrimSpace(scanner.Text())) == "yes" {
		c.trustedPeers[username] = peerKey.Fingerprint
		peerKey.Trusted = true
		fmt.Printf("✅ Trusted key for %s\n", username)
	} else {
		fmt.Printf("❌ Key not trusted\n")
	}
}

func (c *Client) showKeys() {
	fmt.Println("User Keys:")
	for username, peerKey := range c.peers {
		trustStatus := "❌ Not trusted"
		if peerKey.Trusted {
			trustStatus = "✅ Trusted"
		}
		fmt.Printf("  %s: %s (%s)\n", username, peerKey.Fingerprint, trustStatus)
	}
}

func (c *Client) updateKey() {
	newKeyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		fmt.Printf("Error generating new key: %v\n", err)
		return
	}

	c.keyPair = newKeyPair
	
	publicKeyBytes, err := c.keyPair.PublicKeyBytes()
	if err != nil {
		fmt.Printf("Error serializing new key: %v\n", err)
		return
	}

	fingerprint, err := c.keyPair.GetFingerprint()
	if err != nil {
		fmt.Printf("Error getting fingerprint: %v\n", err)
		return
	}

	updateMsg := protocol.NewMessage(protocol.TypeKeyUpdate, c.name, "", "")
	updateMsg.PublicKey = publicKeyBytes
	updateMsg.KeyFingerprint = fingerprint

	if err := c.sendMessage(updateMsg); err != nil {
		fmt.Printf("Error broadcasting new key: %v\n", err)
		return
	}

	fmt.Printf("🔄 New key generated and broadcast (fingerprint: %s)\n", fingerprint)
}

func (c *Client) showMyKey() {
	fingerprint, err := c.keyPair.GetFingerprint()
	if err != nil {
		fmt.Printf("Error getting fingerprint: %v\n", err)
		return
	}
	
	fmt.Printf("Your key fingerprint: %s\n", fingerprint)
}

func (c *Client) initiateEphemeralKeyExchange(targetUser string) {
	eke, err := crypto.NewEphemeralKeyExchange()
	if err != nil {
		fmt.Printf("Error creating ephemeral key: %v\n", err)
		return
	}

	sessionID := fmt.Sprintf("%s-%s-%d", c.name, targetUser, time.Now().UnixNano())
	
	c.sessions[targetUser] = &SessionInfo{
		EphemeralKey: eke,
		SessionID:    sessionID,
		Expiry:       time.Now().Add(24 * time.Hour), // 24 hour session
	}

	ephemeralMsg := protocol.NewMessage(protocol.TypeEphemeralKey, c.name, targetUser, "")
	ephemeralMsg.EphemeralKey = eke.GetPublicKeyBytes()
	ephemeralMsg.SessionID = sessionID

	if err := c.sendMessage(ephemeralMsg); err != nil {
		log.Printf("Error sending ephemeral key: %v", err)
	}
}

func (c *Client) sendForwardSecureMessage(content, to string) {
	c.sendChatMessage(content, to, true)
}

func (c *Client) handleEphemeralKey(msg *protocol.Message) {
	if msg.From == c.name {
		return
	}

	// Create our ephemeral key
	eke, err := crypto.NewEphemeralKeyExchange()
	if err != nil {
		log.Printf("Error creating ephemeral key response: %v", err)
		return
	}

	// Compute shared secret
	sharedSecret, err := eke.ComputeSharedSecret(msg.EphemeralKey)
	if err != nil {
		log.Printf("Error computing shared secret: %v", err)
		return
	}

	// Store session
	c.sessions[msg.From] = &SessionInfo{
		SessionKey:   sharedSecret,
		EphemeralKey: eke,
		SessionID:    msg.SessionID,
		Expiry:       time.Now().Add(24 * time.Hour),
	}

	// Send our ephemeral key back
	responseMsg := protocol.NewMessage(protocol.TypeEphemeralKey, c.name, msg.From, "")
	responseMsg.EphemeralKey = eke.GetPublicKeyBytes()
	responseMsg.SessionID = msg.SessionID

	if err := c.sendMessage(responseMsg); err != nil {
		log.Printf("Error sending ephemeral key response: %v", err)
	}

	fmt.Printf("🔐 Established forward secure session with %s\n", msg.From)
}

func (c *Client) handleSessionRequest(msg *protocol.Message) {
	// Handle session requests if needed
	fmt.Printf("Session request from %s\n", msg.From)
}

func (c *Client) toggleLogging(setting string) {
	switch strings.ToLower(setting) {
	case "on", "true", "1":
		c.loggingEnabled = true
		fmt.Println("✅ Message logging enabled")
	case "off", "false", "0":
		c.loggingEnabled = false
		fmt.Println("❌ Message logging disabled")
	default:
		fmt.Printf("Current logging status: %v\n", c.loggingEnabled)
	}
}

func (c *Client) verifyLogs() {
	valid, err := c.logChain.VerifyIntegrity()
	if err != nil {
		fmt.Printf("❌ Log verification failed: %v\n", err)
		return
	}
	
	if valid {
		fmt.Println("✅ Message logs verified - no tampering detected")
	} else {
		fmt.Println("❌ Message logs integrity compromised!")
	}
}

func (c *Client) showLogs() {
	logs := c.logChain.GetLogs()
	if len(logs) == 0 {
		fmt.Println("No logged messages")
		return
	}

	fmt.Println("Recent message logs:")
	start := len(logs) - 10
	if start < 0 {
		start = 0
	}

	for i := start; i < len(logs); i++ {
		log := logs[i]
		timestamp := log.Timestamp.Format("15:04:05")
		direction := "→"
		if log.To != "" {
			direction = "private→"
		}
		fmt.Printf("[%s] %s %s %s: %s\n", timestamp, log.From, direction, log.To, log.Content)
	}
}

// Helper function to validate recipient for secure messaging
func (c *Client) validateRecipient(username string) error {
	if username == "" {
		return fmt.Errorf("recipient username cannot be empty")
	}
	
	if username == c.name {
		return fmt.Errorf("cannot send message to yourself")
	}

	peerKey, exists := c.peers[username]
	if !exists {
		return fmt.Errorf("no public key available for %s - user may be offline or key exchange incomplete", username)
	}

	if peerKey.PublicKey == nil {
		return fmt.Errorf("invalid public key for %s", username)
	}

	return nil
}

// Enhanced send message with full validation
func (c *Client) sendSecureMessage(content, to string, useForwardSecrecy bool) {
	// Validate recipient
	if err := c.validateRecipient(to); err != nil {
		fmt.Printf("❌ Cannot send message: %v\n", err)
		return
	}

	// Send the message using existing logic
	c.sendChatMessage(content, to, useForwardSecrecy)
}
package server

import (
	"bufio"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"indi_chat/internal/crypto"
	"indi_chat/internal/protocol"
	"indi_chat/internal/security"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

type Client struct {
	conn      net.Conn
	name      string
	publicKey *rsa.PublicKey
	writer    *bufio.Writer
}

type Server struct {
	clients     map[string]*Client
	mutex       sync.RWMutex
	rateLimiter *security.RateLimiter
}

func NewServer() *Server {
	return &Server{
		clients:     make(map[string]*Client),
		rateLimiter: security.NewRateLimiter(3, 5*time.Minute), // 3 key updates per 5 minutes
	}
}

func (s *Server) Start(port string) error {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Printf("Server listening on port %s", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}

		go s.handleClient(conn)
	}
}

func (s *Server) handleClient(conn net.Conn) {
	defer conn.Close()
	
	scanner := bufio.NewScanner(conn)
	writer := bufio.NewWriter(conn)
	
	var client *Client

	for scanner.Scan() {
		line := scanner.Text()
		
		msg, err := protocol.MessageFromJSON([]byte(line))
		if err != nil {
			log.Printf("Error parsing message: %v", err)
			continue
		}

		switch msg.Type {
		case protocol.TypeHandshake:
			client = s.handleHandshake(conn, writer, msg)
		case protocol.TypeJoin:
			s.handleJoin(client, msg)
		case protocol.TypeChat:
			s.handleChat(client, msg)
		case protocol.TypeKeyUpdate:
			s.handleKeyUpdate(client, msg)
		case protocol.TypeKeyRequest:
			s.handleKeyRequest(client, msg)
		case protocol.TypeEphemeralKey:
			s.handleEphemeralKey(client, msg)
		case protocol.TypeSessionRequest:
			s.handleSessionRequest(client, msg)
		case protocol.TypeLeave:
			s.handleLeave(client)
			return
		}
	}

	if client != nil {
		s.removeClient(client.name)
	}
}

func (s *Server) handleHandshake(conn net.Conn, writer *bufio.Writer, msg *protocol.Message) *Client {
	client := &Client{
		conn:   conn,
		name:   msg.From,
		writer: writer,
	}

	if len(msg.PublicKey) > 0 {
		var err error
		client.publicKey, err = crypto.PublicKeyFromBytes(msg.PublicKey)
		if err != nil {
			log.Printf("Error parsing public key: %v", err)
		}
	}

	s.mutex.Lock()
	s.clients[client.name] = client
	s.mutex.Unlock()

	log.Printf("Client %s connected", client.name)
	return client
}

func (s *Server) handleJoin(client *Client, msg *protocol.Message) {
	s.mutex.RLock()
	clientList := make([]string, 0, len(s.clients))
	for name := range s.clients {
		if name != client.name {
			clientList = append(clientList, name)
		}
	}
	s.mutex.RUnlock()

	response := protocol.NewMessage(protocol.TypeJoin, "server", client.name, strings.Join(clientList, ","))
	s.sendToClient(client, response)

	// Send all existing public keys to the new client
	s.sendAllPublicKeys(client)

	// Broadcast new client's public key to all other clients
	if client.publicKey != nil {
		s.broadcastPublicKey(client.name, client.publicKey, client.name)
	}

	joinMsg := protocol.NewMessage(protocol.TypeJoin, "server", "", fmt.Sprintf("%s joined the chat", client.name))
	s.broadcast(joinMsg, client.name)
}

func (s *Server) handleChat(client *Client, msg *protocol.Message) {
	if msg.To == "" {
		s.broadcast(msg, client.name)
	} else {
		s.sendToSpecificClient(msg.To, msg)
	}
}

func (s *Server) handleLeave(client *Client) {
	leaveMsg := protocol.NewMessage(protocol.TypeLeave, "server", "", fmt.Sprintf("%s left the chat", client.name))
	s.broadcast(leaveMsg, client.name)
	s.removeClient(client.name)
}

func (s *Server) broadcast(msg *protocol.Message, except string) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for name, client := range s.clients {
		if name != except {
			s.sendToClient(client, msg)
		}
	}
}

func (s *Server) sendToSpecificClient(clientName string, msg *protocol.Message) {
	s.mutex.RLock()
	client, exists := s.clients[clientName]
	s.mutex.RUnlock()

	if exists {
		s.sendToClient(client, msg)
	}
}

func (s *Server) sendToClient(client *Client, msg *protocol.Message) {
	data, err := msg.ToJSON()
	if err != nil {
		log.Printf("Error serializing message: %v", err)
		return
	}

	client.writer.WriteString(string(data) + "\n")
	client.writer.Flush()
}

func (s *Server) removeClient(name string) {
	s.mutex.Lock()
	delete(s.clients, name)
	s.mutex.Unlock()
	log.Printf("Client %s disconnected", name)
}

func (s *Server) sendAllPublicKeys(client *Client) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for name, c := range s.clients {
		if name != client.name && c.publicKey != nil {
			keyMsg := protocol.NewMessage(protocol.TypeKeyExchange, name, client.name, "")
			
			pubKeyBytes, err := x509.MarshalPKIXPublicKey(c.publicKey)
			if err != nil {
				log.Printf("Error marshaling public key for %s: %v", name, err)
				continue
			}
			keyMsg.PublicKey = pubKeyBytes
			
			fingerprint, err := crypto.GetKeyFingerprint(c.publicKey)
			if err == nil {
				keyMsg.KeyFingerprint = fingerprint
			}
			
			s.sendToClient(client, keyMsg)
		}
	}
}

func (s *Server) broadcastPublicKey(name string, publicKey *rsa.PublicKey, except string) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		log.Printf("Error marshaling public key for broadcast: %v", err)
		return
	}

	fingerprint, err := crypto.GetKeyFingerprint(publicKey)
	if err != nil {
		log.Printf("Error getting fingerprint for %s: %v", name, err)
		return
	}

	keyMsg := protocol.NewMessage(protocol.TypeKeyExchange, name, "", "")
	keyMsg.PublicKey = pubKeyBytes
	keyMsg.KeyFingerprint = fingerprint

	for clientName, client := range s.clients {
		if clientName != except {
			s.sendToClient(client, keyMsg)
		}
	}
}

func (s *Server) handleKeyUpdate(client *Client, msg *protocol.Message) {
	if len(msg.PublicKey) == 0 {
		return
	}

	// Rate limit key updates
	if !s.rateLimiter.Allow(client.name + ":key_update") {
		log.Printf("Rate limited key update from %s", client.name)
		errorMsg := protocol.NewMessage(protocol.TypeChat, "server", client.name, "Rate limit exceeded for key updates. Please wait before updating again.")
		s.sendToClient(client, errorMsg)
		return
	}

	newPublicKey, err := crypto.PublicKeyFromBytes(msg.PublicKey)
	if err != nil {
		log.Printf("Error parsing updated public key from %s: %v", client.name, err)
		return
	}

	s.mutex.Lock()
	client.publicKey = newPublicKey
	s.mutex.Unlock()

	log.Printf("Updated public key for client %s", client.name)

	s.broadcastPublicKey(client.name, newPublicKey, client.name)
}

func (s *Server) handleKeyRequest(client *Client, msg *protocol.Message) {
	targetName := msg.Content
	
	s.mutex.RLock()
	targetClient, exists := s.clients[targetName]
	s.mutex.RUnlock()

	if !exists || targetClient.publicKey == nil {
		return
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(targetClient.publicKey)
	if err != nil {
		log.Printf("Error marshaling requested public key: %v", err)
		return
	}

	fingerprint, err := crypto.GetKeyFingerprint(targetClient.publicKey)
	if err != nil {
		log.Printf("Error getting fingerprint for requested key: %v", err)
		return
	}

	keyMsg := protocol.NewMessage(protocol.TypeKeyExchange, targetName, client.name, "")
	keyMsg.PublicKey = pubKeyBytes
	keyMsg.KeyFingerprint = fingerprint

	s.sendToClient(client, keyMsg)
}

func (s *Server) handleEphemeralKey(client *Client, msg *protocol.Message) {
	targetName := msg.To
	if targetName == "" {
		return
	}

	s.mutex.RLock()
	targetClient, exists := s.clients[targetName]
	s.mutex.RUnlock()

	if !exists {
		return
	}

	// Forward ephemeral key to target client
	forwardMsg := protocol.NewMessage(protocol.TypeEphemeralKey, msg.From, targetName, "")
	forwardMsg.EphemeralKey = msg.EphemeralKey
	forwardMsg.SessionID = msg.SessionID

	s.sendToClient(targetClient, forwardMsg)
}

func (s *Server) handleSessionRequest(client *Client, msg *protocol.Message) {
	targetName := msg.To
	if targetName == "" {
		return
	}

	s.mutex.RLock()
	targetClient, exists := s.clients[targetName]
	s.mutex.RUnlock()

	if !exists {
		return
	}

	// Forward session request to target client
	forwardMsg := protocol.NewMessage(protocol.TypeSessionRequest, msg.From, targetName, "")
	forwardMsg.SessionID = msg.SessionID

	s.sendToClient(targetClient, forwardMsg)
}
package protocol

import (
	"encoding/json"
	"time"
)

type MessageType string

const (
	TypeHandshake       MessageType = "handshake"
	TypeChat            MessageType = "chat"
	TypeJoin            MessageType = "join"
	TypeLeave           MessageType = "leave"
	TypeKeyExchange     MessageType = "key_exchange"
	TypeKeyUpdate       MessageType = "key_update"
	TypeKeyRequest      MessageType = "key_request"
	TypeEphemeralKey    MessageType = "ephemeral_key"
	TypeSessionRequest  MessageType = "session_request"
)

type Message struct {
	Type           MessageType `json:"type"`
	From           string      `json:"from"`
	To             string      `json:"to,omitempty"`
	Content        string      `json:"content"`
	PublicKey      []byte      `json:"public_key,omitempty"`
	Timestamp      time.Time   `json:"timestamp"`
	Encrypted      bool        `json:"encrypted,omitempty"`
	KeyFingerprint string      `json:"key_fingerprint,omitempty"`
	Signature      []byte      `json:"signature,omitempty"`
	EphemeralKey   []byte      `json:"ephemeral_key,omitempty"`
	SessionID      string      `json:"session_id,omitempty"`
	ForwardSecure  bool        `json:"forward_secure,omitempty"`
}

func NewMessage(msgType MessageType, from, to, content string) *Message {
	return &Message{
		Type:      msgType,
		From:      from,
		To:        to,
		Content:   content,
		Timestamp: time.Now(),
	}
}

func (m *Message) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

func MessageFromJSON(data []byte) (*Message, error) {
	var msg Message
	err := json.Unmarshal(data, &msg)
	return &msg, err
}
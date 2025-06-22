package crypto

import (
	crypto2 "crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"time"
)

type KeyPair struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

func GenerateKeyPair() (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

func (kp *KeyPair) PublicKeyBytes() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(kp.PublicKey)
}

func PublicKeyFromBytes(data []byte) (*rsa.PublicKey, error) {
	pubKey, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, err
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return rsaPubKey, nil
}

func EncryptMessage(message string, publicKey *rsa.PublicKey) ([]byte, error) {
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(message), nil)

	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, aesKey, nil)
	if err != nil {
		return nil, err
	}

	result := make([]byte, 2+len(encryptedKey)+len(ciphertext))
	result[0] = byte(len(encryptedKey) >> 8)
	result[1] = byte(len(encryptedKey))
	copy(result[2:], encryptedKey)
	copy(result[2+len(encryptedKey):], ciphertext)

	return result, nil
}

func (kp *KeyPair) DecryptMessage(data []byte) (string, error) {
	if len(data) < 2 {
		return "", errors.New("invalid encrypted data")
	}

	keyLen := int(data[0])<<8 | int(data[1])
	if len(data) < 2+keyLen {
		return "", errors.New("invalid encrypted data")
	}

	encryptedKey := data[2 : 2+keyLen]
	ciphertext := data[2+keyLen:]

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, kp.PrivateKey, encryptedKey, nil)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func GetKeyFingerprint(publicKey *rsa.PublicKey) (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(pubKeyBytes)
	return hex.EncodeToString(hash[:])[:16], nil
}

func (kp *KeyPair) GetFingerprint() (string, error) {
	return GetKeyFingerprint(kp.PublicKey)
}

type PeerKey struct {
	PublicKey        *rsa.PublicKey
	Fingerprint      string
	Trusted          bool
	EphemeralKey     *ecdh.PrivateKey
	PeerEphemeralKey *ecdh.PublicKey
	SessionKey       []byte
	SessionExpiry    time.Time
}

type EphemeralKeyExchange struct {
	curve      ecdh.Curve
	privateKey *ecdh.PrivateKey
	publicKey  *ecdh.PublicKey
}

func NewEphemeralKeyExchange() (*EphemeralKeyExchange, error) {
	curve := ecdh.P256()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &EphemeralKeyExchange{
		curve:      curve,
		privateKey: privateKey,
		publicKey:  privateKey.PublicKey(),
	}, nil
}

func (eke *EphemeralKeyExchange) GetPublicKeyBytes() []byte {
	return eke.publicKey.Bytes()
}

func (eke *EphemeralKeyExchange) ComputeSharedSecret(peerPublicKeyBytes []byte) ([]byte, error) {
	peerPublicKey, err := eke.curve.NewPublicKey(peerPublicKeyBytes)
	if err != nil {
		return nil, err
	}

	sharedSecret, err := eke.privateKey.ECDH(peerPublicKey)
	if err != nil {
		return nil, err
	}

	// Derive session key using HKDF-like approach
	hash := sha256.Sum256(sharedSecret)
	return hash[:], nil
}

func EncryptWithSessionKey(message string, sessionKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(message), nil)
	return ciphertext, nil
}

func DecryptWithSessionKey(ciphertext []byte, sessionKey []byte) (string, error) {
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func SignMessage(message []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto2.SHA256, hash[:])
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func VerifySignature(message []byte, signature []byte, publicKey *rsa.PublicKey) error {
	hash := sha256.Sum256(message)
	return rsa.VerifyPKCS1v15(publicKey, crypto2.SHA256, hash[:], signature)
}

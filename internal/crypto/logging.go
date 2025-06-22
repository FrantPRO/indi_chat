package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type MessageLog struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	From        string    `json:"from"`
	To          string    `json:"to"`
	Content     string    `json:"content"`
	Signature   string    `json:"signature"`
	PrevHash    string    `json:"prev_hash"`
	Hash        string    `json:"hash"`
}

type LogChain struct {
	filePath string
	logs     []MessageLog
}

func NewLogChain(userID string) (*LogChain, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	
	logDir := filepath.Join(homeDir, ".indi_chat", "logs")
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return nil, err
	}
	
	filePath := filepath.Join(logDir, fmt.Sprintf("%s.json", userID))
	
	lc := &LogChain{
		filePath: filePath,
		logs:     make([]MessageLog, 0),
	}
	
	// Load existing logs
	if err := lc.loadLogs(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	
	return lc, nil
}

func (lc *LogChain) AddMessage(from, to, content, signature string) error {
	prevHash := ""
	if len(lc.logs) > 0 {
		prevHash = lc.logs[len(lc.logs)-1].Hash
	}
	
	logEntry := MessageLog{
		ID:        generateLogID(),
		Timestamp: time.Now(),
		From:      from,
		To:        to,
		Content:   content,
		Signature: signature,
		PrevHash:  prevHash,
	}
	
	// Calculate hash of current entry
	logEntry.Hash = lc.calculateHash(logEntry)
	
	lc.logs = append(lc.logs, logEntry)
	
	return lc.saveLogs()
}

func (lc *LogChain) VerifyIntegrity() (bool, error) {
	prevHash := ""
	
	for i, log := range lc.logs {
		// Verify previous hash chain
		if log.PrevHash != prevHash {
			return false, fmt.Errorf("hash chain broken at entry %d", i)
		}
		
		// Verify current hash
		calculatedHash := lc.calculateHash(log)
		if log.Hash != calculatedHash {
			return false, fmt.Errorf("hash mismatch at entry %d", i)
		}
		
		prevHash = log.Hash
	}
	
	return true, nil
}

func (lc *LogChain) GetLogs() []MessageLog {
	return lc.logs
}

func (lc *LogChain) loadLogs() error {
	data, err := os.ReadFile(lc.filePath)
	if err != nil {
		return err
	}
	
	return json.Unmarshal(data, &lc.logs)
}

func (lc *LogChain) saveLogs() error {
	data, err := json.MarshalIndent(lc.logs, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(lc.filePath, data, 0600)
}

func (lc *LogChain) calculateHash(log MessageLog) string {
	// Create hash input without the hash field itself
	hashInput := fmt.Sprintf("%s%s%s%s%s%s%s",
		log.ID,
		log.Timestamp.Format(time.RFC3339Nano),
		log.From,
		log.To,
		log.Content,
		log.Signature,
		log.PrevHash,
	)
	
	hash := sha256.Sum256([]byte(hashInput))
	return hex.EncodeToString(hash[:])
}

func generateLogID() string {
	timestamp := time.Now().UnixNano()
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d", timestamp)))
	return hex.EncodeToString(hash[:8])
}
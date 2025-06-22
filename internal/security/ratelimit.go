package security

import (
	"sync"
	"time"
)

type RateLimiter struct {
	requests map[string][]time.Time
	mutex    sync.RWMutex
	limit    int
	window   time.Duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	
	// Get or create request times for this key
	times, exists := rl.requests[key]
	if !exists {
		times = make([]time.Time, 0)
	}

	// Remove old requests outside the window
	cutoff := now.Add(-rl.window)
	validTimes := make([]time.Time, 0)
	for _, t := range times {
		if t.After(cutoff) {
			validTimes = append(validTimes, t)
		}
	}

	// Check if we're within the limit
	if len(validTimes) >= rl.limit {
		rl.requests[key] = validTimes
		return false
	}

	// Add current request
	validTimes = append(validTimes, now)
	rl.requests[key] = validTimes
	
	return true
}

func (rl *RateLimiter) Reset(key string) {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()
	delete(rl.requests, key)
}

func (rl *RateLimiter) GetRequestCount(key string) int {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()
	
	times, exists := rl.requests[key]
	if !exists {
		return 0
	}

	now := time.Now()
	cutoff := now.Add(-rl.window)
	count := 0
	for _, t := range times {
		if t.After(cutoff) {
			count++
		}
	}
	
	return count
}
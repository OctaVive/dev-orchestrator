package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

type bucket struct {
	count int
	until time.Time
}

// Fixed-window, bounded memory. Do not evict live entries when full: doing so
// would let attacker-chosen usernames bypass account limits by cache churn.
type limiter struct {
	mu      sync.Mutex
	buckets map[string]bucket
	window  time.Duration
	maxKeys int
}

func newLimiter() *limiter {
	return &limiter{buckets: make(map[string]bucket), window: 5 * time.Minute, maxKeys: 4096}
}

func (l *limiter) allow(account, ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, value := range l.buckets {
		if !now.Before(value.until) {
			delete(l.buckets, key)
		}
	}
	sum := sha256.Sum256([]byte(account))
	keys := []string{"account:" + hex.EncodeToString(sum[:]), "ip:" + ip, "global"}
	limits := []int{5, 20, 100}
	newKeys := 0
	for i, key := range keys {
		b, exists := l.buckets[key]
		if !exists {
			newKeys++
		} else if b.count >= limits[i] {
			return false
		}
	}
	if len(l.buckets)+newKeys > l.maxKeys {
		return false
	}
	for _, key := range keys {
		b := l.buckets[key]
		if b.until.IsZero() {
			b.until = now.Add(l.window)
		}
		b.count++
		l.buckets[key] = b
	}
	return true
}

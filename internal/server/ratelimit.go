// Package server: rate limiter using token bucket per IP prefix.
package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net"
	"sync"
	"time"
)

// RateLimiter implements a per-IP-prefix token bucket rate limiter.
// Bucket keys are HMAC-SHA256(dailySalt, ipPrefix) to prevent tracking of
// raw IP addresses. The salt is replaced every UTC calendar day; stale
// buckets are cleared on rotation.
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64 // tokens per second
	burst    float64 // maximum burst
	salt     []byte
	saltDate time.Time        // UTC midnight of the day the salt was generated
	nowFunc  func() time.Time // injectable for tests; defaults to time.Now
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// NewRateLimiter creates a RateLimiter with the given rate (tokens/sec) and burst.
// A fresh cryptographic salt is generated immediately and rotated every UTC day.
func NewRateLimiter(rate, burst float64) *RateLimiter {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		// crypto/rand failure is catastrophic; the process cannot function safely.
		panic("ratelimit: failed to generate initial salt: " + err.Error())
	}
	now := time.Now().UTC()
	today := now.Truncate(24 * time.Hour)
	return &RateLimiter{
		buckets:  make(map[string]*bucket),
		rate:     rate,
		burst:    burst,
		salt:     salt,
		saltDate: today,
		nowFunc:  time.Now,
	}
}

// Allow returns true if the request from addr is permitted.
// addr is the remote address in "host:port" or "host" form.
func (r *RateLimiter) Allow(addr string) bool {
	prefix := ipPrefix(addr)
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.nowFunc()
	r.rotateSaltIfNeeded(now)

	key := r.hashPrefix(prefix)

	b, ok := r.buckets[key]
	if !ok {
		b = &bucket{tokens: r.burst, lastSeen: now}
		r.buckets[key] = b
	}

	elapsed := now.Sub(b.lastSeen).Seconds()
	b.lastSeen = now
	b.tokens += elapsed * r.rate
	if b.tokens > r.burst {
		b.tokens = r.burst
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// rotateSaltIfNeeded replaces the salt and clears all buckets when the UTC
// calendar day advances. Must be called with r.mu held.
func (r *RateLimiter) rotateSaltIfNeeded(now time.Time) {
	today := now.UTC().Truncate(24 * time.Hour)
	if today.After(r.saltDate) {
		newSalt := make([]byte, 32)
		if _, err := rand.Read(newSalt); err != nil {
			// Log the failure (M-04). The existing salt continues to be used;
			// rotation is retried on the next Allow call.
			slog.Warn("Rate limiter salt rotation failed — keeping existing salt", "err", err)
			return
		}
		r.salt = newSalt
		r.saltDate = today
		r.buckets = make(map[string]*bucket)
	}
}

// hashPrefix returns hex(HMAC-SHA256(salt, prefix)) for use as a bucket key.
// Must be called with r.mu held.
func (r *RateLimiter) hashPrefix(prefix string) string {
	mac := hmac.New(sha256.New, r.salt)
	mac.Write([]byte(prefix))
	return hex.EncodeToString(mac.Sum(nil))
}

// ipPrefix extracts the network prefix from an address.
// IPv4: /32 (single host), IPv6: /64.
func ipPrefix(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return addr
	}
	if ip.To4() != nil {
		// IPv4: use full /32
		return ip.To4().String()
	}
	// IPv6: use /64 prefix
	masked := ip.Mask(net.CIDRMask(64, 128))
	return masked.String()
}

// Cleanup removes stale bucket entries older than maxAge.
func (r *RateLimiter) Cleanup(maxAge time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for k, b := range r.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(r.buckets, k)
		}
	}
}

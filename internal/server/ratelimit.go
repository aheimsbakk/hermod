// Package server: rate limiter using token bucket per IP prefix.
package server

import (
	"net"
	"sync"
	"time"
)

// RateLimiter implements a per-IP-prefix token bucket rate limiter.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   float64 // maximum burst
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// NewRateLimiter creates a RateLimiter with the given rate (tokens/sec) and burst.
func NewRateLimiter(rate, burst float64) *RateLimiter {
	return &RateLimiter{
		buckets: make(map[string]*bucket),
		rate:    rate,
		burst:   burst,
	}
}

// Allow returns true if the request from addr is permitted.
// addr is the remote address in "host:port" or "host" form.
func (r *RateLimiter) Allow(addr string) bool {
	key := ipPrefix(addr)
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
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

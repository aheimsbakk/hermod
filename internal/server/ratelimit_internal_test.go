// Internal-package tests for RateLimiter salt rotation and key hashing.
package server

import (
	"testing"
	"time"
)

func TestRateLimiterSaltRotation(t *testing.T) {
	rl := NewRateLimiter(100, 2) // burst of 2

	day1 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)

	rl.nowFunc = func() time.Time { return day1 }
	// Also set saltDate to day1 so the rotation check compares correctly.
	rl.saltDate = day1.Truncate(24 * time.Hour)

	// Exhaust burst on day 1.
	if !rl.Allow("1.2.3.4:80") {
		t.Fatal("first request on day 1 should be allowed")
	}
	if !rl.Allow("1.2.3.4:80") {
		t.Fatal("second request on day 1 should be allowed")
	}
	if rl.Allow("1.2.3.4:80") {
		t.Fatal("third request on day 1 should be denied (burst exhausted)")
	}

	// Advance clock to day 2 — rotation clears all buckets.
	rl.nowFunc = func() time.Time { return day2 }

	if !rl.Allow("1.2.3.4:80") {
		t.Fatal("first request on day 2 should be allowed after salt rotation")
	}
}

func TestRateLimiterKeyIsHashed(t *testing.T) {
	rl := NewRateLimiter(100, 10)
	rl.Allow("1.2.3.4:80")

	rl.mu.Lock()
	defer rl.mu.Unlock()

	rawKey := "1.2.3.4"
	if _, found := rl.buckets[rawKey]; found {
		t.Fatal("raw IP address must not be stored as a bucket key")
	}
	if len(rl.buckets) == 0 {
		t.Fatal("expected at least one bucket entry after Allow")
	}
}

func TestRateLimiterSaltRotationClearsBuckets(t *testing.T) {
	rl := NewRateLimiter(100, 1)

	day1 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	rl.nowFunc = func() time.Time { return day1 }
	rl.saltDate = day1.Truncate(24 * time.Hour)

	// Fill a bucket entry on day 1.
	rl.Allow("10.0.0.1:9000")

	rl.mu.Lock()
	countBefore := len(rl.buckets)
	rl.mu.Unlock()

	if countBefore == 0 {
		t.Fatal("expected bucket entry before rotation")
	}

	// Advance to day 2 and trigger rotation via Allow.
	day2 := time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC)
	rl.nowFunc = func() time.Time { return day2 }
	rl.Allow("10.0.0.1:9000")

	rl.mu.Lock()
	countAfter := len(rl.buckets)
	rl.mu.Unlock()

	// After rotation the old entry is gone; only the new request's bucket remains.
	if countAfter != 1 {
		t.Fatalf("expected exactly 1 bucket after rotation, got %d", countAfter)
	}
}

package server_test

import (
	"testing"
	"time"

	"github.com/hermod/hermod/internal/server"
)

func TestMemoryStoreAllocateAndFetch(t *testing.T) {
	store := server.NewMemoryStore(0)
	defer store.Close()

	if err := store.AllocateChannel(42, time.Minute, ""); err != nil {
		t.Fatalf("allocate: %v", err)
	}

	blob := []byte("hello")
	if err := store.StoreBlob(42, true, blob); err != nil {
		t.Fatalf("store blob: %v", err)
	}

	got, err := store.FetchBlob(42, true)
	if err != nil {
		t.Fatalf("fetch blob: %v", err)
	}
	if string(got) != string(blob) {
		t.Fatalf("blob mismatch: %q != %q", got, blob)
	}
}

func TestMemoryStoreFetchMissing(t *testing.T) {
	store := server.NewMemoryStore(0)
	got, err := store.FetchBlob(99, true)
	if err != nil {
		t.Fatalf("fetch missing should not error: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil for missing blob")
	}
}

func TestMemoryStoreDuplicateAllocation(t *testing.T) {
	store := server.NewMemoryStore(0)
	store.AllocateChannel(1, time.Minute, "")
	err := store.AllocateChannel(1, time.Minute, "")
	if err == nil {
		t.Fatal("expected error for duplicate channel allocation")
	}
}

func TestMemoryStoreRecordFailure(t *testing.T) {
	store := server.NewMemoryStore(0)
	store.AllocateChannel(7, time.Minute, "")

	count, err := store.RecordFailure(7)
	if err != nil {
		t.Fatalf("record failure: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected count 1, got %d", count)
	}

	count, _ = store.RecordFailure(7)
	if count != 2 {
		t.Fatalf("expected count 2, got %d", count)
	}
}

func TestMemoryStoreRecordFailureMissing(t *testing.T) {
	store := server.NewMemoryStore(0)
	_, err := store.RecordFailure(999)
	if err == nil {
		t.Fatal("expected error for missing channel")
	}
}

func TestMemoryStoreDeleteChannel(t *testing.T) {
	store := server.NewMemoryStore(0)
	store.AllocateChannel(5, time.Minute, "")
	store.StoreBlob(5, true, []byte("data"))

	if err := store.DeleteChannel(5); err != nil {
		t.Fatalf("delete: %v", err)
	}

	got, _ := store.FetchBlob(5, true)
	if got != nil {
		t.Fatal("expected nil after delete")
	}
}

func TestMemoryStorePurgeExpired(t *testing.T) {
	store := server.NewMemoryStore(0)
	store.AllocateChannel(10, -time.Second, "") // already expired
	store.AllocateChannel(11, time.Minute, "")  // not expired

	if _, err := store.PurgeExpired(); err != nil {
		t.Fatalf("purge: %v", err)
	}

	// Channel 10 should be gone (purged)
	if err := store.StoreBlob(10, true, []byte("x")); err == nil {
		t.Fatal("expected error — channel 10 should be purged")
	}
	// Channel 11 should exist
	if err := store.StoreBlob(11, true, []byte("y")); err != nil {
		t.Fatalf("channel 11 should still exist: %v", err)
	}
}

func TestMemoryStoreExpiredBlob(t *testing.T) {
	store := server.NewMemoryStore(0)
	store.AllocateChannel(42, -time.Second, "") // already expired

	// StoreBlob should reject expired channels
	err := store.StoreBlob(42, true, []byte("data"))
	if err == nil {
		t.Fatal("expected error for StoreBlob on expired channel")
	}

	// FetchBlob should also reject expired channels
	_, err = store.FetchBlob(42, true)
	if err == nil {
		t.Fatal("expected error for FetchBlob on expired channel")
	}
}

func TestMemoryStoreBothSides(t *testing.T) {
	store := server.NewMemoryStore(0)
	store.AllocateChannel(20, time.Minute, "")

	store.StoreBlob(20, true, []byte("from-sender"))
	store.StoreBlob(20, false, []byte("from-receiver"))

	s, _ := store.FetchBlob(20, true)
	r, _ := store.FetchBlob(20, false)

	if string(s) != "from-sender" {
		t.Fatalf("sender blob: %q", s)
	}
	if string(r) != "from-receiver" {
		t.Fatalf("receiver blob: %q", r)
	}
}

func TestRateLimiter(t *testing.T) {
	rl := server.NewRateLimiter(10, 5) // 10/sec, burst 5

	// First 5 requests should pass (burst)
	for i := 0; i < 5; i++ {
		if !rl.Allow("192.168.1.1:1234") {
			t.Fatalf("request %d should be allowed", i)
		}
	}

	// 6th request should be denied (burst exhausted)
	if rl.Allow("192.168.1.1:1234") {
		t.Fatal("6th request should be rate-limited")
	}
}

func TestRateLimiterDifferentIPs(t *testing.T) {
	rl := server.NewRateLimiter(10, 1)
	// Different IPs have independent buckets
	if !rl.Allow("10.0.0.1:100") {
		t.Fatal("first IP should be allowed")
	}
	if !rl.Allow("10.0.0.2:100") {
		t.Fatal("second IP should be allowed (different bucket)")
	}
}

func TestRateLimiterIPv6Prefix(t *testing.T) {
	rl := server.NewRateLimiter(10, 2)
	// Same /64 prefix should share bucket
	rl.Allow("[2001:db8::1]:80")
	rl.Allow("[2001:db8::2]:80")
	// Third should fail
	if rl.Allow("[2001:db8::3]:80") {
		t.Fatal("third request from same /64 should be rate-limited")
	}
}

func TestRateLimiterCleanup(t *testing.T) {
	rl := server.NewRateLimiter(100, 10)
	rl.Allow("1.2.3.4:80")
	rl.Cleanup(0) // zero duration removes all
	// After cleanup, should be reset (burst available again)
	if !rl.Allow("1.2.3.4:80") {
		t.Fatal("should be allowed after cleanup")
	}
}

// TestSQLiteStorePurgeExpired is handled by TestMemoryStorePurgeExpired above.
// TestSQLiteStoreDeleteChannel is handled by TestMemoryStoreDeleteChannel above.
// The remaining TestSQLiteStore* functions were removed — they were relics from
// the SQLite storage backend and tested the same code paths as TestMemoryStore*.

func TestMemoryStorePerIPCap_BlocksAtLimit(t *testing.T) {
	store := server.NewMemoryStore(3) // max 3 channels per IP
	defer store.Close()

	// Allocate 3 channels from the same IP — all should succeed.
	for i := 0; i < 3; i++ {
		if err := store.AllocateChannel(uint16(100+i), time.Minute, "10.0.0.1:5000"); err != nil {
			t.Fatalf("allocate %d: %v", i, err)
		}
	}

	// 4th allocation from the same IP must fail.
	if err := store.AllocateChannel(200, time.Minute, "10.0.0.1:5000"); err == nil {
		t.Fatal("expected error when per-IP channel limit is exceeded")
	}
}

func TestMemoryStorePerIPCap_DifferentIPs(t *testing.T) {
	store := server.NewMemoryStore(2) // max 2 channels per IP
	defer store.Close()

	// Fill first IP to its limit.
	if err := store.AllocateChannel(10, time.Minute, "10.0.0.1:5000"); err != nil {
		t.Fatalf("allocate from first IP: %v", err)
	}
	if err := store.AllocateChannel(11, time.Minute, "10.0.0.1:5000"); err != nil {
		t.Fatalf("allocate from first IP: %v", err)
	}

	// A different IP can still allocate.
	if err := store.AllocateChannel(20, time.Minute, "10.0.0.2:5000"); err != nil {
		t.Fatalf("allocate from second IP: %v", err)
	}
}

func TestMemoryStorePerIPCap_DeleteDecrements(t *testing.T) {
	store := server.NewMemoryStore(1)
	defer store.Close()

	if err := store.AllocateChannel(1, time.Minute, "10.0.0.1:5000"); err != nil {
		t.Fatalf("first allocate: %v", err)
	}

	// Delete the channel — should free the slot.
	if err := store.DeleteChannel(1); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Same IP can allocate again.
	if err := store.AllocateChannel(2, time.Minute, "10.0.0.1:5000"); err != nil {
		t.Fatalf("allocate after delete: %v", err)
	}
}

func TestMemoryStorePerIPCap_PurgeDecrements(t *testing.T) {
	store := server.NewMemoryStore(1)
	defer store.Close()

	// Allocate an already-expired channel (TTL in the past).
	if err := store.AllocateChannel(1, -time.Second, "10.0.0.1:5000"); err != nil {
		t.Fatalf("allocate expired: %v", err)
	}

	// The channel is expired but still exists — a second allocation should fail.
	if err := store.AllocateChannel(2, time.Minute, "10.0.0.1:5000"); err == nil {
		t.Fatal("expected error — slot still occupied by expired channel")
	}

	// Purge expired channels.
	if _, err := store.PurgeExpired(); err != nil {
		t.Fatalf("purge: %v", err)
	}

	// Now the slot should be free.
	if err := store.AllocateChannel(2, time.Minute, "10.0.0.1:5000"); err != nil {
		t.Fatalf("allocate after purge: %v", err)
	}
}

func TestMemoryStorePerIPCap_Unlimited(t *testing.T) {
	store := server.NewMemoryStore(0) // unlimited
	defer store.Close()

	// Allocate many channels from the same IP — all must succeed.
	for i := 0; i < 1000; i++ {
		if err := store.AllocateChannel(uint16(i), time.Minute, "10.0.0.1:5000"); err != nil {
			t.Fatalf("allocate %d with unlimited cap: %v", i, err)
		}
	}
}

func TestMemoryStorePerIPCap_IPv6Prefix(t *testing.T) {
	store := server.NewMemoryStore(2) // max 2 per /64 prefix
	defer store.Close()

	// Allocate from two IPv6 addresses in the same /64 — both succeed.
	if err := store.AllocateChannel(1, time.Minute, "[2001:db8::1]:5000"); err != nil {
		t.Fatalf("allocate first IPv6: %v", err)
	}
	if err := store.AllocateChannel(2, time.Minute, "[2001:db8::2]:5000"); err != nil {
		t.Fatalf("allocate second IPv6 (same /64): %v", err)
	}

	// Third allocation from the same /64 must fail.
	if err := store.AllocateChannel(3, time.Minute, "[2001:db8::3]:5000"); err == nil {
		t.Fatal("expected error for third IPv6 in same /64")
	}

	// A different /64 should still work.
	if err := store.AllocateChannel(4, time.Minute, "[2001:db9::1]:5000"); err != nil {
		t.Fatalf("allocate from different /64: %v", err)
	}
}

func TestMemoryStorePerIPCap_NoRemoteAddr(t *testing.T) {
	store := server.NewMemoryStore(1) // max 1 per IP
	defer store.Close()

	// Allocate without a remote address — no cap enforcement.
	if err := store.AllocateChannel(1, time.Minute, ""); err != nil {
		t.Fatalf("allocate without remote addr: %v", err)
	}

	// Second allocation without remote address should also succeed (no cap).
	if err := store.AllocateChannel(2, time.Minute, ""); err != nil {
		t.Fatalf("second allocate without remote addr: %v", err)
	}
}

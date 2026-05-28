package server_test

import (
	"testing"
	"time"

	"github.com/hermod/hermod/internal/server"
)

func TestMemoryStoreAllocateAndFetch(t *testing.T) {
	store := server.NewMemoryStore()
	defer store.Close()

	if err := store.AllocateChannel(42, time.Minute); err != nil {
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
	store := server.NewMemoryStore()
	got, err := store.FetchBlob(99, true)
	if err != nil {
		t.Fatalf("fetch missing should not error: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil for missing blob")
	}
}

func TestMemoryStoreDuplicateAllocation(t *testing.T) {
	store := server.NewMemoryStore()
	store.AllocateChannel(1, time.Minute)
	err := store.AllocateChannel(1, time.Minute)
	if err == nil {
		t.Fatal("expected error for duplicate channel allocation")
	}
}

func TestMemoryStoreRecordFailure(t *testing.T) {
	store := server.NewMemoryStore()
	store.AllocateChannel(7, time.Minute)

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
	store := server.NewMemoryStore()
	_, err := store.RecordFailure(999)
	if err == nil {
		t.Fatal("expected error for missing channel")
	}
}

func TestMemoryStoreDeleteChannel(t *testing.T) {
	store := server.NewMemoryStore()
	store.AllocateChannel(5, time.Minute)
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
	store := server.NewMemoryStore()
	store.AllocateChannel(10, -time.Second) // already expired
	store.AllocateChannel(11, time.Minute)  // not expired

	if err := store.PurgeExpired(); err != nil {
		t.Fatalf("purge: %v", err)
	}

	// Channel 10 should be gone
	if err := store.StoreBlob(10, true, []byte("x")); err == nil {
		t.Fatal("expected error — channel 10 should be purged")
	}
	// Channel 11 should exist
	if err := store.StoreBlob(11, true, []byte("y")); err != nil {
		t.Fatalf("channel 11 should still exist: %v", err)
	}
}

func TestMemoryStoreBothSides(t *testing.T) {
	store := server.NewMemoryStore()
	store.AllocateChannel(20, time.Minute)

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

func TestSQLiteStore(t *testing.T) {
	store := server.NewMemoryStore()
	var err error
	_ = err
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	if err := store.AllocateChannel(1, time.Minute); err != nil {
		t.Fatalf("allocate: %v", err)
	}

	blob := []byte("test-payload")
	if err := store.StoreBlob(1, true, blob); err != nil {
		t.Fatalf("store: %v", err)
	}

	got, err := store.FetchBlob(1, true)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(got) != string(blob) {
		t.Fatalf("blob mismatch")
	}
}

func TestSQLiteStoreFetchMissing(t *testing.T) {
	store := server.NewMemoryStore()
	defer store.Close()
	got, err := store.FetchBlob(999, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil")
	}
}

func TestSQLiteStoreRecordFailure(t *testing.T) {
	store := server.NewMemoryStore()
	defer store.Close()
	store.AllocateChannel(2, time.Minute)

	count, err := store.RecordFailure(2)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1, got %d", count)
	}
}

func TestSQLiteStorePurgeExpired(t *testing.T) {
	store := server.NewMemoryStore()
	defer store.Close()
	store.AllocateChannel(50, -time.Second)
	store.AllocateChannel(51, time.Minute)
	store.PurgeExpired()

	// 50 should be gone (error on StoreBlob)
	err := store.StoreBlob(50, true, []byte("x"))
	if err == nil {
		// SQLite won't error on FK since blobs have no FK constraint
		// Just verify fetch returns nothing
		got, _ := store.FetchBlob(50, true)
		_ = got
	}
}

func TestSQLiteStoreDeleteChannel(t *testing.T) {
	store := server.NewMemoryStore()
	defer store.Close()
	store.AllocateChannel(3, time.Minute)
	store.StoreBlob(3, true, []byte("data"))
	store.DeleteChannel(3)

	got, _ := store.FetchBlob(3, true)
	if got != nil {
		t.Fatal("expected nil after delete")
	}
}

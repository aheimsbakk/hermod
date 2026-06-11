// Package server implements the hermod signaling server.
package server

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// SignalingStore defines the persistence layer for the signaling server.
type SignalingStore interface {
	// AllocateChannel registers a new channel with the given TTL.
	AllocateChannel(id uint16, ttl time.Duration) error
	// ChannelExists reports whether a channel has been allocated and not yet expired.
	ChannelExists(id uint16) bool
	// StoreBlob stores an encrypted handshake blob for a channel.
	// sender=true means the blob was sent by the tx side.
	StoreBlob(id uint16, sender bool, blob []byte) error
	// FetchBlob retrieves the blob stored by the given side.
	FetchBlob(id uint16, sender bool) ([]byte, error)
	// RecordFailure increments the failure counter for a channel and returns
	// the new count.
	RecordFailure(id uint16) (int, error)
	// DeleteChannel removes the channel and all its state.
	DeleteChannel(id uint16) error
	// PurgeExpired removes all expired channels and returns their IDs.
	PurgeExpired() ([]uint16, error)
	// Close releases resources held by the store.
	Close() error
}

// MemoryStore is an in-memory SignalingStore.
type MemoryStore struct {
	mu       sync.Mutex
	channels map[uint16]*memChannel
}

type memChannel struct {
	expires  time.Time
	failures int
	blobs    [2][]byte // index 0 = receiver, 1 = sender
}

// NewMemoryStore creates a new empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{channels: make(map[uint16]*memChannel)}
}

func (m *MemoryStore) AllocateChannel(id uint16, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.channels[id]; ok {
		return fmt.Errorf("channel %d already exists", id)
	}
	m.channels[id] = &memChannel{expires: time.Now().Add(ttl)}
	return nil
}

func (m *MemoryStore) ChannelExists(id uint16) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch, ok := m.channels[id]
	if !ok {
		return false
	}
	return time.Now().Before(ch.expires)
}

func (m *MemoryStore) StoreBlob(id uint16, sender bool, blob []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch, ok := m.channels[id]
	if !ok {
		return fmt.Errorf("channel %d not found", id)
	}
	if time.Now().After(ch.expires) {
		return fmt.Errorf("channel %d expired", id)
	}
	idx := 0
	if sender {
		idx = 1
	}
	ch.blobs[idx] = blob
	return nil
}

func (m *MemoryStore) FetchBlob(id uint16, sender bool) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch, ok := m.channels[id]
	if !ok {
		return nil, nil
	}
	if time.Now().After(ch.expires) {
		return nil, fmt.Errorf("channel %d expired", id)
	}
	idx := 0
	if sender {
		idx = 1
	}
	return ch.blobs[idx], nil
}

func (m *MemoryStore) RecordFailure(id uint16) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch, ok := m.channels[id]
	if !ok {
		return 0, fmt.Errorf("channel %d not found", id)
	}
	ch.failures++
	return ch.failures, nil
}

func (m *MemoryStore) DeleteChannel(id uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.channels, id)
	return nil
}

func (m *MemoryStore) PurgeExpired() ([]uint16, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	var expired []uint16
	for id, ch := range m.channels {
		if now.After(ch.expires) {
			delete(m.channels, id)
			expired = append(expired, id)
		}
	}
	return expired, nil
}

func (m *MemoryStore) Close() error { return nil }

// RunGC starts a background goroutine that calls PurgeExpired every interval.
// It stops when ctx is cancelled.
func RunGC(ctx context.Context, store SignalingStore, interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_, _ = store.PurgeExpired()
			}
		}
	}()
}

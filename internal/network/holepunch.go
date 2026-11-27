// NAT hole punching: simultaneous nonce-tagged probes, single- and
// dual-phase (IPv6 preferred, IPv4 fallback).

package network

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"time"
)

// HolePunchResult carries the outcome of NAT hole punching.
type HolePunchResult struct {
	PeerAddr *net.UDPAddr
}

// HolePunch performs simultaneous UDP hole punching to each candidate address.
// probeNonce is a 32-byte SHA-256 hash derived from the CPace shared key.
// The probe payload uses bytes [0:7] and the ack payload uses bytes [8:15],
// giving 64 bits of entropy per packet — practically unguessable by an
// off-path attacker and resistant to spoofed ack injection.
// Returns as soon as a probe/ack exchange succeeds or ctx is cancelled.
//
// probeCtx controls the probe-sending goroutine's lifetime separately from
// the hole-punch timeout. Pass a context that outlives the main ctx so
// probing continues after HolePunch returns, keeping NAT mappings alive
// until the caller signals completion (D-02). Pass ctx to use the same
// lifetime for both.
func HolePunch(ctx context.Context, probeCtx context.Context, mux *packetMux, candidates []*net.UDPAddr, probeNonce [32]byte) (*HolePunchResult, error) {
	if probeCtx == nil {
		probeCtx = ctx
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// probe = [probeMarker, nonce[0:7]]  — 8 bytes
	// ack   = [probeMarker, nonce[8:15]] — 8 bytes
	probe := []byte{probeMarker, probeNonce[0], probeNonce[1], probeNonce[2], probeNonce[3], probeNonce[4], probeNonce[5], probeNonce[6]}
	ack := []byte{probeMarker, probeNonce[8], probeNonce[9], probeNonce[10], probeNonce[11], probeNonce[12], probeNonce[13], probeNonce[14]}

	// Send probes to all candidates periodically.
	// Uses probeCtx so probing continues even after HolePunch returns,
	// preventing NAT mappings from expiring before the QUIC handshake.
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-probeCtx.Done():
				return
			case <-ticker.C:
				for _, addr := range candidates {
					mux.conn.WriteTo(probe, addr) //nolint:errcheck
				}
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("unreachable after 10s: %d candidate(s) tried: %w", len(candidates), ctx.Err())
		case pkt := <-mux.probeCh:
			if len(pkt.data) < 8 {
				continue
			}
			switch {
			case subtle.ConstantTimeCompare(pkt.data[1:8], probeNonce[:7]) == 1: // received probe — send ack
				mux.conn.WriteTo(ack, pkt.addr) //nolint:errcheck
				if udpAddr, ok := pkt.addr.(*net.UDPAddr); ok {
					return &HolePunchResult{PeerAddr: udpAddr}, nil
				}
			case subtle.ConstantTimeCompare(pkt.data[1:8], probeNonce[8:15]) == 1: // received ack
				if udpAddr, ok := pkt.addr.(*net.UDPAddr); ok {
					return &HolePunchResult{PeerAddr: udpAddr}, nil
				}
			}
		}
	}
}

// HolePunchDual performs two-phase NAT hole punching: IPv6 first (preferred),
// then IPv4 (fallback). Each phase uses the existing HolePunch function.
//
// The v6 phase has a 5-second timeout. If it succeeds, the v4 phase is skipped.
// If the v6 phase times out or no v6 candidates exist, the v4 phase runs with
// the remaining context timeout.
//
// Pass an empty candidatesV4 or candidatesV6 slice to skip that phase entirely
// (used when -4 or -6 flag enforces a single protocol).
//
// probeCtx controls the probe-sending goroutine's lifetime. See HolePunch
// for details. Pass ctx to use the same lifetime for both.
func HolePunchDual(ctx context.Context, probeCtx context.Context, mux *packetMux, candidatesV4, candidatesV6 []*net.UDPAddr, probeNonce [32]byte) (*HolePunchResult, error) {
	if probeCtx == nil {
		probeCtx = ctx
	}

	// Phase 1: IPv6 (preferred) — 5-second timeout.
	if len(candidatesV6) > 0 {
		v6Ctx, v6Cancel := context.WithTimeout(ctx, 5*time.Second)
		defer v6Cancel()
		result, err := HolePunch(v6Ctx, probeCtx, mux, candidatesV6, probeNonce)
		if err == nil {
			return result, nil
		}
	}

	// Phase 2: IPv4 (fallback) — use remaining context timeout.
	if len(candidatesV4) > 0 {
		result, err := HolePunch(ctx, probeCtx, mux, candidatesV4, probeNonce)
		if err != nil {
			return nil, fmt.Errorf("IPv4 fallback: %w", err)
		}
		return result, nil
	}

	return nil, fmt.Errorf("no candidates available (IPv4: %d, IPv6: %d)", len(candidatesV4), len(candidatesV6))
}

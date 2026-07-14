# Buffer Sizes for 10 Gbit/s Throughput

## Findings

The program has four buffer/threshold settings that stall a 10 Gbit/s pipe.
The remaining buffers (UDP socket 2 MiB, signaling 64 KiB, reflection 512 B,
crypto payloads < 2 KB) are already adequate or serve control-plane paths.

### 1. QUIC flow control — 200× bottleneck

| Setting | Default | Impact |
|---|---|---|
| `InitialStreamReceiveWindow` | 512 KB | Sender stalls after ~0.4 ms at line rate |
| `InitialConnectionReceiveWindow` | 512 KB | Same at connection level |
| `MaxStreamReceiveWindow` | 6 MB | Auto-tuning cap — too small for 10 Gbit/s BDP |
| `MaxConnectionReceiveWindow` | 15 MB | Same |

On a 10 Gbit/s / 10 ms path the BDP is 12.5 MB. The default 512 KB starting
window forces ~24 round-trips of ramp-up before the pipe fills. On a 50 ms WAN
path the sender is idle ~90% of the time during ramp-up.

### 2. Packet mux read channel — silent packet drops

| Setting | Value | Impact |
|---|---|---|
| `quicCh` capacity | 256 datagrams | Fills in ~0.3 ms at 10 Gbit/s |

The read loop uses a non-blocking send (`select … default`). Once the channel
is full, incoming QUIC datagrams are silently dropped. Each slot holds a
~1.5 KB datagram, so 256 slots = ~384 KB of buffered data.

### 3. Packet mux read buffer — truncation ceiling

| Setting | Value | Impact |
|---|---|---|
| `readLoop` buffer | 64 KiB | Larger than MTU but wastes space; a 1 MiB buffer absorbs bursts |

### 4. UDP socket buffer — already adequate

| Setting | Value | Status |
|---|---|---|
| `SetReadBuffer` / `SetWriteBuffer` | 2 MiB | Sufficient for 10 Gbit/s / 20 ms RTT (BDP ~2.5 MiB) |

The 2 MiB socket buffer is the hard cap between OS and app. The 64 KiB read
buffer feeds from it, so anything larger than MTU (~1.5 KB) is wasted at the
per-read level. A 1 MiB buffer is a reasonable burst absorber.

## Memory Model

QUIC flow control windows are **receiver-side credits, not pre-allocated
buffers**. Memory is only consumed when data actually arrives at the receiver.
On a 10 Mbit/s link the sender cannot push enough data to fill a 64 MB window
— the network is the bottleneck. On a 10 Gbit/s link the window stays full.

This means the same settings satisfy both 10 Mbit and 10 Gbit environments
without any tuning.

## Proposed Changes

**File: `internal/network/network.go`**

1. Add constants for QUIC flow control windows:
   - `InitialStreamReceiveWindow`: 64 MiB
   - `MaxStreamReceiveWindow`: 256 MiB
   - `InitialConnectionReceiveWindow`: 64 MiB
   - `MaxConnectionReceiveWindow`: 256 MiB

2. Add constants for packet mux:
   - `packetMuxReadBuf`: 1 MiB (was 64 KiB)
   - `packetMuxQuicChCap`: 16,384 (was 256)
   - `packetMuxProbeChCap`: 64 (unchanged, kept as constant)

3. Apply these to both `quic.Config` structs in `DialQUIC` and `ListenQUIC`.

4. Apply `packetMuxReadBuf` and `packetMuxQuicChCap` to `NewPacketMux` and
   `readLoop`.

**No other files change.** The `io.Copy` 32 KiB stdlib buffer and the
`HashStream` path are negligible at this scale — the QUIC stack and packet
mux are the only components that can stall a 10 Gbit/s pipe.

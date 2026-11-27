// Package server: WebSocket signaling relay.
package server

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Server is the hermod signaling server.
type Server struct {
	store              SignalingStore
	certRL             *RateLimiter // /cert HTTP endpoint
	wsRL               *RateLimiter // WebSocket upgrade
	joinRL             *RateLimiter // join attempts (per-IP, channel enumeration)
	ttl                time.Duration
	maxBlobsPerChannel int
	maxCPaceFailures   int
	certDER            []byte // DER-encoded server certificate for the /cert endpoint
	upgrader           websocket.Upgrader
	httpServer         *http.Server
	logger             *slog.Logger

	mu         sync.Mutex
	waiters    map[uint16][]*wsConn // pending peer connections
	udpReflect *udpReflector        // UDP reflection for CGNAT address discovery; nil if unavailable

	// wsIdleTimeout is the read deadline for idle WebSocket connections.
	// Set from the --ttl flag. If no data (including pong) is received within
	// this period the connection is closed, preventing stale waiters from
	// blocking channel reuse.
	wsIdleTimeout time.Duration
}

type wsConn struct {
	conn   *websocket.Conn
	sender bool
}

// NewServer constructs a new signaling Server.
// certDER is the DER-encoded server TLS certificate served via the /cert endpoint;
// pass nil to disable the /cert endpoint.
// maxBlobsPerChannel caps the number of relayed blobs per channel; use
// DefaultMaxBlobsPerChannel for the spec default.
// maxCPaceFailures caps CPace protocol violations before the channel is
// invalidated; use DefaultMaxCPaceFailures for the spec default.
func NewServer(store SignalingStore, certRL, wsRL, joinRL *RateLimiter, ttl time.Duration, maxBlobsPerChannel, maxCPaceFailures int, certDER []byte, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		store:              store,
		certRL:             certRL,
		wsRL:               wsRL,
		joinRL:             joinRL,
		ttl:                ttl,
		wsIdleTimeout:      ttl,
		maxBlobsPerChannel: maxBlobsPerChannel,
		maxCPaceFailures:   maxCPaceFailures,
		certDER:            certDER,
		logger:             logger,
		waiters:            make(map[uint16][]*wsConn),
		upgrader: websocket.Upgrader{
			// Reject browser-sourced cross-origin WebSocket connections.
			// Non-browser clients (CLI) do not set an Origin header, so this
			// allows all legitimate hermod peers while blocking CSRF-style attacks.
			CheckOrigin: func(r *http.Request) bool {
				return r.Header.Get("Origin") == ""
			},
		},
	}
}

// ListenAndServe starts the HTTPS/WebSocket server on addr using the given TLS config.
func (s *Server) ListenAndServe(ctx context.Context, addr string, tlsCfg *tls.Config) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	return s.Serve(ctx, ln, tlsCfg)
}

// Serve starts the HTTPS/WebSocket server on the given listener using the TLS
// config.  The caller owns the listener; it is closed when the server shuts down.
func (s *Server) Serve(ctx context.Context, ln net.Listener, tlsCfg *tls.Config) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleWS)
	mux.HandleFunc("/cert", s.handleCert)

	tlsLn := tls.NewListener(ln, tlsCfg)

	s.httpServer = &http.Server{
		Addr:              ln.Addr().String(),
		Handler:           mux,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Start UDP reflection on the same port for CGNAT address discovery.
	// This allows peers behind CGNAT to learn their external UDP address
	// from the server. If the UDP bind fails (e.g. port unavailable), the
	// reflector is nil and clients will fall back to the current behaviour.
	s.udpReflect = startUDPReflector(ctx, ln.Addr().String())
	defer func() {
		if s.udpReflect != nil {
			s.udpReflect.Close()
		}
	}()

	if s.udpReflect != nil {
		s.logger.Info("UDP reflection enabled for CGNAT address discovery", "addr", ln.Addr().String())
	}

	s.logger.Info("Signaling server ready", "addr", ln.Addr().String())

	// Start background goroutine to evict stale rate-limit buckets.
	// Buckets inactive for more than 30 minutes are removed. Without this,
	// the bucket map grows unboundedly for every distinct source IP.
	cleanupCtx, cleanupCancel := context.WithCancel(ctx)
	defer cleanupCancel()
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-cleanupCtx.Done():
				return
			case <-ticker.C:
				s.certRL.Cleanup(30 * time.Minute)
				s.wsRL.Cleanup(30 * time.Minute)
				s.joinRL.Cleanup(30 * time.Minute)
				// Purge expired channel store entries and clean up any
				// stale waiters whose store entries have expired.
				expiredIDs, _ := s.store.PurgeExpired()
				if len(expiredIDs) > 0 {
					s.purgeExpiredWaiters(expiredIDs)
				}
				s.logger.Debug("Rate limiter bucket cleanup completed")
			}
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.httpServer.Serve(tlsLn)
	}()

	select {
	case <-ctx.Done():
		s.logger.Info("Shutdown signal received — stopping server")
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := s.httpServer.Shutdown(shutCtx)
		if err != nil {
			s.logger.Error("Server shutdown returned an error", "err", err)
		} else {
			s.logger.Info("Server shutdown complete")
		}
		return err
	case err := <-errCh:
		if err != nil {
			s.logger.Error("Server exited with an error", "err", err)
		}
		return err
	}
}

// handleCert serves the server's TLS certificate as PEM for client pinning.
// Clients can hash the DER bytes inside the PEM block with SHA-256 to obtain
// the fingerprint they should store via `hermod trust`.
// Rate limiting is applied to prevent abuse.
func (s *Server) handleCert(w http.ResponseWriter, r *http.Request) {
	if !s.certRL.Allow(r.RemoteAddr) {
		s.logger.Warn("cert endpoint rate-limited", "remote_addr", r.RemoteAddr)
		http.Error(w, "Too many requests. Try again later.", http.StatusTooManyRequests)
		return
	}
	if len(s.certDER) == 0 {
		http.Error(w, "Certificate not available", http.StatusNotFound)
		return
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.certDER})
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(pemBlock)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pemBlock)
}

// Shared p2p session setup used by both tx and rx: IP-family selection,
// UDP socket setup, endpoint collection, and peer candidate parsing.

package cli

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/hermod/hermod/internal/config"
	"github.com/hermod/hermod/internal/network"
)

// selectIPFamily maps the global -4/-6 flags to a network.IPFamily value.
func selectIPFamily() network.IPFamily {
	switch {
	case ipv4Only.Load():
		return network.IPFamilyV4
	case ipv6Only.Load():
		return network.IPFamilyV6
	}
	return network.IPFamilyAny
}

// resolveBindAddr enforces a strict IP family when the default ":0" bind is
// used by picking a family-specific wildcard address.
func resolveBindAddr(listenUDP string) string {
	if listenUDP != ":0" {
		return listenUDP
	}
	if ipv4Only.Load() {
		return "0.0.0.0:0"
	}
	if ipv6Only.Load() {
		return "[::]:0"
	}
	return listenUDP
}

// saveDefaultServerIfSet persists the --server URL as the config default when
// the flag was set explicitly and differs from the stored value.
func saveDefaultServerIfSet(cfg *config.Config, serverURL string, saveServer bool) error {
	if !saveServer || serverURL == cfg.ServerURL {
		return nil
	}
	config.SetDefaultServer(cfg, serverURL)
	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("save configuration: %w", err)
	}
	printStatus("Default server set to %s", serverURL)
	logInfo("Default server updated", "server", serverURL)
	return nil
}

// bindUDPAndDiscover binds the UDP socket and discovers the external UDP
// address via the signaling server's reflection endpoint. Discovery must run
// on the raw conn BEFORE the caller wraps it in the packet mux, because the
// mux readLoop would consume the reflection response. This is critical for
// peers behind CGNAT where the NAT-assigned UDP port differs from the
// TCP/WebSocket port. On discovery failure the caller falls back to the
// server-reported IP.
//
// Returns the bound conn, the local address, and the discovered external
// address (nil when discovery failed).
func bindUDPAndDiscover(ctx context.Context, listenUDP, serverURL string) (net.PacketConn, *net.UDPAddr, *net.UDPAddr, error) {
	bindAddr := resolveBindAddr(listenUDP)
	logDebug("binding UDP socket", "addr", bindAddr)
	udpConn, err := network.BindUDP(bindAddr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("bind UDP socket: %w", err)
	}
	var discoveredAddr *net.UDPAddr
	if discovered, err := discoverExternalAddr(ctx, serverURL, udpConn, 2*time.Second); err != nil {
		logDebug("external UDP address discovery failed — using server-reported IP", "err", err)
	} else {
		discoveredAddr = discovered
		logDebug("external UDP address discovered", "addr", discoveredAddr.String())
	}
	localAddr, err := network.LocalUDPAddr(udpConn)
	if err != nil {
		udpConn.Close()
		return nil, nil, nil, fmt.Errorf("get local UDP address: %w", err)
	}
	logDebug("UDP socket bound", "local_addr", localAddr.String())
	return udpConn, localAddr, discoveredAddr, nil
}

// collectEndpoints builds the local and public endpoint lists for the
// endpoint bundle. The reflected external address is preferred; the fallback
// combines the server-reported IP with the local UDP port.
func collectEndpoints(localPort int, discoveredAddr *net.UDPAddr, publicIPV4, publicIPV6 string, ipFamily network.IPFamily) (localV4, localV6 []string, publicEPV4, publicEPV6 string) {
	localV4, localV6, err := network.LocalEndpoints(localPort, ipFamily)
	if err != nil {
		localV4, localV6 = nil, nil
		logWarn("Could not enumerate local network interfaces — using public endpoint only", "err", err)
	}
	if discoveredAddr != nil {
		// Use the discovered external UDP address (CGNAT-aware).
		if discoveredAddr.IP.To4() != nil && ipFamily != network.IPFamilyV6 {
			publicEPV4 = discoveredAddr.String()
		} else if ipFamily != network.IPFamilyV4 {
			publicEPV6 = discoveredAddr.String()
		}
	} else {
		// Fall back to server-reported IP + local port.
		portStr := fmt.Sprintf("%d", localPort)
		if publicIPV4 != "" && ipFamily != network.IPFamilyV6 {
			publicEPV4 = net.JoinHostPort(publicIPV4, portStr)
		}
		if publicIPV6 != "" && ipFamily != network.IPFamilyV4 {
			publicEPV6 = net.JoinHostPort(publicIPV6, portStr)
		}
	}
	logDebug("local endpoints collected", "local_v4", localV4, "local_v6", localV6, "public_v4", publicEPV4, "public_v6", publicEPV6)
	return localV4, localV6, publicEPV4, publicEPV6
}

// parsePeerCandidates converts the peer bundle's endpoint strings into UDP
// addresses and clears candidates from the wrong family so HolePunchDual only
// tries addresses matching -4/-6.
func parsePeerCandidates(bundle *network.EndpointBundle, ipFamily network.IPFamily) ([]*net.UDPAddr, []*net.UDPAddr, error) {
	candidatesV4, err := network.ParseCandidates(bundle.CandidatesV4())
	if err != nil {
		return nil, nil, fmt.Errorf("parse IPv4 candidates: %w", err)
	}
	candidatesV6, err := network.ParseCandidates(bundle.CandidatesV6())
	if err != nil {
		return nil, nil, fmt.Errorf("parse IPv6 candidates: %w", err)
	}
	switch ipFamily {
	case network.IPFamilyV4:
		candidatesV6 = nil
	case network.IPFamilyV6:
		candidatesV4 = nil
	}
	logDebug("NAT candidates parsed", "v4_count", len(candidatesV4), "v6_count", len(candidatesV6))
	return candidatesV4, candidatesV6, nil
}

// discoverExternalAddr tries to discover the peer's external UDP address using
// the signaling server's UDP reflection endpoint. Returns the discovered address
// or an error (callers should fall back gracefully).
func discoverExternalAddr(_ context.Context, serverURL string, conn net.PacketConn, timeout time.Duration) (*net.UDPAddr, error) {
	serverUDP, err := network.ServerUDPAddr(serverURL)
	if err != nil {
		return nil, fmt.Errorf("server UDP addr: %w", err)
	}
	return network.DiscoverViaReflector(conn, serverUDP, timeout)
}

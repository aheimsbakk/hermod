// Package network: handshake payload encoding for CPace + endpoint exchange.
package network

import (
	"encoding/json"
	"fmt"
	"net"
)

// CPaceMsg carries one side's CPace public message.
type CPaceMsg struct {
	PubMsg []byte `json:"pub_msg"` // 65-byte uncompressed P-256 point
}

// EndpointBundle is encrypted with K_classical and exchanged over the relay.
type EndpointBundle struct {
	LocalEndpoints  []string `json:"local_endpoints"`  // host:port UDP candidates
	PublicEndpoint  string   `json:"public_endpoint"`  // server-reflexive host:port
	CertFingerprint string   `json:"cert_fingerprint"` // SHA-256 hex of ephemeral TLS cert
}

// EncodeCPaceMsg serializes a CPaceMsg to JSON.
func EncodeCPaceMsg(msg CPaceMsg) ([]byte, error) {
	return json.Marshal(msg)
}

// DecodeCPaceMsg deserializes a CPaceMsg from JSON.
func DecodeCPaceMsg(data []byte) (CPaceMsg, error) {
	var m CPaceMsg
	err := json.Unmarshal(data, &m)
	return m, err
}

// EncodeEndpointBundle serializes an EndpointBundle to JSON.
func EncodeEndpointBundle(b EndpointBundle) ([]byte, error) {
	return json.Marshal(b)
}

// DecodeEndpointBundle deserializes an EndpointBundle from JSON.
func DecodeEndpointBundle(data []byte) (EndpointBundle, error) {
	var b EndpointBundle
	err := json.Unmarshal(data, &b)
	return b, err
}

// ParseCandidates converts endpoint strings to *net.UDPAddr slices.
func ParseCandidates(endpoints []string) ([]*net.UDPAddr, error) {
	var addrs []*net.UDPAddr
	for _, ep := range endpoints {
		addr, err := net.ResolveUDPAddr("udp", ep)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", ep, err)
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}

// LocalEndpoints returns non-loopback local UDP candidate addresses.
func LocalEndpoints(localPort int) ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var eps []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ip.To4() != nil {
				eps = append(eps, fmt.Sprintf("%s:%d", ip.String(), localPort))
			}
		}
	}
	return eps, nil
}

// Package network: handshake payload encoding for CPace + hybrid KEM + endpoint exchange.
package network

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
)

// IPFamily restricts address collection to a single IP protocol family.
type IPFamily int

const (
	// IPFamilyAny collects both IPv4 and IPv6 addresses (default).
	IPFamilyAny IPFamily = iota
	// IPFamilyV4 collects only IPv4 addresses.
	IPFamilyV4
	// IPFamilyV6 collects only IPv6 addresses.
	IPFamilyV6
)

// EndpointBundle is encrypted with HybridBlobKey and exchanged over the relay.
type EndpointBundle struct {
	LocalEndpointsV4 []string `json:"local_endpoints_v4,omitempty"` // IPv4 host:port candidates
	LocalEndpointsV6 []string `json:"local_endpoints_v6,omitempty"` // IPv6 host:port candidates
	PublicEndpointV4 string   `json:"public_endpoint_v4,omitempty"` // server-reflexive IPv4 host:port
	PublicEndpointV6 string   `json:"public_endpoint_v6,omitempty"` // server-reflexive IPv6 host:port

	PubKeyFingerprint string `json:"public_key_fingerprint"` // SHA-256 SPKI hex of ephemeral TLS cert's public key
	RequireVerify     bool   `json:"require_verify"`         // true if this side requires SAS verification
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

// CandidatesV4 returns IPv4 candidate endpoint strings.
func (b *EndpointBundle) CandidatesV4() []string {
	var c []string
	if b.PublicEndpointV4 != "" {
		c = append(c, b.PublicEndpointV4)
	}
	return append(c, b.LocalEndpointsV4...)
}

// CandidatesV6 returns IPv6 candidate endpoint strings.
// Returns nil when no IPv6 candidates are available.
func (b *EndpointBundle) CandidatesV6() []string {
	var c []string
	if b.PublicEndpointV6 != "" {
		c = append(c, b.PublicEndpointV6)
	}
	return append(c, b.LocalEndpointsV6...)
}

// --- Hybrid KEM blob sizes (fixed-length fields for binary serialization) ---

const (
	// CPacePointSize is the byte length of an uncompressed P-256 point.
	CPacePointSize = 65
	// X25519PubSize is the byte length of an X25519 public key.
	X25519PubSize = 32
	// MLKEMEncapKeySize is the byte length of an ML-KEM-768 encapsulation key.
	MLKEMEncapKeySize = 1184
	// MLKEMCiphertextSize is the byte length of an ML-KEM-768 ciphertext.
	MLKEMCiphertextSize = 1088
)

// SenderHandshakeBlob encodes the sender's CPace message + X25519 public key.
// Format: CPacePointSize bytes + X25519PubSize bytes = 97 bytes.
func SenderHandshakeBlob(cpacePub, x25519Pub []byte) []byte {
	buf := make([]byte, CPacePointSize+X25519PubSize)
	copy(buf[0:CPacePointSize], cpacePub)
	copy(buf[CPacePointSize:], x25519Pub)
	return buf
}

// ParseSenderHandshakeBlob extracts CPace message and X25519 public key.
func ParseSenderHandshakeBlob(data []byte) (cpacePub, x25519Pub []byte, err error) {
	if len(data) < CPacePointSize+X25519PubSize {
		return nil, nil, errors.New("sender handshake blob too short")
	}
	return data[:CPacePointSize], data[CPacePointSize : CPacePointSize+X25519PubSize], nil
}

// ReceiverHandshakeBlob encodes the receiver's CPace message + X25519 public key + ML-KEM enc key.
// Format: CPacePointSize + X25519PubSize + MLKEMEncapKeySize = 1281 bytes.
func ReceiverHandshakeBlob(cpacePub, x25519Pub, mlkemEncapKey []byte) []byte {
	buf := make([]byte, CPacePointSize+X25519PubSize+MLKEMEncapKeySize)
	copy(buf[0:CPacePointSize], cpacePub)
	copy(buf[CPacePointSize:CPacePointSize+X25519PubSize], x25519Pub)
	copy(buf[CPacePointSize+X25519PubSize:], mlkemEncapKey)
	return buf
}

// ParseReceiverHandshakeBlob extracts CPace message, X25519 public key, and ML-KEM enc key.
func ParseReceiverHandshakeBlob(data []byte) (cpacePub, x25519Pub, mlkemEncapKey []byte, err error) {
	offset := CPacePointSize + X25519PubSize
	if len(data) < offset+MLKEMEncapKeySize {
		return nil, nil, nil, errors.New("receiver handshake blob too short")
	}
	return data[:CPacePointSize], data[CPacePointSize:offset], data[offset : offset+MLKEMEncapKeySize], nil
}

// SenderBundleBlob encodes the KEM ciphertext + encrypted endpoint bundle.
// Format: MLKEMCiphertextSize bytes KEM ciphertext + encrypted bundle (variable).
func SenderBundleBlob(kemCt, encBundle []byte) []byte {
	buf := make([]byte, MLKEMCiphertextSize+len(encBundle))
	copy(buf[0:MLKEMCiphertextSize], kemCt)
	copy(buf[MLKEMCiphertextSize:], encBundle)
	return buf
}

// ParseSenderBundleBlob extracts KEM ciphertext and encrypted bundle.
func ParseSenderBundleBlob(data []byte) (kemCt, encBundle []byte, err error) {
	if len(data) < MLKEMCiphertextSize {
		return nil, nil, errors.New("sender bundle blob too short")
	}
	return data[:MLKEMCiphertextSize], data[MLKEMCiphertextSize:], nil
}

// ParseCandidates converts endpoint strings to *net.UDPAddr slices.
func ParseCandidates(endpoints []string) ([]*net.UDPAddr, error) {
	var addrs []*net.UDPAddr
	for _, ep := range endpoints {
		addr, err := net.ResolveUDPAddr("udp", ep)
		if err != nil {
			return nil, fmt.Errorf("resolve UDP address %s: %w", ep, err)
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}

// LocalEndpoints returns non-loopback local UDP candidate addresses,
// split by address family.
//
// The family parameter controls which addresses are returned:
//   - IPFamilyAny: returns both IPv4 and IPv6 (default)
//   - IPFamilyV4:  returns only IPv4 addresses
//   - IPFamilyV6:  returns only IPv6 addresses
func LocalEndpoints(localPort int, family IPFamily) (v4, v6 []string, _ error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
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
			switch {
			case ip.To4() != nil:
				if family != IPFamilyV6 {
					v4 = append(v4, net.JoinHostPort(ip.String(), fmt.Sprintf("%d", localPort)))
				}
			default:
				if family != IPFamilyV4 {
					v6 = append(v6, net.JoinHostPort(ip.String(), fmt.Sprintf("%d", localPort)))
				}
			}
		}
	}
	return v4, v6, nil
}

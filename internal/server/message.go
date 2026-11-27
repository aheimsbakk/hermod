// Signaling wire message types and shared limits.

package server

const (
	maxMessageSize = 65536 // 64 KiB per signaling message

	// DefaultMaxBlobsPerChannel is the default hard cap on relayed blobs per channel.
	DefaultMaxBlobsPerChannel = 10
	// DefaultMaxCPaceFailures is the default limit on CPace handshake failures per channel.
	DefaultMaxCPaceFailures = 3
)

// MsgType identifies signaling message types.
type MsgType string

const (
	MsgAllocate  MsgType = "allocate"
	MsgJoin      MsgType = "join"
	MsgHandshake MsgType = "handshake"
	MsgBlob      MsgType = "blob"
	MsgError     MsgType = "error"
	MsgOK        MsgType = "ok"
	MsgReady     MsgType = "ready"
)

// Message is the signaling wire format.
type Message struct {
	Type      MsgType `json:"type"`
	ChannelID uint16  `json:"channel_id,omitempty"`
	Payload   []byte  `json:"payload,omitempty"`
	Error     string  `json:"error,omitempty"`
}

// Package cli: cancellation helpers for QUIC transfer connections.
package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/quic-go/quic-go"
)

// cancelCodeUser is the QUIC application error code used when a user cancels a transfer.
const cancelCodeUser quic.ApplicationErrorCode = 1

// cancelMsgSender is the QUIC close message sent when the sender cancels.
const cancelMsgSender = "cancelled:sender"

// cancelMsgReceiver is the QUIC close message sent when the receiver cancels.
const cancelMsgReceiver = "cancelled:receiver"

// cancelledByPeer inspects a QUIC error and returns a user-facing error message
// if the peer explicitly cancelled the transfer. Returns nil if the error is not
// a peer-initiated cancellation.
func cancelledByPeer(err error) error {
	if err == nil {
		return nil
	}
	var appErr *quic.ApplicationError
	if !errors.As(err, &appErr) {
		return nil
	}
	if appErr.ErrorCode != cancelCodeUser {
		return nil
	}
	msg := appErr.ErrorMessage
	switch {
	case strings.HasPrefix(msg, "cancelled:sender"):
		return fmt.Errorf("transfer cancelled by sender")
	case strings.HasPrefix(msg, "cancelled:receiver"):
		return fmt.Errorf("transfer cancelled by receiver")
	default:
		return fmt.Errorf("transfer cancelled by peer")
	}
}

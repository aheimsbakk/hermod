// Package cli: unit tests for cancellation helpers.
package cli

import (
	"fmt"
	"testing"

	"github.com/quic-go/quic-go"
)

func TestCancelledByPeer_SenderCancel(t *testing.T) {
	err := &quic.ApplicationError{
		ErrorCode:    cancelCodeUser,
		ErrorMessage: cancelMsgSender,
		Remote:       true,
	}
	got := cancelledByPeer(err)
	if got == nil {
		t.Fatal("expected non-nil error for sender cancellation")
	}
	if got.Error() != "The sender cancelled the transfer." {
		t.Fatalf("unexpected message: %q", got.Error())
	}
}

func TestCancelledByPeer_ReceiverCancel(t *testing.T) {
	err := &quic.ApplicationError{
		ErrorCode:    cancelCodeUser,
		ErrorMessage: cancelMsgReceiver,
		Remote:       true,
	}
	got := cancelledByPeer(err)
	if got == nil {
		t.Fatal("expected non-nil error for receiver cancellation")
	}
	if got.Error() != "The receiver cancelled the transfer." {
		t.Fatalf("unexpected message: %q", got.Error())
	}
}

func TestCancelledByPeer_WrongCode(t *testing.T) {
	err := &quic.ApplicationError{
		ErrorCode:    0,
		ErrorMessage: "done",
		Remote:       true,
	}
	if got := cancelledByPeer(err); got != nil {
		t.Fatalf("expected nil for non-cancel error code, got: %v", got)
	}
}

func TestCancelledByPeer_Nil(t *testing.T) {
	if got := cancelledByPeer(nil); got != nil {
		t.Fatalf("expected nil for nil error, got: %v", got)
	}
}

func TestCancelledByPeer_NonQuicError(t *testing.T) {
	err := fmt.Errorf("some other error")
	if got := cancelledByPeer(err); got != nil {
		t.Fatalf("expected nil for non-QUIC error, got: %v", got)
	}
}

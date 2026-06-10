package cli

import (
	"context"
	"errors"
	"testing"
)

func TestCancelMessage_Default(t *testing.T) {
	ctx := context.Background()
	msg := cancelMessage(ctx)
	if msg != "You cancelled SAS verification." {
		t.Fatalf("expected default cancel message, got %q", msg)
	}
}

func TestCancelMessage_CancelledByPeer(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(errSASCancelledByPeer)
	msg := cancelMessage(ctx)
	if msg != "The other side cancelled SAS verification." {
		t.Fatalf("expected peer-cancel message, got %q", msg)
	}
}

func TestCancelMessage_OtherCause(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(errors.New("some other reason"))
	msg := cancelMessage(ctx)
	if msg != "You cancelled SAS verification." {
		t.Fatalf("expected default cancel message for other cause, got %q", msg)
	}
}

func TestNewHashBar(t *testing.T) {
	bar := newHashBar(100, "testing")
	if bar == nil {
		t.Fatal("expected non-nil progress bar")
	}
}

func TestNewHashBar_Completion(t *testing.T) {
	bar := newHashBar(100, "testing")
	data := make([]byte, 100)
	n, err := bar.Write(data)
	if err != nil {
		t.Fatal(err)
	}
	if n != 100 {
		t.Fatalf("expected 100 bytes, got %d", n)
	}
	// Closing the bar triggers the OnCompletion callback
	_ = bar.Close()
}

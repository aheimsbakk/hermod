package cli

import (
	"bytes"
	"io"
	"os"
	"testing"
	"time"
)

func TestNewStreamBar(t *testing.T) {
	b := newStreamBar()
	if b == nil {
		t.Fatal("expected non-nil streamBar")
	}
	if b.dir != 1 {
		t.Fatalf("expected dir=1, got %d", b.dir)
	}
}

func TestStreamBarWrite(t *testing.T) {
	b := newStreamBar()
	n, err := b.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if n != 5 {
		t.Fatalf("expected 5 bytes written, got %d", n)
	}
	if b.total != 5 {
		t.Fatalf("expected total=5, got %d", b.total)
	}
}

func TestStreamBarFinish(t *testing.T) {
	b := newStreamBar()
	b.Write([]byte("test data"))
	b.Finish()
	// Finish should not panic
}

func TestStreamBarUpdateRate(t *testing.T) {
	b := newStreamBar()
	now := time.Now()

	b.updateRate(now)
	if b.rate != 0 {
		t.Fatalf("expected rate=0 with zero delta, got %f", b.rate)
	}

	// Set fields directly to simulate 10 bytes in 1 second
	b.total = 10
	b.lastBytes = 0
	b.lastTime = now.Add(-time.Second)
	b.updateRate(now)
	if b.rate < 9 || b.rate > 11 {
		t.Fatalf("expected rate~10, got %f", b.rate)
	}

	// Steady 10 bytes/s for another second — EMA should converge to ~10
	b.total = 20
	b.lastBytes = 10
	b.lastTime = now
	b.updateRate(now.Add(time.Second))
	if b.rate < 9 || b.rate > 11 {
		t.Fatalf("expected rate~10 after steady write, got %f", b.rate)
	}
}

func TestStreamBarRenderLine(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = w

	b := newStreamBar()
	b.Write([]byte("test data"))
	b.renderLine(time.Now())

	w.Close()
	os.Stderr = oldStderr

	out, _ := io.ReadAll(r)
	if len(out) == 0 {
		t.Fatal("expected renderLine to write to stderr")
	}
	// Output should contain the description
	if !bytes.Contains(out, []byte("sending ")) {
		t.Fatalf("expected 'sending ' in output, got %q", out)
	}
}

func TestBarHumanizeBytes(t *testing.T) {
	cases := []struct {
		input   float64
		wantVal string
		wantSuf string
	}{
		{0, " 0", " B"},
		{5, " 5", " B"},
		{9, " 9", " B"},
		{10, "10", " B"},
		{999, "999", " B"},
		{1000, "1.0", " kB"},
		{1500, "1.5", " kB"},
		{1000000, "1.0", " MB"},
		{2500000, "2.5", " MB"},
		{1000000000, "1.0", " GB"},
		{1500000000, "1.5", " GB"},
		{1000000000000, "1.0", " TB"},
		{999000000000000, "999", " TB"}, // clamped to TB, val >= 10 → %.0f
	}
	for _, tc := range cases {
		val, suf := barHumanizeBytes(tc.input)
		if val != tc.wantVal {
			t.Errorf("barHumanizeBytes(%f): got val=%q, want %q", tc.input, val, tc.wantVal)
		}
		if suf != tc.wantSuf {
			t.Errorf("barHumanizeBytes(%f): got suf=%q, want %q", tc.input, suf, tc.wantSuf)
		}
	}
}

func TestBarHumanizeBytes_RateBelow10(t *testing.T) {
	val, suf := barHumanizeBytes(3.7)
	if val != " 4" {
		t.Fatalf("expected ' 4', got %q", val)
	}
	if suf != " B" {
		t.Fatalf("expected ' B', got %q", suf)
	}
}

func TestBarHumanizeBytes_Exact(t *testing.T) {
	val, suf := barHumanizeBytes(0)
	if val != " 0" || suf != " B" {
		t.Fatalf("got %q %q, want ' 0' ' B'", val, suf)
	}
	val, suf = barHumanizeBytes(999)
	if val != "999" || suf != " B" {
		t.Fatalf("got %q %q, want '999' ' B'", val, suf)
	}
	val, suf = barHumanizeBytes(1000)
	if val != "1.0" || suf != " kB" {
		t.Fatalf("got %q %q, want '1.0' ' kB'", val, suf)
	}
}

func TestStreamBarRenderLine_Bounce(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = w

	b := newStreamBar()
	now := time.Now()

	// Multiple renders to exercise shuttle bounce, pos clamping, and travel
	for i := 0; i < 50; i++ {
		b.Write([]byte("x"))
		b.renderLine(now)
	}

	w.Close()
	os.Stderr = oldStderr

	out, _ := io.ReadAll(r)
	if len(out) == 0 {
		t.Fatal("expected renderLine output")
	}
	if !bytes.Contains(out, []byte("<=>")) {
		t.Fatal("expected shuttle in output")
	}
}

func TestStreamBarRenderLine_NegativePos(t *testing.T) {
	b := newStreamBar()
	b.pos = -5
	b.dir = -1
	b.renderLine(time.Now())
	// pos is clamped to 0 first, then b.dir is subtracted (pos += dir makes -1),
	// and since pos <= 0, dir bounces back to 1.
	if b.dir != 1 {
		t.Fatalf("expected dir=1 after bounce, got %d", b.dir)
	}
	if b.pos != -1 {
		t.Fatalf("expected pos=-1 (0 + -1), got %d", b.pos)
	}
}

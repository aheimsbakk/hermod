// Package cli: stream progress bar for transfers with unknown size.
package cli

import (
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

const (
	streamShuttle  = "<=>"
	streamDesc     = "sending "
	streamMinInner = 10                           // minimum inner bar width
	streamOverhead = len(streamDesc) + 1 + 1 + 26 // desc + [ + ] + stats reserve
	streamThrottle = 65 * time.Millisecond
)

// streamBar renders a bouncing "<=>" shuttle on "-" padding that dynamically
// resizes with the terminal on every tick, matching the style of newHashBar.
// It implements io.Writer so it can be used in an io.MultiWriter.
// Not goroutine-safe — intended for single-goroutine io.Copy loops.
type streamBar struct {
	total      int64
	lastBytes  int64
	start      time.Time
	lastTime   time.Time
	lastRender time.Time
	rate       float64 // smoothed bytes/s
	pos        int     // shuttle left-edge position
	dir        int     // +1 = right, -1 = left
}

func newStreamBar() *streamBar {
	now := time.Now()
	return &streamBar{start: now, lastTime: now, dir: 1}
}

// Write records bytes transferred and re-renders at most once per throttle window.
func (b *streamBar) Write(p []byte) (int, error) {
	b.total += int64(len(p))
	now := time.Now()
	if now.Sub(b.lastRender) >= streamThrottle {
		b.updateRate(now)
		b.renderLine(now)
		b.lastRender = now
	}
	return len(p), nil
}

// Finish renders the final state and prints a newline.
func (b *streamBar) Finish() {
	b.updateRate(time.Now())
	b.renderLine(time.Now())
	fmt.Fprint(os.Stderr, "\n")
}

func (b *streamBar) updateRate(now time.Time) {
	delta := now.Sub(b.lastTime).Seconds()
	if delta > 0 {
		instant := float64(b.total-b.lastBytes) / delta
		// Exponential moving average: α=0.3 gives smooth but responsive rate.
		if b.rate == 0 {
			b.rate = instant
		} else {
			b.rate = 0.3*instant + 0.7*b.rate
		}
	}
	b.lastBytes = b.total
	b.lastTime = now
}

func (b *streamBar) renderLine(now time.Time) {
	w, _, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil || w <= 0 {
		w = 80
	}

	innerWidth := w - streamOverhead
	if innerWidth < streamMinInner {
		innerWidth = streamMinInner
	}

	travel := innerWidth - len(streamShuttle)
	if travel < 1 {
		travel = 1
	}
	// Clamp position into [0, travel] after any resize.
	if b.pos > travel {
		b.pos = travel
	}
	if b.pos < 0 {
		b.pos = 0
	}

	bar := "[" + strings.Repeat("-", b.pos) + streamShuttle +
		strings.Repeat("-", travel-b.pos) + "]"

	// Advance shuttle and bounce.
	b.pos += b.dir
	if b.pos >= travel {
		b.dir = -1
	}
	if b.pos <= 0 {
		b.dir = 1
	}

	totalStr, totalSuffix := barHumanizeBytes(float64(b.total))
	rateStr, rateSuffix := barHumanizeBytes(b.rate)
	stats := fmt.Sprintf("(%s%s, %s%s/s)", totalStr, totalSuffix, rateStr, rateSuffix)

	fmt.Fprintf(os.Stderr, "\r%s%s %s", streamDesc, bar, stats)
	_ = now
}

// barHumanizeBytes converts a byte count to a human-readable value+suffix pair
// using SI units (1000-based), matching the format of progressbar's DefaultBytes.
func barHumanizeBytes(s float64) (string, string) {
	sizes := []string{" B", " kB", " MB", " GB", " TB"}
	if s < 10 {
		return fmt.Sprintf("%2.0f", s), sizes[0]
	}
	e := math.Floor(math.Log(s) / math.Log(1000))
	if int(e) >= len(sizes) {
		e = float64(len(sizes) - 1)
	}
	val := math.Floor(s/math.Pow(1000, e)*10+0.5) / 10
	f := "%.0f"
	if val < 10 {
		f = "%.1f"
	}
	return fmt.Sprintf(f, val), sizes[int(e)]
}

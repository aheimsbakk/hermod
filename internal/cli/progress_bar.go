// Progress bar for transfers with a known payload size. Unknown-size
// streams use streamBar (stream_bar.go).

package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/schollz/progressbar/v3"
)

// newHashBar returns a progress bar styled with '=' fill and '-' padding.
// Used for transfers with a known size. Stream transfers use streamBar instead.
func newHashBar(size int64, description string) *progressbar.ProgressBar {
	return progressbar.NewOptions64(
		size,
		progressbar.OptionSetDescription(description),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowBytes(true),
		progressbar.OptionShowTotalBytes(true),
		progressbar.OptionSetWidth(10),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionShowCount(),
		progressbar.OptionOnCompletion(func() { fmt.Fprint(os.Stderr, "\n") }),
		progressbar.OptionFullWidth(),
		progressbar.OptionSetRenderBlankState(true),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "=",
			SaucerHead:    ">",
			SaucerPadding: "-",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)
}

// Package cli implements the hermod command-line interface.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version is the application version string. Defaults to appVersion (from
// version.go, kept in sync by scripts/bump-version.sh). Can be overridden at
// build time via -ldflags "-X github.com/hermod/hermod/internal/cli.Version=x.y.z".
var Version = appVersion

// IP version enforcement flags. Set by -4/--ipv4 and -6/--ipv6 flags.
// Both default to false, meaning both families are used with IPv6 preferred.
// The flags are mutually exclusive.
var ipv4Only bool
var ipv6Only bool

func newRootCmd() *cobra.Command {
	var verboseStr string
	var quiet bool

	root := &cobra.Command{
		Use:     "hermod",
		Short:   "Hermod — secure peer-to-peer file and text transfer",
		Version: Version,
		Long: `Hermod transfers files and text directly between peers using QUIC/TLS 1.3.
All data is end-to-end encrypted and never passes through the signaling server.`,
		SilenceUsage:  true,
		SilenceErrors: false,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			level, ok := parseVerboseLevel(verboseStr)
			if !ok {
				return fmt.Errorf("invalid --verbose value %q: must be one of none, error, warning, info, debug", verboseStr)
			}
			applyVerbosity(level)
			quietMode = quiet

			// Validate -4 and -6 are mutually exclusive.
			if ipv4Only && ipv6Only {
				return fmt.Errorf("flags -4/--ipv4 and -6/--ipv6 are mutually exclusive")
			}
			return nil
		},
	}

	root.PersistentFlags().StringVar(
		&verboseStr, "verbose", "none",
		`Log verbosity: none, error, warning, info, debug`,
	)
	root.PersistentFlags().BoolVarP(
		&quiet, "quiet", "q", false,
		`Suppress status output. Errors are always shown. Compatible with --verbose.`,
	)
	root.PersistentFlags().BoolVarP(
		&ipv4Only, "ipv4", "4", false,
		`Use IPv4 only for hole punching. Cannot be combined with -6.`,
	)
	root.PersistentFlags().BoolVarP(
		&ipv6Only, "ipv6", "6", false,
		`Use IPv6 only for hole punching. Cannot be combined with -4.`,
	)

	// Cobra auto-generates --version from cmd.Version. Add -V as short alias.
	root.Flags().BoolP("version", "V", false, "Print version and exit")

	root.AddCommand(newServeCmd())
	root.AddCommand(newTrustCmd())
	root.AddCommand(newTxCmd())
	root.AddCommand(newRxCmd())
	return root
}

// Execute runs the root command using os.Args.
func Execute() error {
	return newRootCmd().Execute()
}

// ExecuteArgs runs the root command with the given arguments.
// args[0] is the program name (e.g. "hermod"); args[1:] are the sub-command and flags.
func ExecuteArgs(args []string) error {
	cmd := newRootCmd()
	cmd.SetArgs(args[1:])
	return cmd.Execute()
}

// printStatus writes a user-facing status line to stderr.
// Suppressed when --quiet is active.
func printStatus(format string, a ...any) {
	if quietMode {
		return
	}
	fmt.Fprintf(os.Stderr, format+"\n", a...)
}

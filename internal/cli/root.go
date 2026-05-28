// Package cli implements the hermod command-line interface.
package cli

import (
	"github.com/spf13/cobra"
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "hermod",
		Short: "Hermod — secure peer-to-peer file and text transfer",
		Long: `Hermod transfers files and text directly between peers using QUIC/TLS 1.3.
All data is end-to-end encrypted and never passes through the signaling server.`,
		SilenceUsage:  true,
		SilenceErrors: false,
	}
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

// Package e2e contains end-to-end tests for hermod using testscript.
package e2e_test

import (
	"os"
	"testing"

	"github.com/hermod/hermod/internal/cli"
	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	os.Exit(testscript.RunMain(m, map[string]func() int{
		"hermod": func() int {
			if err := cli.Execute(); err != nil {
				return 1
			}
			return 0
		},
	}))
}

func TestScripts(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir:  "testdata/scripts",
		Cmds: scriptCmds(),
	})
}

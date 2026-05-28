// Package main is the hermod binary entry point.
package main

import (
	"os"

	"github.com/hermod/hermod/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}

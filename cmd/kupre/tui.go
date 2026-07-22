package main

import (
	"github.com/Rusty-Gopher/kupre/pkg/tui"
	"github.com/spf13/cobra"
)

// runTUI launches the interactive terminal UI.
func runTUI(cmd *cobra.Command) error {
	return tui.Run(tui.Options{
		Kubeconfig: global.kubeconfig,
		Context:    global.context,
	})
}

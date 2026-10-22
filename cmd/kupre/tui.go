package main

import (
	"time"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
	"github.com/Rusty-Gopher/kupre/pkg/tui"
	"github.com/spf13/cobra"
)

// runTUI launches the interactive terminal UI. A ./.kupre.yaml applies here
// exactly as it does to scripted runs, so both views agree on the verdict.
func runTUI(cmd *cobra.Command) error {
	pol, _, err := loadPolicy(checkFlags{})
	if err != nil {
		return err
	}
	opts := tui.Options{
		Kubeconfig: global.kubeconfig,
		Context:    global.context,
	}
	if pol != nil {
		opts.Finalize = func(r *analyzer.Report) { pol.ApplyTo(r, time.Now()) }
	}
	return tui.Run(opts)
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
	"github.com/Rusty-Gopher/kupre/pkg/fleet"
	"github.com/Rusty-Gopher/kupre/pkg/report"
	"github.com/spf13/cobra"
)

// fleetFlags holds options for the fleet subcommand.
type fleetFlags struct {
	targetVersion string
	output        string
	contexts      []string
	concurrency   int
	timeout       time.Duration
	verbose       bool
}

// newFleetCmd builds the `kupre fleet` subcommand.
func newFleetCmd() *cobra.Command {
	var f fleetFlags

	cmd := &cobra.Command{
		Use:   "fleet",
		Short: "Run preflight checks across every kubeconfig context",
		Long: "Scans multiple clusters in one run, one per kubeconfig context.\n\n" +
			"A cluster that cannot be reached is reported as failed rather than aborting\n" +
			"the run. The exit code reflects the worst result across the fleet.",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFleet(cmd, f)
		},
	}

	fs := cmd.Flags()
	fs.StringVar(&f.targetVersion, "target-version", "",
		"Kubernetes version to upgrade to, e.g. 1.37.0 (required)")
	fs.StringVarP(&f.output, "output", "o", "table",
		"output format: table, json, or markdown")
	fs.StringSliceVar(&f.contexts, "contexts", nil,
		"limit the scan to these contexts (default: every context in the kubeconfig)")
	fs.IntVar(&f.concurrency, "concurrency", 4, "how many clusters to scan at once")
	fs.DurationVar(&f.timeout, "timeout", 10*time.Minute, "overall timeout for the fleet scan")
	fs.BoolVarP(&f.verbose, "verbose", "v", false, "include passing and skipped checks")

	_ = cmd.MarkFlagRequired("target-version")
	return cmd
}

// runFleet scans every selected context and renders the aggregate result.
func runFleet(cmd *cobra.Command, f fleetFlags) error {
	target, err := analyzer.ParseVersion(f.targetVersion)
	if err != nil {
		return fmt.Errorf("--target-version: %w", err)
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), f.timeout)
	defer cancel()

	out := cmd.OutOrStdout()
	opts := report.Options{
		Verbose: f.verbose,
		NoColor: global.noColor || !isTerminal(out),
	}

	scanner := &fleet.Scanner{
		Kubeconfig:    global.kubeconfig,
		Contexts:      f.contexts,
		Concurrency:   f.concurrency,
		TargetVersion: target,
	}

	fr, err := scanner.Scan(ctx)
	if err != nil {
		return fmt.Errorf("fleet scan: %w", err)
	}

	switch strings.ToLower(f.output) {
	case "html":
		return fmt.Errorf("--output html is per-cluster only; run kupre check --context <name> -o html for each cluster")
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(fr); err != nil {
			return fmt.Errorf("encode fleet report: %w", err)
		}
	default:
		writer, err := formatWriter(f.output)
		if err != nil {
			return err
		}
		for _, res := range fr.Results {
			if res.Report == nil {
				fmt.Fprintf(out, "\n=== %s: unreachable - %s\n", res.Context, res.Error)
				continue
			}
			fmt.Fprintf(out, "\n=== %s\n\n", res.Context)
			if err := writer(out, res.Report, opts); err != nil {
				return err
			}
		}
		writeFleetSummary(out, fr, opts)
	}

	if code := fr.ExitCode(); code != exitOK {
		return exitWith(code)
	}
	return nil
}

// writeFleetSummary renders the aggregate verdict across all clusters.
func writeFleetSummary(out io.Writer, fr *fleet.FleetReport, _ report.Options) {
	sum := fr.Summarize()
	ready, blocked, unreachable := 0, 0, 0
	for _, r := range fr.Results {
		switch {
		case r.Report == nil:
			unreachable++
		case r.Report.ExitCode() == exitBlocked:
			blocked++
		case r.Report.ExitCode() == exitOK:
			ready++
		}
	}

	fmt.Fprintf(out, "\n=== fleet summary\n\n")
	fmt.Fprintf(out, "clusters scanned: %d - %d ready, %d blocked, %d unreachable\n",
		len(fr.Results), ready, blocked, unreachable)
	fmt.Fprintf(out, "findings: %d blocking, %d warnings, %d passed\n",
		sum.Blocking, sum.Concerning, sum.Passed)
}

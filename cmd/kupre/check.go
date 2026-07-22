package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
	"github.com/Rusty-Gopher/kupre/pkg/provider"
	"github.com/Rusty-Gopher/kupre/pkg/report"

	// Register the provider plugins for auto-detection.
	_ "github.com/Rusty-Gopher/kupre/pkg/provider/capi"
	_ "github.com/Rusty-Gopher/kupre/pkg/provider/kubeadm"
	_ "github.com/Rusty-Gopher/kupre/pkg/provider/openstack"
	"github.com/spf13/cobra"
)

// Exit codes, mirrored from the analyzer package for CLI use.
const (
	exitOK        = analyzer.ExitOK
	exitBlocked   = analyzer.ExitBlocked
	exitWarnings  = analyzer.ExitWarnings
	exitToolError = analyzer.ExitToolError
)

// checkFlags holds options specific to the check subcommand.
type checkFlags struct {
	targetVersion string
	output        string
	verbose       bool
	maxResources  int
	timeout       time.Duration
	failOnWarn    bool
	quiet         bool
}

// newMissionCmd builds a non-interactive subcommand for one mission.
func newMissionCmd(missionName, use, short string) *cobra.Command {
	var f checkFlags

	mission, ok := analyzer.MissionByName(missionName)
	if !ok {
		panic("unknown mission " + missionName)
	}

	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Long: short + "\n\n" +
			"Exit codes: 0 all clear, 1 blocking issues, 2 warnings only, 3 tool error.",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCheck(cmd, f, mission)
		},
	}

	fs := cmd.Flags()
	if mission.NeedsTarget {
		fs.StringVar(&f.targetVersion, "target-version", "",
			"Kubernetes version to upgrade to, e.g. 1.36.0 (required)")
	}
	fs.StringVarP(&f.output, "output", "o", "table",
		"output format: table (an ordered worklist), flat, json, markdown, or html")
	fs.BoolVarP(&f.verbose, "verbose", "v", false,
		"include passing and skipped checks in the output")
	fs.IntVar(&f.maxResources, "max-resources", 10,
		"maximum affected resources to list per finding (-1 for unlimited)")
	fs.DurationVar(&f.timeout, "timeout", 2*time.Minute,
		"overall timeout for the scan")
	fs.BoolVar(&f.failOnWarn, "fail-on-warn", false,
		"exit non-zero (1) when only warnings are found")
	fs.BoolVarP(&f.quiet, "quiet", "q", false,
		"suppress the banner")

	if mission.NeedsTarget {
		_ = cmd.MarkFlagRequired("target-version")
	}
	return cmd
}

// runCheck connects to the cluster, runs the engine, renders the report, and
// sets the process exit code.
func runCheck(cmd *cobra.Command, f checkFlags, mission analyzer.Mission) error {
	var target analyzer.Version
	if mission.NeedsTarget {
		var err error
		if target, err = analyzer.ParseVersion(f.targetVersion); err != nil {
			return fmt.Errorf("--target-version: %w", err)
		}
	}

	writer, err := formatWriter(f.output)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), f.timeout)
	defer cancel()

	out := cmd.OutOrStdout()
	opts := report.Options{
		Verbose:      f.verbose,
		NoColor:      global.noColor || !isTerminal(out),
		MaxResources: f.maxResources,
	}

	// The banner is decoration; it must never contaminate machine-readable output.
	if !f.quiet && (f.output == "table" || f.output == "worklist" || f.output == "flat") {
		report.WriteBanner(out, opts)
	}

	cluster, err := analyzer.Connect(ctx, global.kubeconfig, global.context)
	if err != nil {
		return fmt.Errorf("connect to cluster: %w", err)
	}

	// Missions without a target analyze the cluster as it stands.
	if !mission.NeedsTarget {
		target = cluster.ServerVersion
	}
	up := analyzer.Upgrade{From: cluster.ServerVersion, To: target}

	engine := analyzer.NewEngine(mission.Checks()...)
	providerChecks, detectFailures := provider.ChecksFor(ctx, cluster)
	for _, pc := range providerChecks {
		if mission.ProviderChecks != nil && mission.ProviderChecks(pc.Name) {
			engine.Register(pc)
		}
	}

	rep := engine.Run(ctx, cluster, up)
	rep.Mission = mission.Name
	// A provider that could not even determine applicability leaves a hole in
	// the scan; record it as a tool error so the verdict is inconclusive.
	rep.Errors = append(rep.Errors, detectFailures...)

	// HTML is a browser artifact, not terminal output. When stdout is a
	// terminal, write the report to a file beside the working directory and
	// say where; a redirected stdout keeps the plain streaming behavior so
	// scripts and pipes work unchanged.
	if strings.ToLower(f.output) == "html" && isTerminal(out) {
		path := fmt.Sprintf("kupre-%s-report.html", mission.Name)
		file, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("create %s: %w", path, err)
		}
		werr := writer(file, rep, opts)
		cerr := file.Close()
		if werr != nil {
			return werr
		}
		if cerr != nil {
			return fmt.Errorf("write %s: %w", path, cerr)
		}
		abs, _ := filepath.Abs(path)
		fmt.Fprintf(out, "HTML report written to %s\n", abs)
	} else if err := writer(out, rep, opts); err != nil {
		return err
	}

	code := rep.ExitCode()
	if f.failOnWarn && code == exitWarnings {
		code = exitBlocked
	}
	if code != exitOK {
		return exitWith(code)
	}
	return nil
}

// formatFunc renders a report to a writer.
type formatFunc func(io.Writer, *analyzer.Report, report.Options) error

// formatWriter resolves the --output flag to a renderer.
func formatWriter(format string) (formatFunc, error) {
	switch strings.ToLower(format) {
	case "table", "worklist", "":
		return report.WriteWorklist, nil
	case "flat", "report":
		return report.WriteTable, nil
	case "json":
		return report.WriteJSON, nil
	case "markdown", "md":
		return report.WriteMarkdown, nil
	case "html":
		return report.WriteHTML, nil
	default:
		return nil, fmt.Errorf("--output: unknown format %q (want table, flat, json, markdown, or html)", format)
	}
}

// isTerminal reports whether w is an interactive terminal, used to decide
// whether ANSI color is appropriate.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

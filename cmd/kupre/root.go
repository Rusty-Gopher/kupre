// Package main implements the kupre command-line interface.
package main

import (
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"
)

// version is the kupre release, overridable at build time via -ldflags.
var version = "dev"

// go install builds carry no ldflags, but the module version is recorded in
// the binary's build info; use it so `go install ...@v0.2.1` reports 0.2.1.
func init() {
	if version != "dev" {
		return
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if v := bi.Main.Version; v != "" && v != "(devel)" {
			version = strings.TrimPrefix(v, "v")
		}
	}
}

// globalFlags holds options shared by every subcommand.
type globalFlags struct {
	kubeconfig string
	context    string
	noColor    bool
}

var global globalFlags

// newRootCmd builds the top-level command. With no subcommand it launches the
// interactive TUI.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "kupre",
		Short: "Kubernetes preflight & review engine",
		Long: "kupre analyzes live Kubernetes clusters, read-only. Three missions:\n" +
			"  check    upgrade preflight against a target version\n" +
			"  health   what is wrong right now, and why\n" +
			"  certs    every certificate a read-only client can see\n\n" +
			"First time here? Try:\n" +
			"  kupre contexts                              # which clusters can I see?\n" +
			"  kupre checks                                # what does it look for?\n" +
			"  kupre check --target-version 1.37.0         # upgrade preflight\n" +
			"  kupre health                                # health check\n" +
			"  kupre                                       # interactive mode",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTUI(cmd)
		},
	}

	pf := root.PersistentFlags()
	pf.StringVar(&global.kubeconfig, "kubeconfig", "",
		"path to kubeconfig (defaults to $KUBECONFIG, then ~/.kube/config)")
	pf.StringVar(&global.context, "context", "",
		"kubeconfig context to use (defaults to current-context)")
	pf.BoolVar(&global.noColor, "no-color", false, "disable colored output")

	root.AddCommand(newMissionCmd("upgrade", "check",
		"Upgrade preflight: is the cluster ready for a target Kubernetes version?"))
	root.AddCommand(newMissionCmd("health", "health",
		"Health check: what is wrong with this cluster right now, and why?"))
	root.AddCommand(newMissionCmd("certs", "certs",
		"Certificate audit: everything a read-only client can see, and when it expires."))
	root.AddCommand(newContextsCmd())
	root.AddCommand(newChecksCmd())
	root.AddCommand(newFleetCmd())
	root.AddCommand(newVersionCmd())
	return root
}

// newVersionCmd prints version information.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the kupre version",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "kupre %s\n", version)
		},
	}
}

// exitError carries a process exit code up to main. Commands return one instead
// of calling os.Exit directly: exiting from inside a Cobra handler skips
// deferred cleanup and makes the CLI impossible to drive from a test.
type exitError struct {
	code int
	err  error
}

func (e exitError) Error() string {
	if e.err != nil {
		return e.err.Error()
	}
	return fmt.Sprintf("exit status %d", e.code)
}

func (e exitError) Unwrap() error { return e.err }

// exitWith returns an error that terminates the process with the given code and
// no message. Used for scan verdicts, which have already printed their report.
func exitWith(code int) error { return exitError{code: code} }

// run executes the CLI and returns the process exit code.
func run(args []string) int {
	root := newRootCmd()
	root.SetArgs(args)

	err := root.Execute()
	if err == nil {
		return exitOK
	}

	var ee exitError
	if errors.As(err, &ee) {
		if ee.err != nil {
			fmt.Fprintf(os.Stderr, "kupre: %v\n", ee.err)
		}
		return ee.code
	}

	fmt.Fprintf(os.Stderr, "kupre: %v\n", err)
	return exitToolError
}

func main() { os.Exit(run(os.Args[1:])) }

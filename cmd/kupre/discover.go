package main

import (
	"fmt"
	"sort"
	"text/tabwriter"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
	"github.com/Rusty-Gopher/kupre/pkg/deprecation"
	"github.com/Rusty-Gopher/kupre/pkg/provider"
	"github.com/Rusty-Gopher/kupre/pkg/tui"
	"github.com/spf13/cobra"
)

// newContextsCmd lists the clusters available in the kubeconfig. It is the
// natural first command for someone who has just installed kupre and does not
// yet know what it can see.
func newContextsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "contexts",
		Short: "List the clusters kupre can see in your kubeconfig",
		Long: "Shows every context in the kubeconfig, marking the current one.\n\n" +
			"This performs no cluster access at all - it only reads the kubeconfig file.",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			names, current, err := tui.ListContexts(global.kubeconfig)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			for _, n := range names {
				marker := "  "
				if n == current {
					marker = "* "
				}
				fmt.Fprintf(out, "%s%s\n", marker, n)
			}
			fmt.Fprintf(out, "\n%d context(s). * marks the current one.\n", len(names))
			fmt.Fprintf(out, "Scan one with: kupre check --context <name> --target-version <version>\n")
			return nil
		},
	}
}

// newChecksCmd lists every check kupre can run, without contacting a cluster.
func newChecksCmd() *cobra.Command {
	var (
		category string
		verbose  bool
	)

	cmd := &cobra.Command{
		Use:   "checks",
		Short: "List every preflight check kupre performs",
		Long: "Lists the built-in checks and what each one looks for.\n\n" +
			"Provider-specific checks (OpenStack, etc.) are listed too, but at scan\n" +
			"time they only run on clusters where that provider is auto-detected.",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			checks := analyzer.AllChecks()
			for _, p := range provider.Registered() {
				checks = append(checks, p.Checks()...)
			}

			sort.Slice(checks, func(i, j int) bool {
				if checks[i].Category != checks[j].Category {
					return checks[i].Category < checks[j].Category
				}
				return checks[i].Name < checks[j].Name
			})

			out := cmd.OutOrStdout()
			w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)

			var lastCat analyzer.Category
			shown := 0
			for _, c := range checks {
				if category != "" && string(c.Category) != category {
					continue
				}
				if c.Category != lastCat {
					if lastCat != "" {
						fmt.Fprintln(w, "\t\t")
					}
					fmt.Fprintf(w, "%s\t\t\n", upper(string(c.Category)))
					lastCat = c.Category
				}
				fmt.Fprintf(w, "  %s\t%s\t%s\n", c.Name, c.Severity, c.Description)
				if verbose {
					if c.Evidence != "" {
						fmt.Fprintf(w, "  \t\t  inspects: %s\n", c.Evidence)
					}
					if c.Limits != "" {
						fmt.Fprintf(w, "  \t\t  cannot conclude: %s\n", c.Limits)
					}
				}
				shown++
			}
			w.Flush()

			fmt.Fprintf(out, "\n%d check(s).\n", shown)
			fmt.Fprintf(out, "Severity decides whether a failure blocks the upgrade: "+
				"error blocks (exit 1), warning does not (exit 2).\n")
			fmt.Fprintf(out, "\nDeprecation data verified against Kubernetes %s on %s.\n",
				deprecation.DataHorizon, deprecation.DataHorizonVerified)
			return nil
		},
	}

	cmd.Flags().StringVar(&category, "category", "",
		"show only one category: api, webhook, storage, node, workload, cloud")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false,
		"show what each check inspects and what it cannot conclude")
	return cmd
}

// upper uppercases an ASCII string for section headers.
func upper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}

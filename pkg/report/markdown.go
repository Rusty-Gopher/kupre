package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
)

// WriteMarkdown renders the report as markdown suitable for pasting into a PR
// description or a change ticket.
func WriteMarkdown(w io.Writer, r *analyzer.Report, opts Options) error {
	sum := r.Summarize()

	fmt.Fprintf(w, "# Upgrade preflight: `%s`\n\n", r.Cluster)
	fmt.Fprintf(w, "**%s**\n\n", missionHeading(r))

	switch verdict(sum, r) {
	case "blocked":
		fmt.Fprintf(w, "> **Hold launch** - %d blocking issue(s) found.\n\n", sum.Blocking)
	case "warnings":
		fmt.Fprintf(w, "> **Proceed with caution** - %d warning(s).\n\n", sum.Concerning)
	case "inconclusive":
		fmt.Fprintf(w, "> **Inconclusive** - some checks could not run.\n\n")
	default:
		fmt.Fprintf(w, "> **All systems nominal** - no issues found.\n\n")
	}

	fmt.Fprintf(w, "| | Count |\n|---|---|\n")
	fmt.Fprintf(w, "| Blocking | %d |\n", sum.Blocking)
	fmt.Fprintf(w, "| Warnings | %d |\n", sum.Concerning)
	fmt.Fprintf(w, "| Passed | %d |\n", sum.Passed)
	fmt.Fprintf(w, "| Skipped | %d |\n", sum.Skipped)
	if sum.Errored > 0 {
		fmt.Fprintf(w, "| Errored | %d |\n", sum.Errored)
	}
	fmt.Fprintln(w)

	for _, tl := range r.Errors {
		fmt.Fprintf(w, "- **Tool error:** %s\n", tl)
	}

	groups := r.Worklist()
	if len(groups) == 0 {
		fmt.Fprintln(w, "No issues found.")
		return nil
	}

	n := 0
	for _, g := range groups {
		fmt.Fprintf(w, "## %s\n\n", g.Bucket.TitleFor(r.Mission))
		for _, f := range g.Findings {
			n++
			writeMarkdownFinding(w, n, f, opts)
		}
	}
	return nil
}

// mdStatus returns the markdown label for a finding.
func mdStatus(f analyzer.Finding) string {
	switch {
	case f.Error != "":
		return "ERROR"
	case f.Blocking():
		return "FAIL"
	case f.Concerning():
		return "WARN"
	case f.Result != nil && f.Result.Status == analyzer.StatusSkip:
		return "SKIP"
	default:
		return "PASS"
	}
}

// writeMarkdownFinding renders one finding as a markdown section.
func writeMarkdownFinding(w io.Writer, n int, f analyzer.Finding, opts Options) {
	msg := ""
	if f.Result != nil {
		msg = f.Result.Message
	}
	if f.Error != "" {
		msg = "check could not run: " + f.Error
	}

	fmt.Fprintf(w, "### %d. %s\n\n", n, msg)
	fmt.Fprintf(w, "*`%s` · %s · %s · severity %s*\n\n",
		f.Check, mdStatus(f), f.Category, f.Severity)

	if f.Result == nil {
		return
	}

	if len(f.Result.Resources) > 0 {
		limit := opts.resourceLimit()
		fmt.Fprint(w, "<details><summary>Affected resources</summary>\n\n")
		for i, res := range f.Result.Resources {
			if i >= limit {
				fmt.Fprintf(w, "- _… and %d more_\n", len(f.Result.Resources)-limit)
				break
			}
			line := "- `" + res.String() + "`"
			if res.Detail != "" {
				line += " - " + res.Detail
			}
			fmt.Fprintln(w, line)
		}
		fmt.Fprint(w, "\n</details>\n\n")
	}

	if f.Result.Remediation != "" {
		fmt.Fprintf(w, "**Fix:** %s\n\n", strings.TrimSpace(f.Result.Remediation))
	}
	if len(f.Result.Commands) > 0 {
		fmt.Fprintf(w, "```bash\n%s\n```\n\n", strings.Join(f.Result.Commands, "\n"))
	}
	if f.Result.Docs != "" {
		fmt.Fprintf(w, "[Documentation](%s)\n\n", f.Result.Docs)
	}
}

// Package report renders preflight results in human- and machine-readable forms.
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
)

// Options controls report rendering.
type Options struct {
	// Verbose includes passing and skipped checks in the output.
	Verbose bool
	// NoColor disables ANSI escapes.
	NoColor bool
	// MaxResources caps how many affected resources are listed per finding.
	// Zero means the default of 10; a negative value means unlimited.
	MaxResources int
}

// resourceLimit resolves the effective per-finding resource cap.
func (o Options) resourceLimit() int {
	switch {
	case o.MaxResources == 0:
		return 10
	case o.MaxResources < 0:
		return int(^uint(0) >> 1)
	default:
		return o.MaxResources
	}
}

// ANSI escape codes used for terminal output.
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiBlue   = "\033[34m"
	ansiTeal   = "\033[36m"
)

// colorizer applies or strips ANSI codes according to the options.
type colorizer struct{ enabled bool }

func (c colorizer) wrap(code, s string) string {
	if !c.enabled {
		return s
	}
	return code + s + ansiReset
}

func (c colorizer) bold(s string) string   { return c.wrap(ansiBold, s) }
func (c colorizer) dim(s string) string    { return c.wrap(ansiDim, s) }
func (c colorizer) red(s string) string    { return c.wrap(ansiRed, s) }
func (c colorizer) green(s string) string  { return c.wrap(ansiGreen, s) }
func (c colorizer) yellow(s string) string { return c.wrap(ansiYellow, s) }
func (c colorizer) blue(s string) string   { return c.wrap(ansiBlue, s) }
func (c colorizer) teal(s string) string   { return c.wrap(ansiTeal, s) }

// Banner is the kupre startup banner.
const Banner = `    __
   / /___  ______  ________
  / //_/ / / / __ \/ ___/ _ \
 / ,< / /_/ / /_/ / /  /  __/
/_/|_|\__,_/ .___/_/   \___/
          /_/`

// WriteBanner renders the ASCII banner and tagline.
func WriteBanner(w io.Writer, opts Options) {
	c := colorizer{enabled: !opts.NoColor}
	fmt.Fprintln(w, c.teal(Banner))
	fmt.Fprintln(w, c.dim("  KUBERNETES PREFLIGHT & REVIEW ENGINE"))
	fmt.Fprintln(w)
}

// statusGlyph returns the colored marker for a finding.
func statusGlyph(c colorizer, f analyzer.Finding) string {
	switch {
	case f.Error != "":
		return c.red("  ??")
	case f.Blocking():
		return c.red("FAIL")
	case f.Concerning():
		return c.yellow("WARN")
	case f.Result != nil && f.Result.Status == analyzer.StatusSkip:
		return c.dim("SKIP")
	default:
		return c.green("PASS")
	}
}

// WriteTable renders the report as a human-readable table.
func WriteTable(w io.Writer, r *analyzer.Report, opts Options) error {
	c := colorizer{enabled: !opts.NoColor}
	sum := r.Summarize()

	fmt.Fprintf(w, "%s %s\n", c.dim("cluster:"), c.bold(r.Cluster))
	fmt.Fprintf(w, "%s %s → %s\n\n", c.dim("upgrade:"),
		c.bold(r.Upgrade.From.String()), c.bold(r.Upgrade.To.String()))

	for _, tl := range r.Errors {
		fmt.Fprintf(w, "%s %s\n", c.red("  ??"), tl)
	}
	if len(r.Errors) > 0 {
		fmt.Fprintln(w)
	}

	shown := 0
	for _, f := range r.Findings {
		interesting := f.Error != "" || f.Blocking() || f.Concerning()
		if !interesting && !opts.Verbose {
			continue
		}
		shown++
		writeFinding(w, c, f, opts)
	}

	if shown == 0 {
		fmt.Fprintf(w, "%s\n\n", c.dim("  no issues found"))
	}

	writeSummary(w, c, sum, r)
	return nil
}

// writeFinding renders one finding with its resources and remediation.
func writeFinding(w io.Writer, c colorizer, f analyzer.Finding, opts Options) {
	msg := ""
	if f.Result != nil {
		msg = f.Result.Message
	}
	if f.Error != "" {
		msg = "check could not run: " + f.Error
	}

	fmt.Fprintf(w, "%s  %s %s\n", statusGlyph(c, f),
		c.bold(f.Check), c.dim("["+string(f.Category)+"]"))
	fmt.Fprintf(w, "      %s\n", msg)

	if f.Result == nil {
		fmt.Fprintln(w)
		return
	}

	limit := opts.resourceLimit()
	for i, res := range f.Result.Resources {
		if i >= limit {
			fmt.Fprintf(w, "      %s\n",
				c.dim(fmt.Sprintf("… and %d more", len(f.Result.Resources)-limit)))
			break
		}
		line := "      • " + res.String()
		if res.Detail != "" {
			line += c.dim("  " + res.Detail)
		}
		fmt.Fprintln(w, line)
	}

	if f.Result.Remediation != "" {
		fmt.Fprintf(w, "      %s %s\n", c.blue("fix:"), wrapText(f.Result.Remediation, 72, "           "))
	}
	if f.Result.Docs != "" {
		fmt.Fprintf(w, "      %s %s\n", c.blue("doc:"), c.dim(f.Result.Docs))
	}
	fmt.Fprintln(w)
}

// writeSummary renders the trailing verdict line.
func writeSummary(w io.Writer, c colorizer, sum analyzer.Summary, r *analyzer.Report) {
	parts := []string{
		c.green(fmt.Sprintf("%d passed", sum.Passed)),
	}
	if sum.Concerning > 0 {
		parts = append(parts, c.yellow(fmt.Sprintf("%d warning", sum.Concerning)))
	}
	if sum.Blocking > 0 {
		parts = append(parts, c.red(fmt.Sprintf("%d blocking", sum.Blocking)))
	}
	if sum.Skipped > 0 {
		parts = append(parts, c.dim(fmt.Sprintf("%d skipped", sum.Skipped)))
	}
	if sum.Errored > 0 {
		parts = append(parts, c.red(fmt.Sprintf("%d errored", sum.Errored)))
	}
	fmt.Fprintf(w, "%s  %s\n", c.dim("summary:"), strings.Join(parts, c.dim(" · ")))

	switch {
	case sum.Blocking > 0:
		fmt.Fprintf(w, "\n%s\n", c.red(c.bold(fmt.Sprintf(
			"hold launch - %d issue(s) found", sum.Blocking))))
	case sum.Concerning > 0:
		fmt.Fprintf(w, "\n%s\n", c.yellow(c.bold(fmt.Sprintf(
			"proceed with caution - %d warning(s)", sum.Concerning))))
	case sum.Errored > 0:
		fmt.Fprintf(w, "\n%s\n", c.red(c.bold("inconclusive - some checks could not run")))
	default:
		fmt.Fprintf(w, "\n%s\n", c.green(c.bold("all systems nominal")))
	}
	_ = r
}

// wrapText wraps s at width columns, indenting continuation lines.
func wrapText(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	lineLen := 0
	for i, word := range words {
		switch {
		case i == 0:
			b.WriteString(word)
			lineLen = len(word)
		case lineLen+1+len(word) > width:
			b.WriteString("\n" + indent + word)
			lineLen = len(word)
		default:
			b.WriteString(" " + word)
			lineLen += 1 + len(word)
		}
	}
	return b.String()
}

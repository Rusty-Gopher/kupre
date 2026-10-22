package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
)

// WriteWorklist renders the report as an ordered plan of work rather than a
// flat list of findings.
//
// The distinction matters: a report answers "what is wrong with this cluster",
// which is not the question an operator preparing a maintenance window is
// asking. They are asking "what do I have to do, and in what order". Sections
// are therefore ordered by when the work has to happen - things needing lead
// time come before quick fixes, because starting them late is what actually
// derails an upgrade.
func WriteWorklist(w io.Writer, r *analyzer.Report, opts Options) error {
	c := colorizer{enabled: !opts.NoColor}
	sum := r.Summarize()
	groups := r.Worklist()

	writeVerdict(w, c, r, sum)

	for _, tl := range r.Errors {
		fmt.Fprintf(w, "%s %s\n", c.red("  !!"), tl)
	}
	if len(r.Errors) > 0 {
		fmt.Fprintln(w)
	}

	if len(groups) == 0 {
		fmt.Fprintf(w, "%s\n\n", c.dim("  Nothing to do - no findings."))
	}

	item := 0
	for _, g := range groups {
		// The "not blocking" tail is collapsed by default. It is real, but
		// showing it at full length buries the work that actually matters.
		if g.Bucket == analyzer.BucketReviewLater && !opts.Verbose {
			writeCollapsed(w, c, g, r.Mission)
			continue
		}
		if g.Bucket == analyzer.BucketAccepted && !opts.Verbose {
			writeAccepted(w, c, g, r.Mission)
			continue
		}
		fmt.Fprintf(w, "\n%s\n", bucketHeading(c, g.Bucket, r.Mission))
		for _, f := range g.Findings {
			item++
			writeWorkItem(w, c, item, f, opts)
		}
	}

	if opts.Verbose {
		writePassing(w, c, r)
	} else if sum.Passed+sum.Skipped > 0 {
		fmt.Fprintf(w, "%s\n\n", c.dim(fmt.Sprintf(
			"  %d check(s) passed, %d not applicable. -v shows them, and what each check cannot see.",
			sum.Passed, sum.Skipped)))
	}

	writeFooter(w, c, r, sum)
	return nil
}

// writeVerdict prints the one-line answer at the top, where it is read first.
func writeVerdict(w io.Writer, c colorizer, r *analyzer.Report, sum analyzer.Summary) {
	fmt.Fprintf(w, "%s %s   %s\n",
		c.dim("cluster"), c.bold(r.Cluster), c.dim(missionHeading(r)))

	words := verdictWordsFor(r.Mission)
	var verdict string
	switch {
	case len(r.Errors) > 0 || sum.Errored > 0:
		verdict = c.red(c.bold("INCONCLUSIVE")) + c.dim(" - some checks could not run")
	case sum.Blocking > 0:
		verdict = c.red(c.bold(words.blocked)) + c.dim(fmt.Sprintf(
			" - %d blocking, %d to review", sum.Blocking, sum.Concerning))
	case sum.Concerning > 0:
		verdict = c.yellow(c.bold(words.caveats)) + c.dim(fmt.Sprintf(
			" - %d to review", sum.Concerning))
	default:
		verdict = c.green(c.bold(words.ready)) + c.dim(" - all systems nominal")
	}
	if sum.Accepted > 0 {
		verdict += c.dim(fmt.Sprintf(" (%d accepted by policy)", sum.Accepted))
	}
	fmt.Fprintf(w, "%s\n\n", verdict)
}

// verdictWords is the verdict vocabulary of one mission. "Ready" answers the
// upgrade question; a health check or certificate audit asks a different one.
type verdictWords struct{ blocked, caveats, ready, hold string }

func verdictWordsFor(mission string) verdictWords {
	switch mission {
	case "health":
		return verdictWords{"UNHEALTHY", "HEALTHY, WITH ISSUES", "HEALTHY", "fix now"}
	case "certs":
		return verdictWords{"CERTIFICATES NEED ACTION", "CERTIFICATES OK, WITH ISSUES", "CERTIFICATES OK", "renew now"}
	default:
		return verdictWords{"NOT READY", "READY, WITH CAVEATS", "READY", "hold launch"}
	}
}

// bucketHeading renders a section header, coloured by urgency.
func bucketHeading(c colorizer, b analyzer.Bucket, mission string) string {
	title := b.TitleFor(mission)
	switch b {
	case analyzer.BucketFixBeforeStart, analyzer.BucketInconclusive:
		return c.red(c.bold(title))
	case analyzer.BucketPlanAhead:
		return c.yellow(c.bold(title))
	case analyzer.BucketVerifyManually:
		return c.blue(c.bold(title))
	default:
		return c.bold(title)
	}
}

// writeWorkItem renders one numbered item of the plan.
func writeWorkItem(w io.Writer, c colorizer, n int, f analyzer.Finding, opts Options) {
	msg := ""
	if f.Result != nil {
		msg = f.Result.Message
	}
	if f.Error != "" {
		msg = "check could not run: " + f.Error
	}

	fmt.Fprintf(w, "\n  %s %s\n", c.bold(fmt.Sprintf("%d.", n)), msg)
	fmt.Fprintf(w, "     %s\n", c.dim(f.Check))
	for _, line := range policyLines(f) {
		fmt.Fprintf(w, "     %s %s\n", c.yellow("policy:"), wrapText(line, 66, "             "))
	}

	if f.Result == nil {
		return
	}

	limit := opts.resourceLimit()
	for i, res := range f.Result.Resources {
		if i >= limit {
			fmt.Fprintf(w, "     %s\n",
				c.dim(fmt.Sprintf("… and %d more (--max-resources -1 for all)",
					len(f.Result.Resources)-limit)))
			break
		}
		line := "     · " + res.String()
		if res.Detail != "" {
			// Long details (release advisories carry a whole remediation)
			// wrap under the resource instead of running off the screen.
			if len(res.Detail) > 60 {
				line += "\n       " + c.dim(wrapText(res.Detail, 68, "       "))
			} else {
				line += c.dim("  " + res.Detail)
			}
		}
		fmt.Fprintln(w, line)
	}

	if f.Result.Remediation != "" {
		fmt.Fprintf(w, "     %s %s\n", c.blue("→"),
			wrapText(f.Result.Remediation, 70, "       "))
	}
	for _, cmd := range f.Result.Commands {
		fmt.Fprintf(w, "       %s\n", c.teal("$ "+cmd))
	}
	// Limits are part of every finding's contract, but at full length on every
	// item they bury the plan. The default view keeps the plan; -v, JSON, HTML
	// and the TUI detail view carry them.
	if f.Limits != "" && opts.Verbose {
		fmt.Fprintf(w, "     %s %s\n", c.dim("limits:"),
			c.dim(wrapText(f.Limits, 66, "             ")))
	}
	if f.Result.Docs != "" {
		fmt.Fprintf(w, "     %s %s\n", c.blue("↗"), c.dim(f.Result.Docs))
	}
}

// writeCollapsed renders the non-blocking tail as a single summary line.
func writeCollapsed(w io.Writer, c colorizer, g analyzer.BucketGroup, mission string) {
	names := make([]string, 0, len(g.Findings))
	for _, f := range g.Findings {
		names = append(names, f.Check)
	}
	fmt.Fprintf(w, "\n%s %s\n", c.bold(g.Bucket.TitleFor(mission)),
		c.dim(fmt.Sprintf("(%d)", len(g.Findings))))
	fmt.Fprintf(w, "  %s\n\n", c.dim(strings.Join(names, ", ")))
}

// writeAccepted renders accepted findings one line each, with the reason, so
// what was waived is never out of sight even when it is out of the way.
func writeAccepted(w io.Writer, c colorizer, g analyzer.BucketGroup, mission string) {
	fmt.Fprintf(w, "\n%s %s\n", c.bold(g.Bucket.TitleFor(mission)),
		c.dim(fmt.Sprintf("(%d)", len(g.Findings))))
	for _, f := range g.Findings {
		fmt.Fprintf(w, "  %s %s\n", f.Check, c.dim(policyLines(f)[0]))
	}
	fmt.Fprintln(w)
}

// policyLines describes what policy did to a finding, accepted reason first.
func policyLines(f analyzer.Finding) []string {
	var out []string
	if s := f.Suppression; s != nil && f.Accepted() {
		line := "accepted by " + s.Kind
		var meta []string
		if s.Owner != "" {
			meta = append(meta, s.Owner)
		}
		if s.Expires != "" {
			meta = append(meta, "until "+s.Expires)
		}
		if len(meta) > 0 {
			line += " (" + strings.Join(meta, ", ") + ")"
		}
		out = append(out, line+": "+s.Reason)
	}
	return append(out, f.PolicyNotes...)
}

// writePassing lists the checks that found nothing, for verbose runs.
func writePassing(w io.Writer, c colorizer, r *analyzer.Report) {
	var passed, skipped []string
	for _, f := range r.Findings {
		if f.Result == nil || f.Error != "" {
			continue
		}
		switch f.Result.Status {
		case analyzer.StatusPass:
			passed = append(passed, f.Check)
		case analyzer.StatusSkip:
			skipped = append(skipped, f.Check)
		}
	}
	if len(passed) > 0 {
		fmt.Fprintf(w, "%s %s\n", c.green(c.bold("PASSED")), c.dim(fmt.Sprintf("(%d)", len(passed))))
		fmt.Fprintf(w, "  %s\n\n", c.dim(strings.Join(passed, ", ")))
	}
	if len(skipped) > 0 {
		fmt.Fprintf(w, "%s %s\n", c.bold("NOT APPLICABLE"), c.dim(fmt.Sprintf("(%d)", len(skipped))))
		fmt.Fprintf(w, "  %s\n\n", c.dim(strings.Join(skipped, ", ")))
	}
}

// writeFooter prints the closing verdict and the obvious next command.
func writeFooter(w io.Writer, c colorizer, r *analyzer.Report, sum analyzer.Summary) {
	switch {
	case sum.Errored > 0 || len(r.Errors) > 0:
		fmt.Fprintf(w, "%s\n", c.red(c.bold("inconclusive - do not treat this as a clean result")))
	case sum.Blocking > 0:
		fmt.Fprintf(w, "%s\n", c.red(c.bold(fmt.Sprintf(
			"%s - %d blocking issue(s)", verdictWordsFor(r.Mission).hold, sum.Blocking))))
		fmt.Fprintf(w, "%s\n", c.dim(
			"Work the sections top to bottom, then re-run to confirm."))
	case sum.Concerning > 0:
		fmt.Fprintf(w, "%s\n", c.yellow(c.bold(
			"clear to proceed - nothing blocking, but review the items above")))
	default:
		fmt.Fprintf(w, "%s\n", c.green(c.bold("all systems nominal")))
	}
}

// missionHeading names the analysis and its version span for report headers.
func missionHeading(r *analyzer.Report) string {
	name := r.Mission
	if name == "" {
		name = "upgrade"
	}
	if m, ok := analyzer.MissionByName(name); ok && !m.NeedsTarget {
		return fmt.Sprintf("%s · %s", m.Title, r.Upgrade.From.String())
	}
	return fmt.Sprintf("upgrade %s → %s", r.Upgrade.From.String(), r.Upgrade.To.String())
}

package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
	"github.com/Rusty-Gopher/kupre/pkg/deprecation"
	"github.com/Rusty-Gopher/kupre/pkg/provider"
)

// View renders the current stage. Bubble Tea v2 models return a tea.View,
// which carries terminal state alongside the rendered content.
func (m Model) View() tea.View {
	var body string
	switch m.stage {
	case stageWelcome:
		body = m.viewWelcome()
	case stagePickMission:
		body = m.viewMissionPicker()
	case stagePickKubeconfig:
		body = m.viewKubeconfigPicker()
	case stagePickContext:
		body = m.viewContextPicker()
	case stageTargetVersion:
		body = m.viewTargetVersion()
	case stageScanning:
		body = m.viewScanning()
	case stageResults:
		body = m.viewResults()
	case stageDetail:
		body = m.viewDetail()
	case stageError:
		body = m.viewError()
	}

	v := tea.NewView(m.header() + body)
	v.AltScreen = true
	v.WindowTitle = "kupre"
	return v
}

// header renders the logo and tagline shown on every screen.
func (m Model) header() string {
	return m.styles.Logo.Render(Banner) + "\n" +
		m.styles.Tagline.Render("  KUBERNETES PREFLIGHT & REVIEW ENGINE") + "\n\n"
}

// indentBlock prefixes every line of a multi-line render. Prefixing only the
// string as a whole indents just the first line, which visibly skews any
// bordered box.
func indentBlock(block, prefix string) string {
	lines := strings.Split(block, "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}

// pathTail shows the end of a long path within width, since the interesting
// part of a filesystem path is its tail.
func pathTail(s string, width int) string {
	if width < 8 {
		width = 8
	}
	if len(s) <= width {
		return s
	}
	return "…" + s[len(s)-width+1:]
}

// help renders the key hints line.
func (m Model) help(keys string) string {
	return "\n" + m.styles.Help.Render(keys) + "\n"
}

// viewWelcome explains what kupre does before it asks for anything. A preflight
// tool that opens straight into a cluster picker gives the operator no basis for
// trusting what it is about to do - in particular, that it only reads.
func (m Model) viewWelcome() string {
	var b strings.Builder
	b.WriteString(m.styles.Title.Render("What this does") + "\n\n")

	lines := []string{
		fmt.Sprintf("Analyzes a live Kubernetes cluster, read-only, with %d checks across", totalChecks()),
		"three missions: upgrade preflight, health check, certificate audit.",
		"",
		"Findings come as a worklist with exact fix commands, plus an HTML",
		"report saved next to where you run it.",
		"",
		"It never writes to your cluster. When it cannot check something,",
		"it says so instead of passing it.",
	}
	for _, l := range lines {
		if l == "" {
			b.WriteString("\n")
			continue
		}
		b.WriteString("  " + m.styles.Detail.Render(l) + "\n")
	}
	b.WriteString("\n  " + m.styles.Subtle.Render("Next: pick a mission, pick a cluster, go.") + "\n")

	return b.String() + m.help("enter continue · q quit")
}

// totalChecks counts every check the binary carries, across all missions and
// including provider checks that only run where they apply. Matches what
// `kupre checks` reports.
func totalChecks() int { return len(provider.Catalog()) }

// viewMissionPicker asks what the user wants to do - the tool's front door.
func (m Model) viewMissionPicker() string {
	var b strings.Builder
	b.WriteString(m.styles.Title.Render("What do you want to do?") + "\n\n")

	for i, mi := range analyzer.Missions() {
		cursor := "  "
		title := mi.Title
		if i == m.missionCursor {
			cursor = m.styles.Cursor.Render("▸ ")
			title = m.styles.Selected.Render(title)
		} else {
			title = m.styles.Input.Render(title)
		}
		b.WriteString(cursor + title + "\n")
		b.WriteString("    " + m.styles.Detail.Render(mi.Description) + "\n\n")
	}
	return b.String() + m.help("↑/↓ navigate · enter select · q quit")
}

// viewKubeconfigPicker renders the discovered kubeconfig files, plus the option
// to type a path by hand.
func (m Model) viewKubeconfigPicker() string {
	var b strings.Builder
	b.WriteString(m.styles.Title.Render("Which kubeconfig should I use?") + "\n")
	b.WriteString(m.styles.Detail.Render(
		"  Type a path, or pick one of the files found below.") + "\n\n")

	if !m.kcDiscovered {
		b.WriteString("  " + m.spinner.View() + m.styles.Subtle.Render(" looking for kubeconfig files…") + "\n")
		return b.String() + m.help("ctrl+c quit")
	}

	for i, k := range m.kubeconfigs {
		cursor := "  "
		label := k.Label()
		if i == m.kcCursor && !m.kcTyping {
			cursor = m.styles.Cursor.Render("▸ ")
			label = m.styles.Selected.Render(label)
		} else if !k.Usable() {
			label = m.styles.Skip.Render(label)
		}
		b.WriteString(fmt.Sprintf("%s%s\n", cursor, label))
		b.WriteString("    " + m.styles.Detail.Render(
			fmt.Sprintf("%s · %s", k.Origin, k.Detail())) + "\n")
	}

	// The final row is always "enter a path myself".
	cursor := "  "
	manual := "type a path…"
	if m.kcCursor >= len(m.kubeconfigs) || m.kcTyping {
		cursor = m.styles.Cursor.Render("▸ ")
		manual = m.styles.Selected.Render(manual)
	}
	b.WriteString(fmt.Sprintf("%s%s\n", cursor, manual))

	if m.kcTyping {
		avail := m.width - 12
		input := ""
		if m.kcInput == "" {
			input = m.styles.Subtle.Render("/path/to/kubeconfig")
		} else {
			input = m.styles.Input.Render(pathTail(m.kcInput, avail))
		}
		b.WriteString(indentBlock(m.styles.Box.Render(input+"▌"), "    ") + "\n")
	}

	if len(m.kubeconfigs) == 0 {
		b.WriteString("\n")
		for _, l := range wrap("Nothing found in $KUBECONFIG, ~/.kube/ or this directory. Enter a path.", m.width-4) {
			b.WriteString("  " + m.styles.Subtle.Render(l) + "\n")
		}
	}

	if m.kcErr != nil {
		b.WriteString("\n")
		for _, line := range wrap(m.kcErr.Error(), m.width-6) {
			b.WriteString("  " + m.styles.ErrorText.Render(line) + "\n")
		}
	}

	if m.kcTyping {
		return b.String() + m.help("type a path · enter confirm · esc back")
	}
	return b.String() + m.help("↑/↓ navigate · enter select · e type a path · q quit")
}

// viewContextPicker renders the kubeconfig context selector.
func (m Model) viewContextPicker() string {
	var b strings.Builder
	b.WriteString(m.styles.Title.Render("Which cluster?") + "\n")
	if m.kcChosen != "" {
		b.WriteString(m.styles.Detail.Render("  from "+m.kcChosen) + "\n")
	}
	b.WriteString("\n")

	if len(m.contexts) == 0 {
		b.WriteString(m.styles.Subtle.Render("  loading kubeconfig contexts…") + "\n")
		return b.String() + m.help("ctrl+c quit")
	}

	for i, c := range m.contexts {
		cursor := "  "
		line := c
		if i == m.ctxCursor {
			cursor = m.styles.Cursor.Render("▸ ")
			line = m.styles.Selected.Render(c)
		}
		b.WriteString(cursor + line + "\n")
	}
	return b.String() + m.help("↑/↓ navigate · enter select · ← back · q quit")
}

// viewTargetVersion renders the upgrade target prompt.
func (m Model) viewTargetVersion() string {
	var b strings.Builder
	b.WriteString(m.styles.Title.Render("Target Kubernetes version") + "\n\n")
	b.WriteString(m.styles.Subtle.Render("  cluster: ") + m.ctxChosen + "\n\n")

	input := m.versionBuf
	if input == "" {
		// The newest release kupre has verified data for is the most useful hint.
		input = m.styles.Subtle.Render(deprecation.DataHorizon + ".0")
	} else {
		input = m.styles.Input.Render(input)
	}
	b.WriteString(indentBlock(m.styles.Box.Render(input+"▌"), "  ") + "\n")

	if m.versionBuf != "" {
		if _, err := analyzer.ParseVersion(m.versionBuf); err != nil {
			b.WriteString("\n  " + m.styles.ErrorText.Render("not a valid version yet") + "\n")
		}
	}
	return b.String() + m.help("type a version · enter scan · esc back · q quit")
}

// viewScanning renders the in-progress scan.
func (m Model) viewScanning() string {
	var b strings.Builder
	b.WriteString(m.styles.Title.Render("Scanning") + "\n\n")
	b.WriteString("  " + m.styles.Subtle.Render("cluster: ") + m.ctxChosen + "\n")

	if m.cluster != nil {
		if m.mission.NeedsTarget {
			b.WriteString("  " + m.styles.Subtle.Render("upgrade: ") +
				m.cluster.ServerVersion.String() + " → v" + m.versionBuf + "\n")
		} else {
			b.WriteString("  " + m.styles.Subtle.Render("mission: ") + m.mission.Title + "\n")
		}
	}
	b.WriteString("\n")

	p := m.progress
	switch {
	case m.cluster == nil:
		b.WriteString("  " + m.spinner.View() + " connecting to the API server…\n")
	case p.total == 0:
		b.WriteString("  " + m.spinner.View() + " preparing checks…\n")
	default:
		b.WriteString(fmt.Sprintf("  %s %s\n", m.spinner.View(),
			m.styles.Subtle.Render(fmt.Sprintf("%d/%d checks · %s", p.done, p.total, p.last))))
		b.WriteString("\n  " + m.progressBar(p.done, p.total, 40) + "\n")
	}
	return b.String() + m.help("ctrl+c cancel")
}

// progressBar renders a simple fixed-width bar.
func (m Model) progressBar(done, total, width int) string {
	if total <= 0 {
		return ""
	}
	filled := done * width / total
	if filled > width {
		filled = width
	}
	return m.styles.Selected.Render(strings.Repeat("━", filled)) +
		m.styles.Help.Render(strings.Repeat("━", width-filled))
}

// viewResults renders the findings grouped in worklist order - the same
// sections the CLI prints - with the cursor moving across findings and
// section headers interleaved where the bucket changes.
func (m Model) viewResults() string {
	if m.report == nil {
		return ""
	}
	var b strings.Builder
	r := m.report
	sum := r.Summarize()

	// Header: cluster context on one line, the verdict as the headline.
	head := m.styles.Subtle.Render("cluster ") + r.Cluster
	if m.mission.NeedsTarget {
		head += m.styles.Subtle.Render("   upgrade ") +
			r.Upgrade.From.String() + m.styles.Subtle.Render(" → ") + r.Upgrade.To.String()
	} else {
		head += m.styles.Subtle.Render("   "+m.mission.Title+" · ") + r.Upgrade.From.String()
	}
	b.WriteString(head + "\n")
	b.WriteString(m.verdictLine(sum) + "\n")
	switch {
	case m.reportPath != "":
		b.WriteString(m.styles.Subtle.Render("report ") + m.styles.Detail.Render(m.reportPath) + "\n\n")
	case m.reportErr != nil:
		b.WriteString(m.styles.Help.Render("report not saved: "+m.reportErr.Error()) + "\n\n")
	default:
		b.WriteString("\n")
	}

	if len(m.ordered) == 0 {
		b.WriteString(m.styles.Pass.Render("  Nothing to do - no findings.") + "\n")
		b.WriteString(m.passedFooter())
		return b.String() + m.help("p passing checks · r rescan · q quit")
	}

	rows := m.visibleRows()
	start, end := m.resScroll, m.resScroll+rows
	if end > len(m.ordered) {
		end = len(m.ordered)
	}

	var lastBucket analyzer.Bucket = analyzer.BucketNone
	if start > 0 {
		// Re-anchor the section header when the window starts mid-bucket, so
		// the reader always knows which section the first visible row is in.
		lastBucket = m.ordered[start-1].Bucket
		if m.ordered[start].Bucket == lastBucket {
			b.WriteString(m.bucketHeader(lastBucket) + m.styles.Help.Render(" (cont.)") + "\n")
		}
	}

	for i := start; i < end; i++ {
		of := m.ordered[i]
		if of.Bucket != lastBucket {
			if i > start {
				b.WriteString("\n")
			}
			b.WriteString(m.bucketHeader(of.Bucket) + "\n")
			lastBucket = of.Bucket
		}
		b.WriteString(m.findingRow(i, of) + "\n")
	}

	if len(m.ordered) > rows {
		b.WriteString(m.styles.Help.Render(fmt.Sprintf("\n  %d–%d of %d findings",
			start+1, end, len(m.ordered))) + "\n")
	}
	b.WriteString(m.passedFooter())

	return b.String() + m.help("↑/↓ move · enter details · p passing · r rescan · q quit")
}

// verdictLine renders the one-line answer, mirroring the CLI.
func (m Model) verdictLine(sum analyzer.Summary) string {
	switch {
	case sum.Errored > 0:
		return m.styles.Fail.Render("INCONCLUSIVE") + m.styles.Subtle.Render(" - some checks could not run")
	case sum.Blocking > 0:
		return m.styles.Fail.Render("NOT READY") + m.styles.Subtle.Render(
			fmt.Sprintf(" - %d blocking, %d to review", sum.Blocking, sum.Concerning))
	case sum.Concerning > 0:
		return m.styles.Warn.Render("READY, WITH CAVEATS") + m.styles.Subtle.Render(
			fmt.Sprintf(" - %d to review", sum.Concerning))
	default:
		return m.styles.Nominal.Render("READY") + m.styles.Subtle.Render(" - all systems nominal")
	}
}

// bucketHeader renders one worklist section title, colored by urgency, in the
// active mission's vocabulary.
func (m Model) bucketHeader(b analyzer.Bucket) string {
	title := b.TitleFor(m.mission.Name)
	switch b {
	case analyzer.BucketFixBeforeStart, analyzer.BucketInconclusive:
		return m.styles.Fail.Render("▌ " + title)
	case analyzer.BucketPlanAhead:
		return m.styles.Warn.Render("▌ " + title)
	case analyzer.BucketVerifyManually:
		return m.styles.Remedy.Render("▌ " + title)
	default:
		return m.styles.Title.Render("▌ " + title)
	}
}

// findingRow renders one selectable row.
func (m Model) findingRow(i int, of orderedFinding) string {
	f := of.Finding
	cursor := "  "
	if i == m.resCursor {
		cursor = m.styles.Cursor.Render("▸ ")
	}

	msg := ""
	if f.Result != nil {
		msg = f.Result.Message
	}
	if f.Error != "" {
		msg = "could not run: " + f.Error
	}

	nameWidth := 30
	name := fmt.Sprintf("%-*s", nameWidth, truncate(f.Check, nameWidth))
	if i == m.resCursor {
		name = m.styles.Selected.Render(name)
	} else {
		name = m.styles.Input.Render(name)
	}

	avail := m.width - nameWidth - 14
	return fmt.Sprintf("%s%s %s %s",
		cursor,
		m.styles.statusStyle(f).Render(statusLabel(f)),
		name,
		m.styles.Detail.Render(truncate(msg, avail)))
}

// passedFooter renders the collapsed passing/skipped sections, expanded on 'p'.
func (m Model) passedFooter() string {
	if len(m.passed) == 0 && len(m.skipped) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n")
	label := fmt.Sprintf("PASSED (%d)", len(m.passed))
	if len(m.skipped) > 0 {
		label += fmt.Sprintf("  ·  NOT APPLICABLE (%d)", len(m.skipped))
	}
	if !m.showPassed {
		b.WriteString(m.styles.Pass.Render("▌ "+label) + m.styles.Help.Render("  - press p to expand") + "\n")
		return b.String()
	}
	b.WriteString(m.styles.Pass.Render("▌ "+label) + "\n")
	var names []string
	for _, f := range m.passed {
		names = append(names, f.Check)
	}
	for _, line := range wrap(strings.Join(names, " · "), m.width-4) {
		b.WriteString("  " + m.styles.Detail.Render(line) + "\n")
	}
	if len(m.skipped) > 0 {
		names = names[:0]
		for _, f := range m.skipped {
			names = append(names, f.Check)
		}
		b.WriteString("  " + m.styles.Help.Render("n/a: "+strings.Join(names, " · ")) + "\n")
	}
	return b.String()
}

// summaryLine renders the verdict and counts.
func (m Model) summaryLine(sum analyzer.Summary) string {
	parts := []string{m.styles.Pass.Render(fmt.Sprintf("%d passed", sum.Passed))}
	if sum.Concerning > 0 {
		parts = append(parts, m.styles.Warn.Render(fmt.Sprintf("%d warning", sum.Concerning)))
	}
	if sum.Blocking > 0 {
		parts = append(parts, m.styles.Fail.Render(fmt.Sprintf("%d blocking", sum.Blocking)))
	}
	if sum.Skipped > 0 {
		parts = append(parts, m.styles.Skip.Render(fmt.Sprintf("%d skipped", sum.Skipped)))
	}
	if sum.Errored > 0 {
		parts = append(parts, m.styles.ErrorText.Render(fmt.Sprintf("%d errored", sum.Errored)))
	}

	verdict := m.styles.Nominal.Render("all systems nominal")
	if sum.Blocking > 0 {
		verdict = m.styles.Hold.Render(fmt.Sprintf("hold launch - %d issue(s) found", sum.Blocking))
	} else if sum.Concerning > 0 {
		verdict = m.styles.Warn.Render(fmt.Sprintf("proceed with caution - %d warning(s)", sum.Concerning))
	}

	return strings.Join(parts, m.styles.Subtle.Render(" · ")) + "\n" + verdict
}

// viewDetail renders the full record for the selected finding, including the
// copy-paste commands and the evidence basis the CLI report shows.
func (m Model) viewDetail() string {
	if m.resCursor >= len(m.ordered) {
		return ""
	}
	of := m.ordered[m.resCursor]
	f := of.Finding
	width := m.width - 6
	if width < 40 {
		width = 40
	}

	var b strings.Builder
	b.WriteString(m.bucketHeader(of.Bucket) +
		m.styles.Help.Render(fmt.Sprintf("   finding %d of %d", m.resCursor+1, len(m.ordered))) + "\n\n")
	b.WriteString(m.styles.statusStyle(f).Render(statusLabel(f)) + "  " +
		m.styles.Title.Render(f.Check) + "  " +
		m.styles.Category.Render(fmt.Sprintf("[%s · %s]", f.Category, f.Severity)) + "\n\n")

	msg := ""
	if f.Result != nil {
		msg = f.Result.Message
	}
	if f.Error != "" {
		msg = "check could not run: " + f.Error
	}
	for _, line := range wrap(msg, width) {
		b.WriteString("  " + line + "\n")
	}

	if f.Result == nil {
		return b.String() + m.help("esc back · q quit")
	}

	if len(f.Result.Resources) > 0 {
		b.WriteString("\n" + m.styles.Subtle.Render("  affected") + "\n")
		limit := m.height - 20
		if limit < 3 {
			limit = 3
		}
		for i, res := range f.Result.Resources {
			if i >= limit {
				b.WriteString(m.styles.Help.Render(
					fmt.Sprintf("    … and %d more", len(f.Result.Resources)-limit)) + "\n")
				break
			}
			line := "    · " + res.String()
			if res.Detail != "" {
				line += m.styles.Detail.Render("  " + res.Detail)
			}
			b.WriteString(truncate(line, m.width) + "\n")
		}
	}

	if f.Result.Remediation != "" {
		b.WriteString("\n" + m.styles.Remedy.Render("  → fix") + "\n")
		for _, line := range wrap(f.Result.Remediation, width-4) {
			b.WriteString("    " + line + "\n")
		}
	}
	for _, cmd := range f.Result.Commands {
		b.WriteString("      " + m.styles.Selected.Render("$ "+cmd) + "\n")
	}
	if f.Limits != "" {
		b.WriteString("\n" + m.styles.Subtle.Render("  cannot conclude") + "\n")
		for _, line := range wrap(f.Limits, width-4) {
			b.WriteString("    " + m.styles.Detail.Render(line) + "\n")
		}
	}
	if f.Result.Docs != "" {
		b.WriteString("\n  " + m.styles.Remedy.Render("↗ ") + m.styles.Detail.Render(f.Result.Docs) + "\n")
	}

	return b.String() + m.help("↑/↓ next finding · esc back · q quit")
}

// viewError renders a fatal error.
func (m Model) viewError() string {
	var b strings.Builder
	b.WriteString(m.styles.Fail.Render("Error") + "\n\n")
	for _, line := range wrap(m.err.Error(), m.width-4) {
		b.WriteString("  " + m.styles.ErrorText.Render(line) + "\n")
	}
	return b.String() + m.help("any key to quit")
}

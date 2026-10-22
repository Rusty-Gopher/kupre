// Package tui implements kupre's interactive terminal interface.
package tui

import (
	"charm.land/lipgloss/v2"
	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
)

// Styles holds every lipgloss style the TUI uses. Colors are resolved once
// against the detected terminal background rather than per render.
type Styles struct {
	Logo      lipgloss.Style
	Tagline   lipgloss.Style
	Title     lipgloss.Style
	Subtle    lipgloss.Style
	Help      lipgloss.Style
	Selected  lipgloss.Style
	Cursor    lipgloss.Style
	Box       lipgloss.Style
	Input     lipgloss.Style
	Pass      lipgloss.Style
	Warn      lipgloss.Style
	Fail      lipgloss.Style
	Skip      lipgloss.Style
	ErrorText lipgloss.Style
	Nominal   lipgloss.Style
	Hold      lipgloss.Style
	Category  lipgloss.Style
	Detail    lipgloss.Style
	Remedy    lipgloss.Style
}

// NewStyles builds the style set for the given terminal background.
//
// Lip Gloss v2 removed AdaptiveColor in favour of an explicit light/dark
// resolver, so the caller passes in what the terminal reported.
func NewStyles(dark bool) Styles {
	ld := lipgloss.LightDark(dark)

	var (
		teal   = ld(lipgloss.Color("#0F766E"), lipgloss.Color("#2DD4BF"))
		muted  = ld(lipgloss.Color("#64748B"), lipgloss.Color("#94A3B8"))
		faint  = ld(lipgloss.Color("#94A3B8"), lipgloss.Color("#64748B"))
		green  = ld(lipgloss.Color("#15803D"), lipgloss.Color("#4ADE80"))
		yellow = ld(lipgloss.Color("#A16207"), lipgloss.Color("#FACC15"))
		red    = ld(lipgloss.Color("#B91C1C"), lipgloss.Color("#F87171"))
		blue   = ld(lipgloss.Color("#1D4ED8"), lipgloss.Color("#60A5FA"))
		fg     = ld(lipgloss.Color("#0F172A"), lipgloss.Color("#E2E8F0"))
	)

	return Styles{
		Logo:      lipgloss.NewStyle().Foreground(teal).Bold(true),
		Tagline:   lipgloss.NewStyle().Foreground(muted),
		Title:     lipgloss.NewStyle().Foreground(fg).Bold(true),
		Subtle:    lipgloss.NewStyle().Foreground(muted),
		Help:      lipgloss.NewStyle().Foreground(faint),
		Selected:  lipgloss.NewStyle().Foreground(teal).Bold(true),
		Cursor:    lipgloss.NewStyle().Foreground(teal),
		Box:       lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(faint).Padding(0, 1),
		Input:     lipgloss.NewStyle().Foreground(fg),
		Pass:      lipgloss.NewStyle().Foreground(green).Bold(true),
		Warn:      lipgloss.NewStyle().Foreground(yellow).Bold(true),
		Fail:      lipgloss.NewStyle().Foreground(red).Bold(true),
		Skip:      lipgloss.NewStyle().Foreground(faint),
		ErrorText: lipgloss.NewStyle().Foreground(red),
		Nominal:   lipgloss.NewStyle().Foreground(green).Bold(true),
		Hold:      lipgloss.NewStyle().Foreground(red).Bold(true),
		Category:  lipgloss.NewStyle().Foreground(muted),
		Detail:    lipgloss.NewStyle().Foreground(muted),
		Remedy:    lipgloss.NewStyle().Foreground(blue),
	}
}

// statusStyle returns the style matching a finding's outcome.
func (s Styles) statusStyle(f analyzer.Finding) lipgloss.Style {
	switch {
	case f.Error != "":
		return s.ErrorText
	case f.Blocking():
		return s.Fail
	case f.Concerning():
		return s.Warn
	case f.Accepted():
		return s.Skip
	case f.Result != nil && f.Result.Status == analyzer.StatusSkip:
		return s.Skip
	default:
		return s.Pass
	}
}

// statusLabel returns the four-character marker for a finding.
func statusLabel(f analyzer.Finding) string {
	switch {
	case f.Error != "":
		return "  ??"
	case f.Blocking():
		return "FAIL"
	case f.Concerning():
		return "WARN"
	case f.Accepted():
		return " ACK"
	case f.Result != nil && f.Result.Status == analyzer.StatusSkip:
		return "SKIP"
	default:
		return "PASS"
	}
}

// Banner is the kupre ASCII logo.
const Banner = `    __
   / /___  ______  ________
  / //_/ / / / __ \/ ___/ _ \
 / ,< / /_/ / /_/ / /  /  __/
/_/|_|\__,_/ .___/_/   \___/
          /_/`

// Package policy applies a team's accepted risk to a report: disabled checks,
// severity overrides, expiring waivers, and a baseline of known findings.
//
// One rule holds throughout: policy can change what counts toward the
// verdict, but it can never hide a finding. Disabled checks are reported as
// skipped, accepted findings move to their own section, and every change is
// written to the finding's PolicyNotes. Blockers cannot be waived or
// baselined at all; accepting one takes an explicit severity override.
package policy

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
)

// DefaultFile is the policy file kupre picks up from the working directory.
const DefaultFile = ".kupre.yaml"

// Policy is the parsed .kupre.yaml.
type Policy struct {
	// Version is the file format version; only 1 exists.
	Version int `json:"version"`
	// Disable lists checks that are not evaluated. They still appear in the
	// report, as skipped, so the gap in coverage stays visible.
	Disable []string `json:"disable,omitempty"`
	// Severity overrides a check's severity: error, warning or info.
	Severity map[string]string `json:"severity,omitempty"`
	// Waivers accept specific non-blocking findings until they expire.
	Waivers []Waiver `json:"waivers,omitempty"`

	source string
}

// Waiver accepts a check's findings, optionally only for named resources.
type Waiver struct {
	Check string `json:"check"`
	// Resources limits the waiver to these objects. Empty means the whole
	// check. When set, a finding is accepted only if every affected resource
	// is listed, so a new offender is never covered by an old waiver.
	Resources []Resource `json:"resources,omitempty"`
	Reason    string     `json:"reason"`
	Owner     string     `json:"owner,omitempty"`
	// Expires is a date (YYYY-MM-DD); the waiver applies through that day.
	Expires string `json:"expires"`

	expires time.Time
}

// Resource identifies an object a waiver covers. Kind is optional.
type Resource struct {
	Kind      string `json:"kind,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

func (r Resource) matches(a analyzer.AffectedResource) bool {
	return r.Name == a.Name && r.Namespace == a.Namespace &&
		(r.Kind == "" || strings.EqualFold(r.Kind, a.Kind))
}

// Load reads and validates a policy file. known is the set of valid check
// names; a typo in a check name is an error, not a silently inert rule.
func Load(path string, known map[string]bool) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Policy
	if err := yaml.UnmarshalStrict(data, &p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p.source = path
	if err := p.validate(known); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &p, nil
}

// Discover loads DefaultFile from dir if it exists. A missing file is not an
// error and returns nil.
func Discover(dir string, known map[string]bool) (*Policy, error) {
	path := DefaultFile
	if dir != "" {
		path = dir + string(os.PathSeparator) + DefaultFile
	}
	p, err := Load(path, known)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return p, err
}

func (p *Policy) validate(known map[string]bool) error {
	var errs []string
	checkName := func(where, name string) {
		if !known[name] {
			errs = append(errs, fmt.Sprintf("%s: unknown check %q (see kupre checks)", where, name))
		}
	}
	if p.Version != 1 {
		errs = append(errs, fmt.Sprintf("version: want 1, got %d", p.Version))
	}
	for _, name := range p.Disable {
		checkName("disable", name)
	}
	for name, sev := range p.Severity {
		checkName("severity", name)
		if _, ok := parseSeverity(sev); !ok {
			errs = append(errs, fmt.Sprintf("severity.%s: %q is not error, warning or info", name, sev))
		}
	}
	for i := range p.Waivers {
		w := &p.Waivers[i]
		where := fmt.Sprintf("waivers[%d]", i)
		checkName(where, w.Check)
		if strings.TrimSpace(w.Reason) == "" {
			errs = append(errs, where+": reason is required")
		}
		t, err := time.Parse(time.DateOnly, w.Expires)
		if err != nil {
			errs = append(errs, where+": expires must be a date like 2026-12-31")
		}
		w.expires = t
		for j, r := range w.Resources {
			if r.Name == "" {
				errs = append(errs, fmt.Sprintf("%s.resources[%d]: name is required", where, j))
			}
		}
	}
	sort.Strings(errs)
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func parseSeverity(s string) (analyzer.Severity, bool) {
	switch strings.ToLower(s) {
	case "error":
		return analyzer.SeverityError, true
	case "warning", "warn":
		return analyzer.SeverityWarning, true
	case "info":
		return analyzer.SeverityInfo, true
	}
	return 0, false
}

// Apply rewrites the report in place. today decides waiver expiry.
func (p *Policy) Apply(r *analyzer.Report, today time.Time) {
	disabled := map[string]bool{}
	for _, name := range p.Disable {
		disabled[name] = true
	}
	for i := range r.Findings {
		f := &r.Findings[i]

		if disabled[f.Check] {
			f.Error = ""
			f.Result = analyzer.Skip("disabled by %s", p.source)
			f.PolicyNotes = append(f.PolicyNotes, "check disabled by policy")
			continue
		}

		if s, ok := p.Severity[f.Check]; ok {
			sev, _ := parseSeverity(s)
			if sev != f.Severity {
				f.PolicyNotes = append(f.PolicyNotes,
					fmt.Sprintf("severity overridden by policy: %s -> %s", f.Severity, sev))
				f.Severity = sev
			}
		}

		for _, w := range p.Waivers {
			if w.Check == f.Check {
				p.applyWaiver(f, w, today)
			}
		}
	}
}

func (p *Policy) applyWaiver(f *analyzer.Finding, w Waiver, today time.Time) {
	if f.Error != "" || f.Result == nil ||
		(f.Result.Status != analyzer.StatusWarn && f.Result.Status != analyzer.StatusFail) {
		return
	}
	who := ""
	if w.Owner != "" {
		who = " (" + w.Owner + ")"
	}
	// The waiver is valid through the whole expiry day.
	if !today.Before(w.expires.AddDate(0, 0, 1)) {
		f.PolicyNotes = append(f.PolicyNotes,
			fmt.Sprintf("EXPIRED waiver%s ended %s: %s", who, w.Expires, w.Reason))
		return
	}
	if f.Blocking() {
		f.PolicyNotes = append(f.PolicyNotes, fmt.Sprintf("waiver%s not applied: blocking "+
			"findings cannot be waived; override the check's severity to accept it", who))
		return
	}
	if len(w.Resources) > 0 {
		var uncovered []string
		for _, a := range f.Result.Resources {
			covered := false
			for _, r := range w.Resources {
				if r.matches(a) {
					covered = true
					break
				}
			}
			if !covered {
				uncovered = append(uncovered, a.String())
			}
		}
		if len(f.Result.Resources) == 0 {
			f.PolicyNotes = append(f.PolicyNotes, fmt.Sprintf("waiver%s lists resources, "+
				"but this finding names none, so it cannot be matched", who))
			return
		}
		if len(uncovered) > 0 {
			f.PolicyNotes = append(f.PolicyNotes, fmt.Sprintf("waiver%s does not cover: %s",
				who, strings.Join(uncovered, ", ")))
			return
		}
	}
	f.Suppression = &analyzer.Suppression{
		Kind: "waiver", Reason: w.Reason, Owner: w.Owner, Expires: w.Expires,
	}
}

// KnownChecks builds the set of valid check names from check lists.
func KnownChecks(lists ...[]analyzer.Check) map[string]bool {
	out := map[string]bool{}
	for _, l := range lists {
		for _, c := range l {
			out[c.Name] = true
		}
	}
	return out
}

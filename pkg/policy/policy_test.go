package policy

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
	"github.com/Rusty-Gopher/kupre/pkg/report"
)

var known = map[string]bool{"pdb-blocks-drain": true, "single-replica-workloads": true, "legacy-endpoints": true}

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), DefaultFile)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func res(ns, name string) analyzer.AffectedResource {
	return analyzer.AffectedResource{Kind: "Deployment", Namespace: ns, Name: name}
}

// sample has one blocker and one warning naming two resources.
func sample() *analyzer.Report {
	return &analyzer.Report{Cluster: "c", Findings: []analyzer.Finding{
		{Check: "pdb-blocks-drain", Severity: analyzer.SeverityError,
			Result: analyzer.Fail("blocked").WithResources(res("shop", "api"))},
		{Check: "single-replica-workloads", Severity: analyzer.SeverityWarning,
			Result: analyzer.Warn("single").WithResources(res("shop", "api"), res("shop", "web"))},
		{Check: "legacy-endpoints", Severity: analyzer.SeverityWarning, Result: analyzer.Pass("ok")},
	}}
}

var today = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

func TestLoadRejectsMistakes(t *testing.T) {
	for name, body := range map[string]string{
		"unknown check":    "version: 1\ndisable: [no-such-check]\n",
		"bad severity":     "version: 1\nseverity: {legacy-endpoints: critical}\n",
		"missing reason":   "version: 1\nwaivers: [{check: legacy-endpoints, expires: 2026-12-31}]\n",
		"missing expiry":   "version: 1\nwaivers: [{check: legacy-endpoints, reason: x}]\n",
		"unknown field":    "version: 1\nwaiver: []\n",
		"missing version":  "disable: [legacy-endpoints]\n",
		"resource no name": "version: 1\nwaivers: [{check: legacy-endpoints, reason: x, expires: 2026-12-31, resources: [{namespace: a}]}]\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(write(t, body), known); err == nil {
				t.Fatal("want a validation error")
			}
		})
	}
}

func TestDiscoverMissingFileIsNil(t *testing.T) {
	p, err := Discover(t.TempDir(), known)
	if p != nil || err != nil {
		t.Fatalf("got %v, %v; want nil, nil", p, err)
	}
}

func TestWaiverAcceptsWarningButNeverABlocker(t *testing.T) {
	p, err := Load(write(t, `version: 1
waivers:
  - check: single-replica-workloads
    reason: accepted for staging
    owner: platform
    expires: 2026-10-22
  - check: pdb-blocks-drain
    reason: trying to hide a blocker
    expires: 2027-01-01
`), known)
	if err != nil {
		t.Fatal(err)
	}
	r := sample()
	p.Apply(r, today) // the expiry day itself is still covered

	if !r.Findings[1].Accepted() {
		t.Error("warning was not accepted by a valid waiver")
	}
	if !r.Findings[0].Blocking() || r.Findings[0].Accepted() {
		t.Error("a waiver turned a blocker into an accepted finding")
	}
	if !strings.Contains(strings.Join(r.Findings[0].PolicyNotes, " "), "cannot be waived") {
		t.Errorf("blocker notes = %v, want an explanation", r.Findings[0].PolicyNotes)
	}
	if got := r.ExitCode(); got != analyzer.ExitBlocked {
		t.Errorf("exit = %d, want %d", got, analyzer.ExitBlocked)
	}
	if s := r.Summarize(); s.Accepted != 1 || s.Concerning != 0 {
		t.Errorf("summary = %+v, want 1 accepted, 0 concerning", s)
	}
}

func TestExpiredWaiverStopsApplyingAndSaysSo(t *testing.T) {
	p, _ := Load(write(t, "version: 1\nwaivers: [{check: single-replica-workloads, reason: old, expires: 2026-10-21}]\n"), known)
	r := sample()
	p.Apply(r, today)
	f := r.Findings[1]
	if f.Accepted() || !f.Concerning() {
		t.Fatal("expired waiver still applies")
	}
	if !strings.Contains(f.PolicyNotes[0], "EXPIRED") {
		t.Errorf("notes = %v, want EXPIRED", f.PolicyNotes)
	}
}

func TestResourceWaiverDoesNotCoverNewOffenders(t *testing.T) {
	p, _ := Load(write(t, `version: 1
waivers:
  - check: single-replica-workloads
    reason: api is a singleton by design
    expires: 2027-01-01
    resources: [{namespace: shop, name: api}]
`), known)
	r := sample()
	p.Apply(r, today)
	f := r.Findings[1]
	if f.Accepted() {
		t.Fatal("waiver for shop/api accepted a finding that also names shop/web")
	}
	if !strings.Contains(strings.Join(f.PolicyNotes, " "), "shop/web") {
		t.Errorf("notes = %v, want the uncovered resource named", f.PolicyNotes)
	}
}

func TestDisableAndSeverityOverrideStayVisible(t *testing.T) {
	p, _ := Load(write(t, "version: 1\ndisable: [single-replica-workloads]\nseverity: {pdb-blocks-drain: warning}\n"), known)
	r := sample()
	p.Apply(r, today)
	if r.Findings[1].Result.Status != analyzer.StatusSkip || len(r.Findings[1].PolicyNotes) == 0 {
		t.Error("disabled check should be reported as skipped, with a note")
	}
	if r.Findings[0].Blocking() || !r.Findings[0].Concerning() {
		t.Error("explicit severity override should downgrade the blocker to a warning")
	}
	if !strings.Contains(r.Findings[0].PolicyNotes[0], "error -> warning") {
		t.Errorf("notes = %v, want the override recorded", r.Findings[0].PolicyNotes)
	}
}

func TestBaselineAcceptsOnlyKnownWarnings(t *testing.T) {
	var buf bytes.Buffer
	old := sample()
	old.Findings[1].Result = analyzer.Warn("single").WithResources(res("shop", "api"))
	if err := report.WriteJSON(&buf, old, report.Options{MaxResources: -1}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := LoadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}

	// Same warning, same resource: accepted. Blocker: never accepted.
	same := sample()
	same.Findings[1].Result = analyzer.Warn("single").WithResources(res("shop", "api"))
	b.Apply(same)
	if !same.Findings[1].Accepted() {
		t.Error("known warning was not accepted by the baseline")
	}
	if !same.Findings[0].Blocking() {
		t.Error("baseline accepted a blocker")
	}

	// A new resource on a known check is new.
	grown := sample()
	b.Apply(grown)
	if grown.Findings[1].Accepted() {
		t.Error("a warning with a new resource was accepted as known")
	}
}

func TestBaselineRejectsForeignFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.json")
	_ = os.WriteFile(path, []byte(`{"findings": []}`), 0o600)
	if _, err := LoadBaseline(path); err == nil {
		t.Fatal("a file without a matching schemaVersion must be rejected")
	}
}

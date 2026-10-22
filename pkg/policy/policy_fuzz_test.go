package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
)

// FuzzLoad: .kupre.yaml is user input. Loading must never panic, and no
// policy that loads may ever turn a blocking finding into a non-blocking one
// unless it explicitly overrides that check's severity.
func FuzzLoad(f *testing.F) {
	f.Add("version: 1\nwaivers: [{check: pdb-blocks-drain, reason: x, expires: 2099-01-01}]\n")
	f.Add("version: 1\ndisable: [legacy-endpoints]\nseverity: {single-replica-workloads: info}\n")
	f.Add("version: 1\nwaivers: [{check: single-replica-workloads, reason: r, expires: 2099-12-31, resources: [{namespace: shop, name: api}]}]\n")
	f.Fuzz(func(t *testing.T, body string) {
		path := filepath.Join(t.TempDir(), DefaultFile)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		p, err := Load(path, known)
		if err != nil {
			return
		}
		r := sample()
		p.ApplyTo(r, time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC))
		f := r.Findings[0]
		_, overridden := p.Severity["pdb-blocks-drain"]
		disabled := false
		for _, d := range p.Disable {
			disabled = disabled || d == "pdb-blocks-drain"
		}
		if !overridden && !disabled && !f.Blocking() {
			t.Fatalf("policy %q unblocked a blocker without an explicit override", body)
		}
		if f.Accepted() && f.Severity == analyzer.SeverityError && f.Result.Status == analyzer.StatusFail {
			t.Fatalf("a blocking failure was accepted")
		}
	})
}

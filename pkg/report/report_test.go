package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
)

// sampleReport builds a report covering every outcome, for renderer tests.
func sampleReport() *analyzer.Report {
	return &analyzer.Report{
		Cluster: "test-cluster",
		Upgrade: analyzer.Upgrade{
			From: analyzer.MustParseVersion("1.35.3"),
			To:   analyzer.MustParseVersion("1.36.0"),
		},
		Findings: []analyzer.Finding{
			{
				Check: "pdb-blocks-drain", Category: analyzer.CategoryWorkload,
				Severity: analyzer.SeverityError,
				Result: &analyzer.Result{
					Status:  analyzer.StatusFail,
					Message: "1 PodDisruptionBudget blocks drain",
					Resources: []analyzer.AffectedResource{
						{Kind: "PodDisruptionBudget", Namespace: "prod", Name: "api", Detail: "disruptionsAllowed=0"},
					},
					Remediation: "Scale the workload above its minAvailable.",
					Docs:        "https://example.invalid/pdb",
				},
			},
			{
				Check: "webhook-timeout", Category: analyzer.CategoryWebhook,
				Severity: analyzer.SeverityWarning,
				Result:   &analyzer.Result{Status: analyzer.StatusWarn, Message: "1 webhook is slow"},
			},
			{
				Check: "node-ready", Category: analyzer.CategoryNode,
				Severity: analyzer.SeverityError,
				Result:   &analyzer.Result{Status: analyzer.StatusPass, Message: "all nodes ready"},
			},
			{
				Check: "broken", Category: analyzer.CategoryAPI,
				Severity: analyzer.SeverityError,
				Error:    "API server unreachable",
			},
		},
	}
}

func TestWriteJSONIsValidAndComplete(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleReport(), Options{}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}

	if got["verdict"] != "inconclusive" {
		t.Errorf("verdict = %v, want inconclusive (an errored check makes the run inconclusive)", got["verdict"])
	}
	if got["cluster"] != "test-cluster" {
		t.Errorf("cluster = %v, want test-cluster", got["cluster"])
	}
	if got["schemaVersion"] != JSONSchemaVersion {
		t.Errorf("schemaVersion = %v, want %q", got["schemaVersion"], JSONSchemaVersion)
	}

	sum := got["summary"].(map[string]any)
	if sum["blocking"].(float64) != 1 {
		t.Errorf("summary.blocking = %v, want 1", sum["blocking"])
	}
	if sum["errored"].(float64) != 1 {
		t.Errorf("summary.errored = %v, want 1", sum["errored"])
	}

	findings := got["findings"].([]any)
	if len(findings) != 4 {
		t.Fatalf("findings = %d, want 4", len(findings))
	}
	first := findings[0].(map[string]any)
	if first["remediation"] == nil || first["docs"] == nil {
		t.Error("blocking finding lost its remediation or docs in JSON output")
	}
}

func TestWriteJSONNeverEmitsANSI(t *testing.T) {
	// JSON is consumed by machines; color codes would corrupt it. Verify the
	// renderer ignores the color option entirely.
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleReport(), Options{NoColor: false}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if strings.Contains(buf.String(), "\033[") {
		t.Error("JSON output contains ANSI escape codes")
	}
}

func TestWriteTableVerbosity(t *testing.T) {
	tests := []struct {
		name        string
		verbose     bool
		wantPresent []string
		wantAbsent  []string
	}{
		{
			name:        "default hides passing checks",
			verbose:     false,
			wantPresent: []string{"pdb-blocks-drain", "webhook-timeout", "hold launch"},
			wantAbsent:  []string{"node-ready"},
		},
		{
			name:        "verbose shows everything",
			verbose:     true,
			wantPresent: []string{"pdb-blocks-drain", "webhook-timeout", "node-ready"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := WriteTable(&buf, sampleReport(), Options{Verbose: tt.verbose, NoColor: true})
			if err != nil {
				t.Fatalf("WriteTable: %v", err)
			}
			out := buf.String()
			for _, want := range tt.wantPresent {
				if !strings.Contains(out, want) {
					t.Errorf("output missing %q\n---\n%s", want, out)
				}
			}
			for _, absent := range tt.wantAbsent {
				if strings.Contains(out, absent) {
					t.Errorf("output unexpectedly contains %q\n---\n%s", absent, out)
				}
			}
		})
	}
}

func TestWriteTableNoColorSuppressesANSI(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTable(&buf, sampleReport(), Options{NoColor: true}); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}
	if strings.Contains(buf.String(), "\033[") {
		t.Error("NoColor output still contains ANSI escape codes")
	}
}

func TestWriteTableAllClear(t *testing.T) {
	r := &analyzer.Report{
		Cluster: "clean",
		Upgrade: analyzer.Upgrade{
			From: analyzer.MustParseVersion("1.35.3"),
			To:   analyzer.MustParseVersion("1.36.0"),
		},
		Findings: []analyzer.Finding{{
			Check: "node-ready", Severity: analyzer.SeverityError,
			Result: &analyzer.Result{Status: analyzer.StatusPass, Message: "fine"},
		}},
	}

	var buf bytes.Buffer
	if err := WriteTable(&buf, r, Options{NoColor: true}); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}
	if !strings.Contains(buf.String(), "all systems nominal") {
		t.Errorf("clean report should say all systems nominal:\n%s", buf.String())
	}
}

func TestMaxResourcesTruncation(t *testing.T) {
	r := sampleReport()
	for i := 0; i < 20; i++ {
		r.Findings[0].Result.Resources = append(r.Findings[0].Result.Resources,
			analyzer.AffectedResource{Kind: "Pod", Namespace: "prod", Name: "extra"})
	}

	var buf bytes.Buffer
	if err := WriteTable(&buf, r, Options{NoColor: true, MaxResources: 3}); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}
	if !strings.Contains(buf.String(), "and 18 more") {
		t.Errorf("expected a truncation notice:\n%s", buf.String())
	}
}

func TestWriteMarkdownStructure(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, sampleReport(), Options{}); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"# Upgrade preflight",
		"`test-cluster`",
		"v1.35.3 → v1.36.0",
		"## BLOCKS THE UPGRADE", // sections are worklist buckets
		"`pdb-blocks-drain`",
		"**Fix:**",
		"<details>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q\n---\n%s", want, out)
		}
	}
}

func TestWrapText(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		width int
		want  int // expected line count
	}{
		{name: "short text stays on one line", in: "hello world", width: 40, want: 1},
		{name: "long text wraps", in: strings.Repeat("word ", 30), width: 40, want: 4},
		{name: "empty stays empty", in: "", width: 40, want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := len(strings.Split(wrapText(tt.in, tt.width, "  "), "\n"))
			if got != tt.want {
				t.Errorf("wrapText produced %d lines, want %d", got, tt.want)
			}
		})
	}
}

func TestWorklistOrdersByUrgencyNotSeverity(t *testing.T) {
	r := &analyzer.Report{
		Cluster: "c",
		Upgrade: analyzer.Upgrade{
			From: analyzer.MustParseVersion("1.35.3"),
			To:   analyzer.MustParseVersion("1.36.0"),
		},
		Findings: []analyzer.Finding{
			// Declared in deliberately unhelpful order.
			{Check: "cosmetic", Severity: analyzer.SeverityWarning,
				Action: analyzer.ActionReviewLater,
				Result: &analyzer.Result{Status: analyzer.StatusWarn, Message: "cosmetic thing"}},
			{Check: "slow-fix", Severity: analyzer.SeverityWarning,
				Action: analyzer.ActionPlanAhead,
				Result: &analyzer.Result{Status: analyzer.StatusWarn, Message: "needs lead time"}},
			{Check: "blocker", Severity: analyzer.SeverityError,
				Action: analyzer.ActionFixBeforeStart,
				Result: &analyzer.Result{Status: analyzer.StatusFail, Message: "stops the upgrade"}},
		},
	}

	var buf bytes.Buffer
	if err := WriteWorklist(&buf, r, Options{NoColor: true}); err != nil {
		t.Fatalf("WriteWorklist: %v", err)
	}
	out := buf.String()

	// The verdict must be the first thing readable.
	if !strings.HasPrefix(strings.TrimSpace(out), "cluster") {
		t.Errorf("worklist should open with the cluster/verdict header:\n%s", out)
	}
	if !strings.Contains(out, "NOT READY") {
		t.Errorf("worklist missing the top-line verdict:\n%s", out)
	}

	// Blocking work must precede lead-time work, which must precede cosmetics.
	iBlock := strings.Index(out, "stops the upgrade")
	iSlow := strings.Index(out, "needs lead time")
	iCosmetic := strings.Index(out, "cosmetic")
	if iBlock < 0 || iSlow < 0 {
		t.Fatalf("worklist dropped a finding:\n%s", out)
	}
	if iBlock > iSlow {
		t.Errorf("blocking work should come before lead-time work:\n%s", out)
	}
	if iSlow > iCosmetic {
		t.Errorf("lead-time work should come before cosmetic findings:\n%s", out)
	}
}

func TestWorklistCollapsesTheNonBlockingTail(t *testing.T) {
	r := &analyzer.Report{
		Cluster: "c",
		Findings: []analyzer.Finding{
			{Check: "cosmetic-one", Severity: analyzer.SeverityWarning,
				Action: analyzer.ActionReviewLater,
				Result: &analyzer.Result{Status: analyzer.StatusWarn,
					Message:     "a long explanation nobody needs right now",
					Remediation: "some remediation text"}},
		},
	}

	var terse, verbose bytes.Buffer
	_ = WriteWorklist(&terse, r, Options{NoColor: true})
	_ = WriteWorklist(&verbose, r, Options{NoColor: true, Verbose: true})

	if strings.Contains(terse.String(), "a long explanation nobody needs") {
		t.Errorf("non-blocking findings should be collapsed by default:\n%s", terse.String())
	}
	if !strings.Contains(terse.String(), "cosmetic-one") {
		t.Errorf("collapsed section should still name the checks:\n%s", terse.String())
	}
	if !strings.Contains(verbose.String(), "a long explanation nobody needs") {
		t.Errorf("-v should expand the collapsed section:\n%s", verbose.String())
	}
}

func TestJSONCarriesWorklistOrdering(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleReport(), Options{}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	for _, raw := range got["findings"].([]any) {
		f := raw.(map[string]any)
		if f["bucket"] == nil || f["bucket"] == "" {
			t.Errorf("finding %v has no bucket", f["check"])
		}
		// Non-passing findings must carry a worklist position so a consumer can
		// reproduce kupre's prioritisation without reimplementing it.
		if f["status"] != "pass" && f["status"] != "skip" {
			if order, ok := f["order"].(float64); !ok || order < 1 {
				t.Errorf("finding %v has no worklist order", f["check"])
			}
		}
	}
}

func TestWriteHTML(t *testing.T) {
	r := sampleReport()
	// Adversarial content: a finding message that would break or script the
	// page if escaping ever regresses.
	r.Findings[0].Result.Message = `1 PDB blocks drain <script>alert("x")</script>`
	r.Findings[0].Result.Commands = []string{"kubectl scale deployment/api -n prod --replicas=2"}
	r.Findings[0].Limits = "Replica count only."

	var buf bytes.Buffer
	if err := WriteHTML(&buf, r, Options{}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"<!DOCTYPE html>",
		"INCONCLUSIVE",                 // sample report has an errored check
		"BLOCKS THE UPGRADE",           // bucket section
		"kubectl scale deployment/api", // commands block
		"Evidence &amp; limits",        // disclosure
		"Replica count only.",          // limits text
		"&lt;script&gt;",               // escaped, not executed
	} {
		if !strings.Contains(out, want) {
			t.Errorf("html missing %q", want)
		}
	}
	if strings.Contains(out, "<script>alert") {
		t.Fatal("unescaped script tag - HTML injection")
	}
	if strings.Contains(out, "src=\"http") || strings.Contains(out, "href=\"http://cdn") {
		t.Error("html must be self-contained")
	}
}

// TestHTMLHasNoScripts guards the no-JS guarantee the report advertises: page
// switching must be pure CSS, and nothing executable may appear.
func TestHTMLHasNoScripts(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, sampleReport(), Options{}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	out := strings.ToLower(buf.String())
	for _, banned := range []string{"<script", "javascript:", "onclick=", "onload="} {
		if strings.Contains(out, banned) {
			t.Errorf("html contains %q - the report must stay script-free", banned)
		}
	}
}

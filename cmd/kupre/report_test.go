package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
	"github.com/Rusty-Gopher/kupre/pkg/fleet"
	"github.com/Rusty-Gopher/kupre/pkg/report"
)

// reportOpts returns render options suitable for asserting on plain text.
func reportOpts() report.Options { return report.Options{NoColor: true} }

// scanReport builds a report covering every outcome a scan can produce,
// including content that must be escaped by the HTML writer.
func scanReport() *analyzer.Report {
	return &analyzer.Report{
		Cluster: "prod-cluster",
		Mission: "upgrade",
		Upgrade: analyzer.Upgrade{
			From: analyzer.MustParseVersion("1.35.3"),
			To:   analyzer.MustParseVersion("1.36.0"),
		},
		Findings: []analyzer.Finding{
			{
				Check: "pdb-blocks-drain", Category: analyzer.CategoryWorkload,
				Severity: analyzer.SeverityError, Action: analyzer.ActionFixBeforeStart,
				Evidence: "Reads PDB status.", Limits: "Replica count only.",
				Result: &analyzer.Result{
					Status:  analyzer.StatusFail,
					Message: `1 PDB blocks drain <script>alert("x")</script>`,
					Resources: []analyzer.AffectedResource{{
						Kind: "PodDisruptionBudget", Namespace: "prod", Name: "api",
						Detail: "disruptionsAllowed=0",
					}},
					Remediation: "Scale the workload above its minAvailable.",
					Commands:    []string{"kubectl -n prod scale deployment/api --replicas=2"},
				},
			},
			{
				Check: "webhook-timeout", Category: analyzer.CategoryWebhook,
				Severity: analyzer.SeverityWarning, Action: analyzer.ActionReviewLater,
				Result: &analyzer.Result{
					Status: analyzer.StatusWarn, Message: "1 webhook is slow",
					Remediation: "Lower the timeout.",
				},
			},
			{
				Check: "node-ready", Category: analyzer.CategoryNode,
				Severity: analyzer.SeverityError,
				Result:   &analyzer.Result{Status: analyzer.StatusPass, Message: "all nodes ready"},
			},
			{
				Check: "cert-audit", Category: analyzer.CategoryWorkload,
				Severity: analyzer.SeverityError,
				Result:   &analyzer.Result{Status: analyzer.StatusSkip, Message: "not installed"},
			},
		},
	}
}

// TestEveryAdvertisedFormatRendersAScanReport resolves each --output value the
// CLI advertises through the real formatWriter and renders a full scan report
// with it: JSON must parse, HTML must escape, markdown must be structured, and
// every terminal format must show the blocking finding.
func TestEveryAdvertisedFormatRendersAScanReport(t *testing.T) {
	rep := scanReport()

	tests := []struct {
		format string
		verify func(t *testing.T, out string)
	}{
		{format: "json", verify: func(t *testing.T, out string) {
			var got map[string]any
			if err := json.Unmarshal([]byte(out), &got); err != nil {
				t.Fatalf("output is not valid JSON: %v", err)
			}
			if got["verdict"] != "blocked" {
				t.Errorf("verdict = %v, want blocked", got["verdict"])
			}
			if got["exitCode"].(float64) != float64(exitBlocked) {
				t.Errorf("exitCode = %v, want %d", got["exitCode"], exitBlocked)
			}
			if len(got["findings"].([]any)) != 4 {
				t.Errorf("findings = %d, want 4", len(got["findings"].([]any)))
			}
		}},
		{format: "html", verify: func(t *testing.T, out string) {
			for _, want := range []string{
				"<!DOCTYPE html>", "pdb-blocks-drain",
				"kubectl -n prod scale deployment/api", "&lt;script&gt;",
			} {
				if !strings.Contains(out, want) {
					t.Errorf("html missing %q", want)
				}
			}
			if strings.Contains(out, "<script>alert") {
				t.Fatal("unescaped script tag - HTML injection")
			}
		}},
		{format: "markdown", verify: func(t *testing.T, out string) {
			for _, want := range []string{"# Upgrade preflight", "## ", "`pdb-blocks-drain`", "**Fix:**"} {
				if !strings.Contains(out, want) {
					t.Errorf("markdown missing %q", want)
				}
			}
		}},
		{format: "md", verify: func(t *testing.T, out string) {
			if !strings.Contains(out, "# Upgrade preflight") {
				t.Error("md alias did not produce markdown")
			}
		}},
		{format: "table", verify: func(t *testing.T, out string) {
			for _, want := range []string{"pdb-blocks-drain", "NOT READY"} {
				if !strings.Contains(out, want) {
					t.Errorf("worklist missing %q", want)
				}
			}
		}},
		{format: "worklist", verify: func(t *testing.T, out string) {
			if !strings.Contains(out, "pdb-blocks-drain") {
				t.Error("worklist alias missing the blocking finding")
			}
		}},
		{format: "flat", verify: func(t *testing.T, out string) {
			for _, want := range []string{"pdb-blocks-drain", "webhook-timeout"} {
				if !strings.Contains(out, want) {
					t.Errorf("flat table missing %q", want)
				}
			}
		}},
		{format: "report", verify: func(t *testing.T, out string) {
			if !strings.Contains(out, "pdb-blocks-drain") {
				t.Error("report alias missing the blocking finding")
			}
		}},
		{format: "JSON", verify: func(t *testing.T, out string) {
			var got map[string]any
			if err := json.Unmarshal([]byte(out), &got); err != nil {
				t.Fatalf("format matching must be case-insensitive; got invalid JSON: %v", err)
			}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			writer, err := formatWriter(tt.format)
			if err != nil {
				t.Fatalf("formatWriter(%q): %v", tt.format, err)
			}
			var buf bytes.Buffer
			if err := writer(&buf, rep, reportOpts()); err != nil {
				t.Fatalf("render %s: %v", tt.format, err)
			}
			if buf.Len() == 0 {
				t.Fatalf("format %s produced no output", tt.format)
			}
			tt.verify(t, buf.String())
		})
	}

	t.Run("unknown format is rejected", func(t *testing.T) {
		if _, err := formatWriter("yaml"); err == nil {
			t.Error("formatWriter accepted an unsupported format")
		}
	})
}

// TestExitCodeForMapping pins the CLI exit contract: 0 clear, 1 blocking,
// 2 warnings, 3 tool error - and --fail-on-warn promoting only the
// warnings-only verdict.
func TestExitCodeForMapping(t *testing.T) {
	clean := &analyzer.Report{Findings: []analyzer.Finding{{
		Check: "fine", Severity: analyzer.SeverityError,
		Result: &analyzer.Result{Status: analyzer.StatusPass},
	}}}
	warnOnly := &analyzer.Report{Findings: []analyzer.Finding{{
		Check: "iffy", Severity: analyzer.SeverityWarning,
		Result: &analyzer.Result{Status: analyzer.StatusWarn},
	}}}
	blocked := scanReport()
	erroredCheck := &analyzer.Report{Findings: []analyzer.Finding{{
		Check: "broken", Severity: analyzer.SeverityError, Error: "unreachable",
	}}}
	toolError := &analyzer.Report{Errors: []string{"provider detection failed"}}

	tests := []struct {
		name       string
		rep        *analyzer.Report
		failOnWarn bool
		want       int
	}{
		{name: "clean is 0", rep: clean, want: exitOK},
		{name: "clean stays 0 under fail-on-warn", rep: clean, failOnWarn: true, want: exitOK},
		{name: "warnings are 2", rep: warnOnly, want: exitWarnings},
		{name: "fail-on-warn promotes warnings to 1", rep: warnOnly, failOnWarn: true, want: exitBlocked},
		{name: "blocking is 1", rep: blocked, want: exitBlocked},
		{name: "blocking unchanged by fail-on-warn", rep: blocked, failOnWarn: true, want: exitBlocked},
		{name: "errored check is 3", rep: erroredCheck, want: exitToolError},
		{name: "errored check unchanged by fail-on-warn", rep: erroredCheck, failOnWarn: true, want: exitToolError},
		{name: "tool-level error is 3", rep: toolError, want: exitToolError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCodeFor(tt.rep, tt.failOnWarn); got != tt.want {
				t.Errorf("exitCodeFor() = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestIsTerminalNonTerminalWriters covers the seam that decides whether
// `-o html` writes a report file (interactive terminal) or streams to stdout
// (pipes, redirects, tests): neither a buffer nor a regular file is a
// terminal, so both must stream.
func TestIsTerminalNonTerminalWriters(t *testing.T) {
	if isTerminal(&bytes.Buffer{}) {
		t.Error("a bytes.Buffer is not a terminal")
	}

	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTerminal(f) {
		t.Error("a regular file is not a terminal; redirected output must stream, not re-write a report file")
	}
}

// writeUnreachableKubeconfig writes a syntactically valid kubeconfig whose
// server does not exist, so connecting fails fast.
func writeUnreachableKubeconfig(t *testing.T, contexts ...string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: Config\ncurrent-context: " + contexts[0] + "\n" +
		"clusters:\n  - name: fake\n    cluster:\n      server: https://127.0.0.1:1\n" +
		"users:\n  - name: fake\n    user: {}\ncontexts:\n")
	for _, c := range contexts {
		b.WriteString("  - name: " + c + "\n    context:\n      cluster: fake\n      user: fake\n")
	}
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestMissionCommandsExitToolErrorWhenUnreachable drives each mission command
// end to end against a kubeconfig whose API server does not exist: the
// process exit code must be 3 (tool error), never a clean or blocked verdict.
func TestMissionCommandsExitToolErrorWhenUnreachable(t *testing.T) {
	kc := writeUnreachableKubeconfig(t, "ghost")

	tests := [][]string{
		{"check", "--kubeconfig", kc, "--target-version", "1.36.0"},
		{"health", "--kubeconfig", kc},
		{"certs", "--kubeconfig", kc},
	}
	for _, args := range tests {
		t.Run(args[0], func(t *testing.T) {
			if got := run(args); got != exitToolError {
				t.Errorf("run(%v) = %d, want %d", args, got, exitToolError)
			}
		})
	}
}

// TestFleetCommandWithUnreachableClusters drives `kupre fleet` end to end: an
// unreachable fleet must exit with the tool-error code and, in table mode,
// name every context as unreachable in the summary rather than dropping it.
func TestFleetCommandWithUnreachableClusters(t *testing.T) {
	kc := writeUnreachableKubeconfig(t, "prod-a", "prod-b")

	t.Run("table output names unreachable clusters", func(t *testing.T) {
		var buf bytes.Buffer
		root := newRootCmd()
		root.SetOut(&buf)
		root.SetErr(io.Discard)
		root.SetArgs([]string{"fleet", "--kubeconfig", kc, "--target-version", "1.36.0"})

		err := root.Execute()
		var ee exitError
		if !errors.As(err, &ee) || ee.code != exitToolError {
			t.Fatalf("fleet exit = %v, want exit code %d", err, exitToolError)
		}
		out := buf.String()
		for _, want := range []string{"prod-a", "prod-b", "unreachable", "fleet summary"} {
			if !strings.Contains(out, want) {
				t.Errorf("fleet output missing %q\n---\n%s", want, out)
			}
		}
	})

	t.Run("json output is machine-parseable", func(t *testing.T) {
		var buf bytes.Buffer
		root := newRootCmd()
		root.SetOut(&buf)
		root.SetErr(io.Discard)
		root.SetArgs([]string{"fleet", "--kubeconfig", kc, "--target-version", "1.36.0", "-o", "json"})

		err := root.Execute()
		var ee exitError
		if !errors.As(err, &ee) || ee.code != exitToolError {
			t.Fatalf("fleet exit = %v, want exit code %d", err, exitToolError)
		}
		var got map[string]any
		if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
			t.Fatalf("fleet JSON does not parse: %v", err)
		}
		results := got["results"].([]any)
		if len(results) != 2 {
			t.Fatalf("results = %d, want both contexts present", len(results))
		}
		for _, raw := range results {
			r := raw.(map[string]any)
			if r["error"] == nil || r["error"] == "" {
				t.Errorf("context %v has no error despite being unreachable", r["context"])
			}
		}
	})

	t.Run("html is refused for fleets", func(t *testing.T) {
		root := newRootCmd()
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		root.SetArgs([]string{"fleet", "--kubeconfig", kc, "--target-version", "1.36.0", "-o", "html"})

		err := root.Execute()
		if err == nil {
			t.Fatal("fleet accepted -o html; it is documented as per-cluster only")
		}
		var ee exitError
		if errors.As(err, &ee) {
			t.Fatalf("html refusal should be a plain error, got exit code %d", ee.code)
		}
	})
}

// TestWriteFleetSummary verifies the aggregate fleet verdict line counts
// ready, blocked, and unreachable clusters correctly.
func TestWriteFleetSummary(t *testing.T) {
	blocked := &analyzer.Report{Findings: []analyzer.Finding{{
		Check: "blocker", Severity: analyzer.SeverityError,
		Result: &analyzer.Result{Status: analyzer.StatusFail, Message: "broken"},
	}}}
	ready := &analyzer.Report{Findings: []analyzer.Finding{{
		Check: "fine", Severity: analyzer.SeverityError,
		Result: &analyzer.Result{Status: analyzer.StatusPass, Message: "ok"},
	}}}
	fr := &fleet.FleetReport{Results: []fleet.ClusterResult{
		{Context: "a", Report: ready},
		{Context: "b", Report: blocked},
		{Context: "c", Error: "unreachable"},
	}}

	var buf bytes.Buffer
	writeFleetSummary(&buf, fr, reportOpts())
	out := buf.String()
	if !strings.Contains(out, "clusters scanned: 3 - 1 ready, 1 blocked, 1 unreachable") {
		t.Errorf("summary miscounts the fleet:\n%s", out)
	}
	if !strings.Contains(out, "findings: 1 blocking") {
		t.Errorf("summary lost the blocking count:\n%s", out)
	}
}

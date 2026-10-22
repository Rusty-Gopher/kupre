package fleet

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
)

// reportWithExit builds a minimal report whose ExitCode() is the given code.
func reportWithExit(code int) *analyzer.Report {
	r := &analyzer.Report{Cluster: "c"}
	switch code {
	case analyzer.ExitBlocked:
		r.Findings = []analyzer.Finding{{
			Check: "blocker", Severity: analyzer.SeverityError,
			Result: &analyzer.Result{Status: analyzer.StatusFail, Message: "broken"},
		}}
	case analyzer.ExitWarnings:
		r.Findings = []analyzer.Finding{{
			Check: "warner", Severity: analyzer.SeverityWarning,
			Result: &analyzer.Result{Status: analyzer.StatusWarn, Message: "iffy"},
		}}
	case analyzer.ExitToolError:
		r.Errors = []string{"scan incomplete"}
	default:
		r.Findings = []analyzer.Finding{{
			Check: "fine", Severity: analyzer.SeverityError,
			Result: &analyzer.Result{Status: analyzer.StatusPass, Message: "ok"},
		}}
	}
	return r
}

// TestFleetExitCodeIsWorstOf verifies the pipeline contract: the fleet exit
// code is the worst outcome across every cluster, and a cluster with no report
// at all counts as a tool error.
func TestFleetExitCodeIsWorstOf(t *testing.T) {
	ok := ClusterResult{Context: "ok", Report: reportWithExit(analyzer.ExitOK)}
	warn := ClusterResult{Context: "warn", Report: reportWithExit(analyzer.ExitWarnings)}
	blocked := ClusterResult{Context: "blocked", Report: reportWithExit(analyzer.ExitBlocked)}
	toolErr := ClusterResult{Context: "toolerr", Report: reportWithExit(analyzer.ExitToolError)}
	unreachable := ClusterResult{Context: "gone", Error: "connection refused"}

	tests := []struct {
		name    string
		results []ClusterResult
		want    int
	}{
		{name: "empty fleet is clean", results: nil, want: analyzer.ExitOK},
		{name: "all clean", results: []ClusterResult{ok, ok}, want: analyzer.ExitOK},
		{name: "one warning taints the fleet", results: []ClusterResult{ok, warn}, want: analyzer.ExitWarnings},
		{name: "blocked beats warnings", results: []ClusterResult{warn, blocked, ok}, want: analyzer.ExitBlocked},
		{name: "unreachable cluster beats blocked", results: []ClusterResult{blocked, unreachable}, want: analyzer.ExitToolError},
		{name: "errored report is a tool error", results: []ClusterResult{ok, toolErr}, want: analyzer.ExitToolError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fr := &FleetReport{Results: tt.results}
			if got := fr.ExitCode(); got != tt.want {
				t.Errorf("ExitCode() = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestFleetSummarizeAggregates verifies per-cluster counts are summed and that
// a reportless cluster is counted as errored rather than vanishing.
func TestFleetSummarizeAggregates(t *testing.T) {
	fr := &FleetReport{Results: []ClusterResult{
		{Context: "a", Report: reportWithExit(analyzer.ExitBlocked)},
		{Context: "b", Report: reportWithExit(analyzer.ExitWarnings)},
		{Context: "c", Report: reportWithExit(analyzer.ExitOK)},
		{Context: "gone", Error: "unreachable"},
	}}
	got := fr.Summarize()
	want := analyzer.Summary{Blocking: 1, Concerning: 1, Passed: 1, Errored: 1}
	if got != want {
		t.Errorf("Summarize() = %+v, want %+v", got, want)
	}
}

// TestScanBoundsConcurrencyAndKeepsEveryCluster drives Scan through the stub
// seam: the semaphore must never admit more than Concurrency scans at once,
// and every context must come back exactly once, sorted by name.
func TestScanBoundsConcurrencyAndKeepsEveryCluster(t *testing.T) {
	const limit = 3
	contexts := []string{"g", "c", "a", "e", "b", "f", "d", "h"}

	var (
		mu           sync.Mutex
		current, max int
	)
	s := &Scanner{
		Contexts:      contexts,
		Concurrency:   limit,
		TargetVersion: analyzer.MustParseVersion("1.36.0"),
		scan: func(_ context.Context, name string) ClusterResult {
			mu.Lock()
			current++
			if current > max {
				max = current
			}
			mu.Unlock()

			time.Sleep(5 * time.Millisecond) // hold the slot long enough to overlap

			mu.Lock()
			current--
			mu.Unlock()
			return ClusterResult{Context: name, Report: reportWithExit(analyzer.ExitOK)}
		},
	}

	fr, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if max > limit {
		t.Errorf("observed %d concurrent scans, limit is %d", max, limit)
	}
	got := make([]string, 0, len(fr.Results))
	for _, r := range fr.Results {
		got = append(got, r.Context)
	}
	want := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("results = %v, want every context once, sorted: %v", got, want)
	}
	if fr.ExitCode() != analyzer.ExitOK {
		t.Errorf("ExitCode() = %d, want %d", fr.ExitCode(), analyzer.ExitOK)
	}
}

// writeTestKubeconfig writes a minimal kubeconfig with the given contexts.
func writeTestKubeconfig(t *testing.T, contexts ...string) string {
	t.Helper()
	var b []byte
	b = append(b, []byte("apiVersion: v1\nkind: Config\nclusters:\n"+
		"  - name: fake\n    cluster:\n      server: https://127.0.0.1:1\n"+
		"users:\n  - name: fake\n    user: {}\ncontexts:\n")...)
	for _, c := range contexts {
		b = append(b, []byte("  - name: "+c+"\n    context:\n      cluster: fake\n      user: fake\n")...)
	}
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestResolveContexts covers context selection: an explicit list wins, an
// unfiltered scan takes every kubeconfig context sorted, and a kubeconfig
// without contexts is an error rather than an empty (all-clear) fleet.
func TestResolveContexts(t *testing.T) {
	t.Run("explicit contexts are used verbatim", func(t *testing.T) {
		s := &Scanner{Contexts: []string{"z", "a"}}
		got, err := s.resolveContexts()
		if err != nil {
			t.Fatalf("resolveContexts: %v", err)
		}
		if !reflect.DeepEqual(got, []string{"z", "a"}) {
			t.Errorf("contexts = %v, want the explicit list unaltered", got)
		}
	})

	t.Run("kubeconfig contexts are discovered and sorted", func(t *testing.T) {
		s := &Scanner{Kubeconfig: writeTestKubeconfig(t, "prod-b", "prod-a")}
		got, err := s.resolveContexts()
		if err != nil {
			t.Fatalf("resolveContexts: %v", err)
		}
		if !reflect.DeepEqual(got, []string{"prod-a", "prod-b"}) {
			t.Errorf("contexts = %v, want [prod-a prod-b]", got)
		}
	})

	t.Run("kubeconfig with no contexts is an error", func(t *testing.T) {
		s := &Scanner{Kubeconfig: writeTestKubeconfig(t)}
		if _, err := s.resolveContexts(); err == nil {
			t.Fatal("expected an error for a kubeconfig without contexts")
		}
	})
}

// TestCancelledScanDropsNoCluster guards against the fleet report silently
// omitting clusters whose scan never started. A fleet report that lists 3 of 5
// clusters reads as "the other two were fine", which is the dangerous reading.
func TestCancelledScanDropsNoCluster(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // everything is already expired before any scan starts

	s := &Scanner{
		Contexts:      []string{"prod-a", "prod-b", "prod-c"},
		Concurrency:   1,
		TargetVersion: analyzer.MustParseVersion("1.36.0"),
	}
	fr, err := s.Scan(ctx)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if len(fr.Results) != 3 {
		got := make([]string, 0, len(fr.Results))
		for _, r := range fr.Results {
			got = append(got, r.Context)
		}
		t.Fatalf("results = %d (%v), want all 3 contexts present", len(fr.Results), got)
	}
	for _, r := range fr.Results {
		if r.Error == "" && (r.Report == nil || r.Report.ExitCode() == analyzer.ExitOK) {
			t.Errorf("context %q reported clean under a cancelled scan", r.Context)
		}
	}
	if fr.ExitCode() != analyzer.ExitToolError {
		t.Errorf("ExitCode() = %d, want %d (tool error)", fr.ExitCode(), analyzer.ExitToolError)
	}
}

// TestUnreachableClusterIsAnErrorResult confirms a bad context yields an
// explicit error entry rather than being skipped.
func TestUnreachableClusterIsAnErrorResult(t *testing.T) {
	s := &Scanner{
		Kubeconfig:    "/nonexistent/kubeconfig",
		Contexts:      []string{"ghost"},
		TargetVersion: analyzer.MustParseVersion("1.36.0"),
	}
	fr, err := s.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(fr.Results) != 1 || fr.Results[0].Error == "" {
		t.Fatalf("want one explicit error result, got %+v", fr.Results)
	}
}

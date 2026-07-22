package fleet

import (
	"context"
	"testing"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
)

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

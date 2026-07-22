package analyzer

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// staticCheck builds a check returning a fixed result.
func staticCheck(name string, sev Severity, res *Result) Check {
	return Check{
		Name: name, Category: CategoryAPI, Severity: sev,
		Run: func(context.Context, *Cluster, Upgrade) (*Result, error) { return res, nil },
	}
}

func TestEngineRunCollectsAllResults(t *testing.T) {
	e := NewEngine(
		staticCheck("a", SeverityError, Pass("fine")),
		staticCheck("b", SeverityWarning, Warn("hmm")),
		staticCheck("c", SeverityError, Fail("broken")),
		staticCheck("d", SeverityInfo, Skip("n/a")),
	)

	rep := e.Run(context.Background(), newTestCluster(), testUpgrade())
	if len(rep.Findings) != 4 {
		t.Fatalf("got %d findings, want 4", len(rep.Findings))
	}

	sum := rep.Summarize()
	if sum.Passed != 1 || sum.Concerning != 1 || sum.Blocking != 1 || sum.Skipped != 1 {
		t.Errorf("summary = %+v, want 1 of each", sum)
	}
	if got := rep.ExitCode(); got != ExitBlocked {
		t.Errorf("ExitCode() = %d, want %d", got, ExitBlocked)
	}
}

func TestEngineIsolatesFailures(t *testing.T) {
	// A check that errors or panics must not prevent the others from reporting.
	// This is the property that keeps one broken check from hiding a real finding.
	e := NewEngine(
		Check{Name: "errors", Category: CategoryAPI, Severity: SeverityError,
			Run: func(context.Context, *Cluster, Upgrade) (*Result, error) {
				return nil, errors.New("API server unreachable")
			}},
		Check{Name: "panics", Category: CategoryAPI, Severity: SeverityError,
			Run: func(context.Context, *Cluster, Upgrade) (*Result, error) {
				var p *Result
				return p.WithRemediation("boom"), nil // nil pointer dereference
			}},
		Check{Name: "returns nil", Category: CategoryAPI, Severity: SeverityInfo,
			Run: func(context.Context, *Cluster, Upgrade) (*Result, error) { return nil, nil }},
		staticCheck("healthy", SeverityError, Pass("fine")),
	)

	rep := e.Run(context.Background(), newTestCluster(), testUpgrade())
	if len(rep.Findings) != 4 {
		t.Fatalf("got %d findings, want 4", len(rep.Findings))
	}

	byName := map[string]Finding{}
	for _, f := range rep.Findings {
		byName[f.Check] = f
	}

	if e := byName["errors"].Error; !strings.Contains(e, "unreachable") {
		t.Errorf("errors check: Error = %q, want it to mention the cause", e)
	}
	if e := byName["panics"].Error; !strings.Contains(e, "panicked") {
		t.Errorf("panics check: Error = %q, want a recovered panic", e)
	}
	if e := byName["returns nil"].Error; e == "" {
		t.Error("nil-result check: want an error, got none")
	}
	if f := byName["healthy"]; f.Error != "" || f.Result.Status != StatusPass {
		t.Errorf("healthy check was affected by its neighbours: %+v", f)
	}

	// Any errored check makes the whole run inconclusive rather than clean.
	if got := rep.ExitCode(); got != ExitToolError {
		t.Errorf("ExitCode() = %d, want %d", got, ExitToolError)
	}
}

func TestEngineProgressReporting(t *testing.T) {
	const n = 12
	checks := make([]Check, 0, n)
	for i := 0; i < n; i++ {
		checks = append(checks, staticCheck(string(rune('a'+i)), SeverityInfo, Pass("ok")))
	}
	e := NewEngine(checks...)

	var (
		mu    sync.Mutex
		calls int
		maxD  int
	)
	e.Run(context.Background(), newTestCluster(), testUpgrade(), func(done, total int, _ string) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if total != n {
			t.Errorf("progress total = %d, want %d", total, n)
		}
		if done > maxD {
			maxD = done
		}
	})

	if calls != n {
		t.Errorf("progress called %d times, want %d", calls, n)
	}
	if maxD != n {
		t.Errorf("final progress done = %d, want %d", maxD, n)
	}
}

func TestEngineRespectsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	e := NewEngine(staticCheck("a", SeverityInfo, Pass("ok")))
	rep := e.Run(ctx, newTestCluster(), testUpgrade())

	if len(rep.Errors) == 0 {
		t.Error("want a tool-level error recording the interruption, got none")
	}
	if got := rep.ExitCode(); got != ExitToolError {
		t.Errorf("ExitCode() = %d, want %d", got, ExitToolError)
	}
}

func TestExitCodes(t *testing.T) {
	tests := []struct {
		name  string
		check Check
		want  int
	}{
		{name: "all pass", check: staticCheck("a", SeverityError, Pass("ok")), want: ExitOK},
		{name: "warning", check: staticCheck("a", SeverityWarning, Warn("hmm")), want: ExitWarnings},
		{name: "blocking", check: staticCheck("a", SeverityError, Fail("no")), want: ExitBlocked},
		{name: "skip is not a warning", check: staticCheck("a", SeverityError, Skip("n/a")), want: ExitOK},
		{
			// A failing check registered at warning severity is concerning, not
			// blocking: severity decides whether a failure halts the upgrade.
			name:  "warn-severity failure does not block",
			check: staticCheck("a", SeverityWarning, Fail("no")),
			want:  ExitWarnings,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := NewEngine(tt.check).Run(context.Background(), newTestCluster(), testUpgrade())
			if got := rep.ExitCode(); got != tt.want {
				t.Errorf("ExitCode() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSortFindingsOrdersBySeverity(t *testing.T) {
	e := NewEngine(
		staticCheck("zpass", SeverityInfo, Pass("ok")),
		staticCheck("askip", SeverityInfo, Skip("n/a")),
		staticCheck("zfail", SeverityError, Fail("bad")),
		staticCheck("awarn", SeverityWarning, Warn("hmm")),
	)
	rep := e.Run(context.Background(), newTestCluster(), testUpgrade())

	want := []string{"zfail", "awarn", "zpass", "askip"}
	for i, name := range want {
		if rep.Findings[i].Check != name {
			got := make([]string, len(rep.Findings))
			for j, f := range rep.Findings {
				got[j] = f.Check
			}
			t.Fatalf("finding order = %v, want %v", got, want)
		}
	}
}

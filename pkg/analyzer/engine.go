package analyzer

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Engine runs a set of checks against a cluster and collects the results.
type Engine struct {
	checks []Check
	// Concurrency bounds how many checks run at once. Zero means unlimited.
	Concurrency int
}

// NewEngine builds an engine over the given checks.
func NewEngine(checks ...Check) *Engine {
	return &Engine{checks: checks, Concurrency: 8}
}

// Register appends checks to the engine.
func (e *Engine) Register(checks ...Check) { e.checks = append(e.checks, checks...) }

// Checks returns the registered checks.
func (e *Engine) Checks() []Check { return e.checks }

// Len returns the number of registered checks.
func (e *Engine) Len() int { return len(e.checks) }

// Progress reports check completion to a caller, e.g. the TUI. It is invoked
// from multiple goroutines and must be safe for concurrent use.
type Progress func(done, total int, check string)

// Run executes every registered check against the cluster and returns a report.
// An optional Progress callback receives completion updates as checks finish.
//
// A check that returns an error is recorded as an errored finding rather than
// aborting the run: one broken check must not hide the results of the others.
// Panics in a check are recovered for the same reason.
func (e *Engine) Run(ctx context.Context, c *Cluster, up Upgrade, progress ...Progress) *Report {
	var onProgress Progress
	if len(progress) > 0 {
		onProgress = progress[0]
	}

	report := &Report{
		Cluster:  c.Name,
		Context:  c.Name,
		Upgrade:  up,
		Findings: make([]Finding, 0, len(e.checks)),
	}

	limit := e.Concurrency
	if limit <= 0 {
		limit = len(e.checks)
	}
	if limit < 1 {
		limit = 1
	}

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		sem  = make(chan struct{}, limit)
		done int
	)

	for _, chk := range e.checks {
		wg.Add(1)
		go func(chk Check) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			f := runCheck(ctx, chk, c, up)

			mu.Lock()
			report.Findings = append(report.Findings, f)
			done++
			n := done
			mu.Unlock()

			if onProgress != nil {
				onProgress(n, len(e.checks), chk.Name)
			}
		}(chk)
	}
	wg.Wait()

	if err := ctx.Err(); err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("scan interrupted: %v", err))
	}

	SortFindings(report.Findings)
	return report
}

// runCheck executes a single check, converting errors and panics into an
// errored finding.
func runCheck(ctx context.Context, chk Check, c *Cluster, up Upgrade) (f Finding) {
	f = Finding{
		Check: chk.Name, Category: chk.Category, Severity: chk.Severity,
		Action: chk.Action, Evidence: chk.Evidence, Limits: chk.Limits,
	}

	start := time.Now()
	defer func() {
		f.Duration = time.Since(start)
		if r := recover(); r != nil {
			f.Result = nil
			f.Error = fmt.Sprintf("check panicked: %v", r)
		}
	}()

	res, err := chk.Run(ctx, c, up)
	switch {
	case err != nil:
		f.Error = err.Error()
	case res == nil:
		f.Error = "check returned no result"
	default:
		f.Result = res
	}
	return f
}

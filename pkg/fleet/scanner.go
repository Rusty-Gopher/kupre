// Package fleet scans multiple clusters in one run by iterating kubeconfig
// contexts.
package fleet

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
	"github.com/Rusty-Gopher/kupre/pkg/provider"
	"k8s.io/client-go/tools/clientcmd"
)

// Scanner runs preflight checks across several kubeconfig contexts.
type Scanner struct {
	// Kubeconfig is the kubeconfig path, or "" for the standard loading rules.
	Kubeconfig string
	// Contexts limits the scan to these context names. Empty means all.
	Contexts []string
	// Concurrency bounds how many clusters are scanned at once.
	Concurrency int
	// TargetVersion is the upgrade target applied to every cluster.
	TargetVersion analyzer.Version
}

// ClusterResult pairs a context name with its report or the error that
// prevented one being produced.
type ClusterResult struct {
	Context string           `json:"context"`
	Report  *analyzer.Report `json:"report,omitempty"`
	Error   string           `json:"error,omitempty"`
}

// FleetReport is the outcome of scanning several clusters.
type FleetReport struct {
	Target  analyzer.Version `json:"target"`
	Results []ClusterResult  `json:"results"`
}

// Summarize aggregates counts across every cluster that produced a report.
func (f *FleetReport) Summarize() analyzer.Summary {
	var total analyzer.Summary
	for _, r := range f.Results {
		if r.Report == nil {
			total.Errored++
			continue
		}
		s := r.Report.Summarize()
		total.Blocking += s.Blocking
		total.Concerning += s.Concerning
		total.Passed += s.Passed
		total.Skipped += s.Skipped
		total.Errored += s.Errored
	}
	return total
}

// ExitCode returns the worst exit code across the fleet, so a pipeline fails if
// any cluster is not ready.
func (f *FleetReport) ExitCode() int {
	worst := analyzer.ExitOK
	rank := map[int]int{
		analyzer.ExitOK: 0, analyzer.ExitWarnings: 1,
		analyzer.ExitBlocked: 2, analyzer.ExitToolError: 3,
	}
	for _, r := range f.Results {
		code := analyzer.ExitToolError
		if r.Report != nil {
			code = r.Report.ExitCode()
		}
		if rank[code] > rank[worst] {
			worst = code
		}
	}
	return worst
}

// Scan runs the preflight checks against every selected context.
//
// A cluster that cannot be reached is recorded as a failed ClusterResult rather
// than aborting the fleet scan: one unreachable cluster must not hide the
// results for the rest.
func (s *Scanner) Scan(ctx context.Context) (*FleetReport, error) {
	contexts, err := s.resolveContexts()
	if err != nil {
		return nil, err
	}

	limit := s.Concurrency
	if limit <= 0 {
		limit = 4
	}

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		sem     = make(chan struct{}, limit)
		results = make([]ClusterResult, 0, len(contexts))
	)

	for _, name := range contexts {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				// Never silently drop a cluster: a context that timed out while
				// queued must appear in the result as unscanned, or the fleet
				// report reads as complete when it is not.
				mu.Lock()
				results = append(results, ClusterResult{
					Context: name,
					Error:   fmt.Sprintf("not scanned: %v before the scan could start", ctx.Err()),
				})
				mu.Unlock()
				return
			}

			res := s.scanOne(ctx, name)

			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		}(name)
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].Context < results[j].Context })
	return &FleetReport{Target: s.TargetVersion, Results: results}, nil
}

// scanOne connects to and scans a single context.
func (s *Scanner) scanOne(ctx context.Context, name string) ClusterResult {
	cluster, err := analyzer.Connect(ctx, s.Kubeconfig, name)
	if err != nil {
		return ClusterResult{Context: name, Error: err.Error()}
	}

	engine := analyzer.NewEngine(analyzer.AllChecks()...)
	providerChecks, detectFailures := provider.ChecksFor(ctx, cluster)
	engine.Register(providerChecks...)

	up := analyzer.Upgrade{From: cluster.ServerVersion, To: s.TargetVersion}
	rep := engine.Run(ctx, cluster, up)
	rep.Mission = "upgrade"
	rep.Errors = append(rep.Errors, detectFailures...)
	return ClusterResult{Context: name, Report: rep}
}

// resolveContexts returns the context names to scan.
func (s *Scanner) resolveContexts() ([]string, error) {
	if len(s.Contexts) > 0 {
		return s.Contexts, nil
	}

	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if s.Kubeconfig != "" {
		rules = &clientcmd.ClientConfigLoadingRules{ExplicitPath: s.Kubeconfig}
	}
	cfg, err := rules.Load()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	if len(cfg.Contexts) == 0 {
		return nil, fmt.Errorf("kubeconfig contains no contexts")
	}

	names := make([]string, 0, len(cfg.Contexts))
	for name := range cfg.Contexts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

package policy

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
	"github.com/Rusty-Gopher/kupre/pkg/report"
)

// Baseline is a previous kupre JSON report whose known findings are accepted,
// so CI fails only on what is new.
type Baseline struct {
	source string
	// byCheck maps a check to the resources it reported, for checks whose
	// status was warn or fail.
	byCheck map[string]baselineEntry
}

type baselineEntry struct {
	resources map[string]bool
	// complete is false when the baseline truncated the resource list; then
	// an unlisted resource cannot be proven old, and is treated as new.
	complete bool
}

type baselineReport struct {
	SchemaVersion string `json:"schemaVersion"`
	Findings      []struct {
		Check     string `json:"check"`
		Status    string `json:"status"`
		Resources []struct {
			Kind      string `json:"kind"`
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
		} `json:"resources"`
		ResourcesTruncated int `json:"resourcesTruncated"`
	} `json:"findings"`
}

// LoadBaseline reads a report written by kupre -o json.
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var br baselineReport
	if err := json.Unmarshal(data, &br); err != nil {
		return nil, fmt.Errorf("baseline %s: not a kupre JSON report: %w", path, err)
	}
	if br.SchemaVersion != report.JSONSchemaVersion {
		return nil, fmt.Errorf("baseline %s: schemaVersion %q, want %q (regenerate it with this kupre)",
			path, br.SchemaVersion, report.JSONSchemaVersion)
	}
	b := &Baseline{source: path, byCheck: map[string]baselineEntry{}}
	for _, f := range br.Findings {
		if f.Status != "warn" && f.Status != "fail" {
			continue
		}
		e := baselineEntry{resources: map[string]bool{}, complete: f.ResourcesTruncated == 0}
		for _, r := range f.Resources {
			e.resources[resourceKey(r.Kind, r.Namespace, r.Name)] = true
		}
		b.byCheck[f.Check] = e
	}
	return b, nil
}

func resourceKey(kind, ns, name string) string { return kind + "/" + ns + "/" + name }

// Apply accepts findings already present in the baseline. A finding is known
// only if its check was a problem in the baseline and every resource it names
// now was named then. Blocking findings are never accepted: a known blocker
// still blocks.
func (b *Baseline) Apply(r *analyzer.Report) {
	for i := range r.Findings {
		f := &r.Findings[i]
		if f.Suppression != nil || f.Error != "" || f.Result == nil ||
			(f.Result.Status != analyzer.StatusWarn && f.Result.Status != analyzer.StatusFail) {
			continue
		}
		e, ok := b.byCheck[f.Check]
		if !ok {
			f.PolicyNotes = append(f.PolicyNotes, "new since baseline")
			continue
		}
		var added int
		for _, a := range f.Result.Resources {
			if !e.resources[resourceKey(a.Kind, a.Namespace, a.Name)] {
				added++
			}
		}
		if added > 0 {
			f.PolicyNotes = append(f.PolicyNotes, fmt.Sprintf("new since baseline: %d resource(s)", added))
			if !e.complete {
				f.PolicyNotes = append(f.PolicyNotes, "baseline listed only some resources; regenerate it with --max-resources -1")
			}
			continue
		}
		if f.Blocking() {
			f.PolicyNotes = append(f.PolicyNotes, "in baseline, but blocking findings are never accepted")
			continue
		}
		f.Suppression = &analyzer.Suppression{Kind: "baseline", Reason: "present in " + b.source}
	}
}

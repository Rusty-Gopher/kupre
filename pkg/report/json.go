package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
)

// JSONSchemaVersion identifies the --output json contract. Adding fields is
// compatible and keeps the version; renaming, removing or changing the meaning
// of a field, a status, a bucket slug or an exit code bumps it.
const JSONSchemaVersion = "1"

// jsonReport is the wire format for --output json. It is a distinct type from
// analyzer.Report so the CLI contract stays stable as internals change.
type jsonReport struct {
	SchemaVersion string          `json:"schemaVersion"`
	Cluster       string          `json:"cluster"`
	Upgrade       jsonUpgrade     `json:"upgrade"`
	Summary       jsonSummary     `json:"summary"`
	Verdict       string          `json:"verdict"`
	ExitCode      int             `json:"exitCode"`
	Findings      []jsonFinding   `json:"findings"`
	Errors        []string        `json:"errors,omitempty"`
	Meta          json.RawMessage `json:"-"`
}

type jsonUpgrade struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type jsonSummary struct {
	Blocking   int `json:"blocking"`
	Concerning int `json:"warnings"`
	Passed     int `json:"passed"`
	Skipped    int `json:"skipped"`
	Errored    int `json:"errored"`
	Total      int `json:"total"`
}

type jsonFinding struct {
	Check    string `json:"check"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Status   string `json:"status"`
	Blocking bool   `json:"blocking"`
	// Bucket is the worklist section this finding belongs to, and Order is its
	// position in the overall plan. Together they let a consumer reproduce
	// kupre's prioritisation without reimplementing it.
	Bucket string `json:"bucket"`
	Order  int    `json:"order"`
	// Evidence states what the check inspected; Limits what it cannot conclude.
	Evidence    string         `json:"evidence,omitempty"`
	Limits      string         `json:"limits,omitempty"`
	Message     string         `json:"message"`
	Remediation string         `json:"remediation,omitempty"`
	Commands    []string       `json:"commands,omitempty"`
	Docs        string         `json:"docs,omitempty"`
	Resources   []jsonResource `json:"resources,omitempty"`
	// ResourcesTruncated counts resources omitted by --max-resources, so a
	// consumer can tell a short list from a complete one.
	ResourcesTruncated int    `json:"resourcesTruncated,omitempty"`
	Error              string `json:"error,omitempty"`
}

type jsonResource struct {
	Kind       string `json:"kind,omitempty"`
	APIVersion string `json:"apiVersion,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
	Detail     string `json:"detail,omitempty"`
}

// bucketSlug renders a bucket as a stable machine-readable identifier. These
// strings are part of the CLI's output contract; do not rename them casually.
func bucketSlug(b analyzer.Bucket) string {
	switch b {
	case analyzer.BucketFixBeforeStart:
		return "fix-before-start"
	case analyzer.BucketPlanAhead:
		return "plan-ahead"
	case analyzer.BucketVerifyManually:
		return "verify-manually"
	case analyzer.BucketResolveFirst:
		return "resolve-first"
	case analyzer.BucketReviewLater:
		return "review-later"
	case analyzer.BucketInconclusive:
		return "inconclusive"
	default:
		return "none"
	}
}

// verdict renders the one-word outcome used by dashboards and CI summaries.
func verdict(sum analyzer.Summary, r *analyzer.Report) string {
	switch {
	case len(r.Errors) > 0 || sum.Errored > 0:
		return "inconclusive"
	case sum.Blocking > 0:
		return "blocked"
	case sum.Concerning > 0:
		return "warnings"
	default:
		return "ready"
	}
}

// WriteJSON renders the report as indented JSON suitable for CI consumption.
func WriteJSON(w io.Writer, r *analyzer.Report, opts Options) error {
	sum := r.Summarize()
	out := jsonReport{
		SchemaVersion: JSONSchemaVersion,
		Cluster:       r.Cluster,
		Upgrade:       jsonUpgrade{From: r.Upgrade.From.String(), To: r.Upgrade.To.String()},
		Summary: jsonSummary{
			Blocking: sum.Blocking, Concerning: sum.Concerning, Passed: sum.Passed,
			Skipped: sum.Skipped, Errored: sum.Errored, Total: len(r.Findings),
		},
		Verdict:  verdict(sum, r),
		ExitCode: r.ExitCode(),
		Findings: make([]jsonFinding, 0, len(r.Findings)),
		Errors:   r.Errors,
	}

	// Emit findings in worklist order so a consumer reading the array top to
	// bottom gets the same prioritisation the terminal output shows.
	order := map[string]int{}
	n := 0
	for _, g := range r.Worklist() {
		for _, f := range g.Findings {
			n++
			order[f.Check] = n
		}
	}

	for _, f := range r.Findings {
		jf := jsonFinding{
			Check:    f.Check,
			Category: string(f.Category),
			Severity: f.Severity.String(),
			Blocking: f.Blocking(),
			Bucket:   bucketSlug(f.Bucket()),
			Order:    order[f.Check],
			Evidence: f.Evidence,
			Limits:   f.Limits,
			Error:    f.Error,
			Status:   "error",
		}
		if f.Result != nil {
			jf.Status = f.Result.Status.String()
			jf.Message = f.Result.Message
			jf.Remediation = f.Result.Remediation
			jf.Commands = f.Result.Commands
			jf.Docs = f.Result.Docs
			limit := opts.resourceLimit()
			for i, res := range f.Result.Resources {
				if i >= limit {
					jf.ResourcesTruncated = len(f.Result.Resources) - limit
					break
				}
				jf.Resources = append(jf.Resources, jsonResource{
					Kind: res.Kind, APIVersion: res.APIVersion,
					Namespace: res.Namespace, Name: res.Name, Detail: res.Detail,
				})
			}
		}
		out.Findings = append(out.Findings, jf)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("encode json report: %w", err)
	}
	return nil
}

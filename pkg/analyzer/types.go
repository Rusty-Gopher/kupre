// Package analyzer defines the core preflight check model and the engine that
// runs checks against a live cluster. All checks are strictly read-only.
package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Severity expresses how much a failing check should block an upgrade.
type Severity int

const (
	// SeverityInfo is advisory only and never affects the exit code.
	SeverityInfo Severity = iota
	// SeverityWarning indicates the upgrade may have issues.
	SeverityWarning
	// SeverityError indicates the upgrade will break.
	SeverityError
)

// String returns the lowercase name of the severity.
func (s Severity) String() string {
	switch s {
	case SeverityError:
		return "error"
	case SeverityWarning:
		return "warning"
	case SeverityInfo:
		return "info"
	default:
		return "unknown"
	}
}

// Status is the outcome of running a single check.
type Status int

const (
	// StatusPass means the check found no problems.
	StatusPass Status = iota
	// StatusWarn means the check found a non-blocking problem.
	StatusWarn
	// StatusFail means the check found a blocking problem.
	StatusFail
	// StatusSkip means the check did not apply to this cluster.
	StatusSkip
)

// String returns the lowercase name of the status.
func (s Status) String() string {
	switch s {
	case StatusPass:
		return "pass"
	case StatusWarn:
		return "warn"
	case StatusFail:
		return "fail"
	case StatusSkip:
		return "skip"
	default:
		return "unknown"
	}
}

// Category groups related checks in reports and the TUI.
type Category string

// Check categories.
const (
	CategoryAPI      Category = "api"
	CategoryWebhook  Category = "webhook"
	CategoryStorage  Category = "storage"
	CategoryNode     Category = "node"
	CategoryWorkload Category = "workload"
	CategoryCloud    Category = "cloud"
)

// AffectedResource identifies a single cluster object implicated by a finding.
type AffectedResource struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
	// Detail carries check-specific context, e.g. the offending field value.
	Detail string `json:"detail,omitempty"`
}

// String renders the resource as namespace/name (Kind), suitable for reports.
func (r AffectedResource) String() string {
	id := r.Name
	if r.Namespace != "" {
		id = r.Namespace + "/" + r.Name
	}
	if r.Kind != "" {
		id = fmt.Sprintf("%s (%s)", id, r.Kind)
	}
	return id
}

// Result is the outcome of a single check.
type Result struct {
	Status      Status             `json:"status"`
	Message     string             `json:"message"`
	Resources   []AffectedResource `json:"resources,omitempty"`
	Remediation string             `json:"remediation,omitempty"`
	// Commands are copy-pasteable shell commands that resolve or verify the
	// finding. Only populate these when the exact command is known to be
	// correct for this cluster - a confidently wrong command is worse than
	// none, because an operator will run it.
	Commands []string `json:"commands,omitempty"`
	// Docs optionally links to upstream documentation for the finding.
	Docs string `json:"docs,omitempty"`
	// OverrideAction reclassifies this specific outcome when a check's
	// possible results demand different handling - e.g. a webhook that cannot
	// speak v1 at all needs lead time, while one merely listing a stale
	// version alongside v1 is cleanup. Nil inherits the check's Action.
	OverrideAction *Action `json:"-"`
}

// WithAction overrides the worklist action for this specific result.
func (r *Result) WithAction(a Action) *Result {
	r.OverrideAction = &a
	return r
}

// WithCommands attaches copy-pasteable commands to the result and returns it.
func (r *Result) WithCommands(cmds ...string) *Result {
	r.Commands = append(r.Commands, cmds...)
	return r
}

// Pass returns a passing result with the given message.
func Pass(format string, args ...any) *Result {
	return &Result{Status: StatusPass, Message: fmt.Sprintf(format, args...)}
}

// Skip returns a skipped result with the given reason.
func Skip(format string, args ...any) *Result {
	return &Result{Status: StatusSkip, Message: fmt.Sprintf(format, args...)}
}

// Warn returns a warning result with the given message.
func Warn(format string, args ...any) *Result {
	return &Result{Status: StatusWarn, Message: fmt.Sprintf(format, args...)}
}

// Fail returns a failing result with the given message.
func Fail(format string, args ...any) *Result {
	return &Result{Status: StatusFail, Message: fmt.Sprintf(format, args...)}
}

// WithResources attaches affected resources to the result and returns it.
func (r *Result) WithResources(res ...AffectedResource) *Result {
	r.Resources = append(r.Resources, res...)
	return r
}

// WithRemediation attaches remediation guidance to the result and returns it.
func (r *Result) WithRemediation(format string, args ...any) *Result {
	r.Remediation = fmt.Sprintf(format, args...)
	return r
}

// WithDocs attaches a documentation URL to the result and returns it.
func (r *Result) WithDocs(url string) *Result {
	r.Docs = url
	return r
}

// Check is a single preflight check. Run must not mutate cluster state.
type Check struct {
	// Name is a short, stable, human-readable identifier.
	Name string
	// Description explains what the check looks for.
	Description string
	Category    Category
	Severity    Severity
	// Action says what kind of work a failure of this check demands, and
	// therefore where it lands in the worklist.
	Action Action
	// Evidence states precisely what the check inspects. Limits states what
	// cannot be concluded from that evidence.
	//
	// These exist because the failure mode of a preflight tool is not missing a
	// problem - it is asserting more than it measured. A check that inspects
	// node counts must not imply it modelled scheduling. Both fields are
	// surfaced by `kupre checks` and in finding detail, so the operator can see
	// the basis for every claim.
	Evidence string
	Limits   string
	// Run executes the check. It receives the cluster under test and the
	// upgrade being evaluated. Returning an error means the check itself
	// could not run, which is distinct from the check failing.
	Run func(ctx context.Context, c *Cluster, up Upgrade) (*Result, error)
}

// Upgrade describes the version transition being evaluated.
type Upgrade struct {
	// From is the cluster's current server version, e.g. "1.35.3".
	From Version
	// To is the target version, e.g. "1.36.0".
	To Version
}

// Finding pairs a check with its result for reporting.
type Finding struct {
	Check    string   `json:"check"`
	Category Category `json:"category"`
	Severity Severity `json:"severity"`
	Action   Action   `json:"-"`
	// Evidence and Limits are copied from the Check so every reported finding
	// carries the basis for its claim.
	Evidence string  `json:"evidence,omitempty"`
	Limits   string  `json:"limits,omitempty"`
	Result   *Result `json:"result"`
	// Error is set when the check could not be executed at all.
	Error string `json:"error,omitempty"`
	// Suppression is set when a policy waiver or a baseline accepts this
	// finding. An accepted finding stays in the report, in its own section,
	// but no longer drives the verdict or exit code.
	Suppression *Suppression `json:"suppression,omitempty"`
	// PolicyNotes records what policy did to this finding (severity override,
	// expired waiver), so a changed verdict is always explained.
	PolicyNotes []string `json:"policyNotes,omitempty"`
}

// Suppression explains why a finding was accepted.
type Suppression struct {
	// Kind is "waiver" or "baseline".
	Kind    string `json:"kind"`
	Reason  string `json:"reason"`
	Owner   string `json:"owner,omitempty"`
	Expires string `json:"expires,omitempty"`
}

// Accepted reports whether a waiver or baseline accepted a real problem.
//
// Only non-blocking problems can be accepted. A blocker means the operation
// will break; a waiver cannot change that, so an error-severity failure stays
// blocking whatever its Suppression says. Accepting one takes an explicit
// severity override, which is recorded in PolicyNotes.
func (f Finding) Accepted() bool {
	if f.Suppression == nil || f.Error != "" || f.Result == nil {
		return false
	}
	switch f.Result.Status {
	case StatusWarn:
		return true
	case StatusFail:
		return f.Severity != SeverityError
	}
	return false
}

// Blocking reports whether the finding should block an upgrade, i.e. an
// error-severity check that failed.
func (f Finding) Blocking() bool {
	return f.Error == "" && f.Severity == SeverityError && f.Result != nil && f.Result.Status == StatusFail
}

// Concerning reports whether the finding warrants attention but does not block:
// any warn status, or a failure from a non-error-severity check.
func (f Finding) Concerning() bool {
	if f.Error != "" || f.Result == nil || f.Blocking() || f.Accepted() {
		return false
	}
	return f.Result.Status == StatusWarn || f.Result.Status == StatusFail
}

// Report is the full outcome of a preflight run against one cluster.
type Report struct {
	Cluster string `json:"cluster"`
	Context string `json:"context,omitempty"`
	// Mission names the analysis mode that produced this report; renderers use
	// it to pick section vocabulary. Empty means upgrade (pre-mission reports).
	Mission  string    `json:"mission,omitempty"`
	Upgrade  Upgrade   `json:"upgrade"`
	Findings []Finding `json:"findings"`
	// Errors holds tool-level failures such as connectivity problems.
	Errors []string `json:"errors,omitempty"`
}

// Summary counts findings by outcome.
type Summary struct {
	Blocking   int `json:"blocking"`
	Concerning int `json:"concerning"`
	Passed     int `json:"passed"`
	Skipped    int `json:"skipped"`
	Errored    int `json:"errored"`
	Accepted   int `json:"accepted"`
}

// Summarize tallies the report's findings.
func (r *Report) Summarize() Summary {
	var s Summary
	for _, f := range r.Findings {
		switch {
		case f.Error != "":
			s.Errored++
		case f.Accepted():
			s.Accepted++
		case f.Blocking():
			s.Blocking++
		case f.Concerning():
			s.Concerning++
		case f.Result != nil && f.Result.Status == StatusSkip:
			s.Skipped++
		default:
			s.Passed++
		}
	}
	return s
}

// Exit codes returned by the CLI in non-interactive mode.
const (
	// ExitOK means all checks passed.
	ExitOK = 0
	// ExitBlocked means one or more blocking issues were found.
	ExitBlocked = 1
	// ExitWarnings means only non-blocking issues were found.
	ExitWarnings = 2
	// ExitToolError means the tool could not complete the run.
	ExitToolError = 3
)

// ExitCode maps the report to a CI exit code.
func (r *Report) ExitCode() int {
	if len(r.Errors) > 0 {
		return ExitToolError
	}
	s := r.Summarize()
	switch {
	case s.Errored > 0:
		return ExitToolError
	case s.Blocking > 0:
		return ExitBlocked
	case s.Concerning > 0:
		return ExitWarnings
	default:
		return ExitOK
	}
}

// SortFindings orders findings by severity (most severe first), then category,
// then check name, so report output is deterministic.
func SortFindings(fs []Finding) {
	rank := func(f Finding) int {
		switch {
		case f.Error != "":
			return 0
		case f.Blocking():
			return 1
		case f.Concerning():
			return 2
		case f.Result != nil && f.Result.Status == StatusSkip:
			return 4
		default:
			return 3
		}
	}
	sort.SliceStable(fs, func(i, j int) bool {
		if ri, rj := rank(fs[i]), rank(fs[j]); ri != rj {
			return ri < rj
		}
		if fs[i].Category != fs[j].Category {
			return fs[i].Category < fs[j].Category
		}
		return strings.ToLower(fs[i].Check) < strings.ToLower(fs[j].Check)
	})
}

// Action describes what kind of work a finding demands. It is orthogonal to
// Severity: severity says whether a failure stops the upgrade, Action says what
// the operator has to *do* and when.
//
// This is what lets kupre emit a worklist rather than a flat report. A blocking
// finding you can fix with one kubectl command belongs in a different part of
// the plan than a blocking finding that needs a chart upgrade and a test cycle.
type Action int

const (
	// ActionReviewLater is real but will not affect this upgrade.
	ActionReviewLater Action = iota
	// ActionResolveFirst marks pre-existing degradation. Worth clearing before
	// the upgrade so that anything breaking afterwards is attributable to it.
	ActionResolveFirst
	// ActionPlanAhead needs lead time - a component upgrade, a migration, a
	// test cycle. Cannot be done in the maintenance window itself.
	ActionPlanAhead
	// ActionVerifyManually cannot be checked from the Kubernetes API at all.
	// A human has to go and look.
	ActionVerifyManually
	// ActionFixBeforeStart blocks the upgrade but is quick to resolve, so it
	// belongs in the run-up to the window.
	ActionFixBeforeStart
)

// Bucket is a section of the worklist. Buckets are ordered by when the operator
// needs to act, not by severity.
type Bucket int

const (
	// BucketNone is used for passing and skipped findings.
	BucketNone Bucket = iota
	// BucketFixBeforeStart blocks the upgrade and is quick to fix.
	BucketFixBeforeStart
	// BucketPlanAhead needs lead time; start before the window.
	BucketPlanAhead
	// BucketVerifyManually is outside what kupre can check.
	BucketVerifyManually
	// BucketResolveFirst is pre-existing degradation.
	BucketResolveFirst
	// BucketReviewLater will not affect this upgrade.
	BucketReviewLater
	// BucketInconclusive holds checks that could not run.
	BucketInconclusive
	// BucketAccepted holds findings a waiver or baseline accepted.
	BucketAccepted
)

// Title is the worklist heading for the bucket.
func (b Bucket) Title() string {
	switch b {
	case BucketFixBeforeStart:
		return "BLOCKS THE UPGRADE: fix before you start"
	case BucketPlanAhead:
		return "START NOW: these need lead time"
	case BucketVerifyManually:
		return "VERIFY BY HAND: kupre cannot check these"
	case BucketResolveFirst:
		return "RESOLVE FIRST: keep new failures attributable"
	case BucketReviewLater:
		return "NOT BLOCKING THIS UPGRADE"
	case BucketInconclusive:
		return "COULD NOT BE CHECKED"
	case BucketAccepted:
		return "ACCEPTED: waived or in baseline"
	default:
		return ""
	}
}

// worklistOrder is the order buckets appear in a report.
var worklistOrder = []Bucket{
	BucketInconclusive,
	BucketFixBeforeStart,
	BucketPlanAhead,
	BucketVerifyManually,
	BucketResolveFirst,
	BucketReviewLater,
	BucketAccepted,
}

// Bucket places the finding in the worklist.
//
// Any blocking finding lands in one of the first two buckets regardless of its
// declared Action, so "everything that stops the upgrade is in the top two
// sections" holds unconditionally.
func (f Finding) Bucket() Bucket {
	if f.Error != "" {
		return BucketInconclusive
	}
	if f.Result == nil {
		return BucketInconclusive
	}
	if f.Result.Status == StatusPass || f.Result.Status == StatusSkip {
		return BucketNone
	}
	if f.Accepted() {
		return BucketAccepted
	}

	action := f.Action
	if f.Result != nil && f.Result.OverrideAction != nil {
		action = *f.Result.OverrideAction
	}

	if f.Blocking() {
		if action == ActionPlanAhead {
			return BucketPlanAhead
		}
		return BucketFixBeforeStart
	}

	switch action {
	case ActionVerifyManually:
		return BucketVerifyManually
	case ActionPlanAhead:
		return BucketPlanAhead
	case ActionResolveFirst:
		return BucketResolveFirst
	default:
		return BucketReviewLater
	}
}

// Worklist groups a report's findings into buckets, in the order the operator
// should work through them. Empty buckets are omitted.
func (r *Report) Worklist() []BucketGroup {
	byBucket := map[Bucket][]Finding{}
	for _, f := range r.Findings {
		if b := f.Bucket(); b != BucketNone {
			byBucket[b] = append(byBucket[b], f)
		}
	}

	var out []BucketGroup
	for _, b := range worklistOrder {
		if fs := byBucket[b]; len(fs) > 0 {
			out = append(out, BucketGroup{Bucket: b, Findings: fs})
		}
	}
	return out
}

// BucketGroup is one section of the worklist.
type BucketGroup struct {
	Bucket   Bucket
	Findings []Finding
}

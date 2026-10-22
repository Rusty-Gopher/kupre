package report

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
)

// The JSON output, exit codes, statuses, verdicts and bucket slugs are a
// contract with every script and pipeline that consumes kupre. This file pins
// them. If a test here fails, either the change was an accident, or it is a
// breaking change: then bump JSONSchemaVersion and update these lists in the
// same commit. Adding a new field is compatible: add it to the list.

var (
	contractTopLevel = []string{"schemaVersion", "cluster", "upgrade", "summary", "verdict",
		"exitCode", "findings", "errors"}
	contractSummary = []string{"blocking", "warnings", "passed", "skipped", "errored",
		"accepted", "total"}
	contractFinding = []string{"check", "category", "severity", "status", "blocking", "bucket",
		"order", "evidence", "limits", "message", "remediation", "commands", "docs", "resources",
		"resourcesTruncated", "error", "suppression", "policyNotes", "durationMs"}
	contractResource = []string{"kind", "apiVersion", "namespace", "name", "detail"}
)

// jsonFields lists the JSON names a struct type can emit.
func jsonFields(t reflect.Type) []string {
	var out []string
	for i := range t.NumField() {
		tag := t.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name != "" && name != "-" {
			out = append(out, name)
		}
	}
	return out
}

func TestJSONFieldContract(t *testing.T) {
	for _, c := range []struct {
		name string
		typ  reflect.Type
		want []string
	}{
		{"report", reflect.TypeOf(jsonReport{}), contractTopLevel},
		{"summary", reflect.TypeOf(jsonSummary{}), contractSummary},
		{"finding", reflect.TypeOf(jsonFinding{}), contractFinding},
		{"resource", reflect.TypeOf(jsonResource{}), contractResource},
	} {
		got := jsonFields(c.typ)
		for _, f := range c.want {
			if !slices.Contains(got, f) {
				t.Errorf("%s: field %q is gone - that breaks consumers; bump JSONSchemaVersion if intended", c.name, f)
			}
		}
		for _, f := range got {
			if !slices.Contains(c.want, f) {
				t.Errorf("%s: new field %q - compatible, add it to the contract list in this file", c.name, f)
			}
		}
	}
	if JSONSchemaVersion != "1" {
		t.Errorf("schemaVersion changed to %q: update the contract lists for the new version", JSONSchemaVersion)
	}
}

// Exit codes, verdicts, statuses and bucket slugs are documented in the
// README and parsed by the GitHub Action; they must not drift.
func TestEnumContract(t *testing.T) {
	if analyzer.ExitOK != 0 || analyzer.ExitBlocked != 1 || analyzer.ExitWarnings != 2 || analyzer.ExitToolError != 3 {
		t.Error("exit codes changed: 0 ready, 1 blocking, 2 warnings, 3 inconclusive is a public contract")
	}
	statuses := map[analyzer.Status]string{analyzer.StatusPass: "pass", analyzer.StatusWarn: "warn",
		analyzer.StatusFail: "fail", analyzer.StatusSkip: "skip"}
	for s, want := range statuses {
		if s.String() != want {
			t.Errorf("status %d renders %q, contract says %q", s, s.String(), want)
		}
	}
	buckets := map[analyzer.Bucket]string{
		analyzer.BucketFixBeforeStart: "fix-before-start", analyzer.BucketPlanAhead: "plan-ahead",
		analyzer.BucketVerifyManually: "verify-manually", analyzer.BucketResolveFirst: "resolve-first",
		analyzer.BucketReviewLater: "review-later", analyzer.BucketInconclusive: "inconclusive",
		analyzer.BucketAccepted: "accepted",
	}
	for b, want := range buckets {
		if got := bucketSlug(b); got != want {
			t.Errorf("bucket %d slug %q, contract says %q", b, got, want)
		}
	}

	// Verdict strings, as emitted for each kind of report.
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleReport(), Options{}); err != nil {
		t.Fatal(err)
	}
	var out struct{ Verdict string }
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains([]string{"ready", "warnings", "blocked", "inconclusive"}, out.Verdict) {
		t.Errorf("verdict %q is outside the documented set", out.Verdict)
	}
}

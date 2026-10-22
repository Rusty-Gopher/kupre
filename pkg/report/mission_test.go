package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
)

// missionReport builds a report attributed to the given mission with one
// blocking and one lead-time finding, so both retitled buckets render.
func missionReport(mission string) *analyzer.Report {
	return &analyzer.Report{
		Cluster: "prod",
		Mission: mission,
		Upgrade: analyzer.Upgrade{
			From: analyzer.MustParseVersion("1.35.3"),
			To:   analyzer.MustParseVersion("1.35.3"),
		},
		Findings: []analyzer.Finding{
			{
				Check: "pod-failure-causes", Category: analyzer.CategoryWorkload,
				Severity: analyzer.SeverityError, Action: analyzer.ActionFixBeforeStart,
				Result: &analyzer.Result{
					Status: analyzer.StatusFail, Message: "2 pods are unhealthy",
					Remediation: "Fix the causes.",
				},
			},
			{
				Check: "tls-secret-expiry", Category: analyzer.CategoryWorkload,
				Severity: analyzer.SeverityWarning, Action: analyzer.ActionPlanAhead,
				Result: &analyzer.Result{
					Status: analyzer.StatusWarn, Message: "1 certificate expires soon",
					Remediation: "Renew it.",
				},
			},
		},
	}
}

// TestMissionVocabularyInEveryWriter verifies each renderer titles its
// sections in the mission's own vocabulary, not the upgrade wording: a health
// report must not tell the operator something "BLOCKS THE UPGRADE".
func TestMissionVocabularyInEveryWriter(t *testing.T) {
	writers := map[string]func(*bytes.Buffer, *analyzer.Report) error{
		"worklist": func(b *bytes.Buffer, r *analyzer.Report) error {
			return WriteWorklist(b, r, Options{NoColor: true})
		},
		"markdown": func(b *bytes.Buffer, r *analyzer.Report) error {
			return WriteMarkdown(b, r, Options{})
		},
		"html": func(b *bytes.Buffer, r *analyzer.Report) error {
			return WriteHTML(b, r, Options{})
		},
	}

	tests := []struct {
		mission     string
		wantPresent []string
		wantAbsent  []string
	}{
		{
			mission: "health",
			wantPresent: []string{
				"BROKEN: fix now",       // BucketFixBeforeStart, health vocabulary
				"AT RISK: address soon", // BucketPlanAhead, health vocabulary
				"Health check",          // heading names the mission
			},
			wantAbsent: []string{"BLOCKS THE UPGRADE"},
		},
		{
			mission: "certs",
			wantPresent: []string{
				"EXPIRED OR BROKEN: fix now",
				"EXPIRING SOON: renew now",
			},
			wantAbsent: []string{"BLOCKS THE UPGRADE", "START NOW: these need lead time"},
		},
		{
			mission:     "upgrade",
			wantPresent: []string{"BLOCKS THE UPGRADE"},
			wantAbsent:  []string{"BROKEN: fix now"},
		},
	}

	for _, tt := range tests {
		for name, write := range writers {
			t.Run(tt.mission+"/"+name, func(t *testing.T) {
				var buf bytes.Buffer
				if err := write(&buf, missionReport(tt.mission)); err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				out := buf.String()
				for _, want := range tt.wantPresent {
					if !strings.Contains(out, want) {
						t.Errorf("%s output for %s mission missing %q", name, tt.mission, want)
					}
				}
				for _, absent := range tt.wantAbsent {
					if strings.Contains(out, absent) {
						t.Errorf("%s output for %s mission uses the wrong vocabulary %q",
							name, tt.mission, absent)
					}
				}
			})
		}
	}
}

// TestMissionHeadingVersionSpan verifies targetless missions show the single
// analyzed version while the upgrade mission shows the from -> to span.
func TestMissionHeadingVersionSpan(t *testing.T) {
	var health bytes.Buffer
	if err := WriteMarkdown(&health, missionReport("health"), Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(health.String(), "Health check · v1.35.3") {
		t.Errorf("health heading should name the mission and the analyzed version:\n%s", health.String())
	}
	if strings.Contains(health.String(), "→") {
		t.Errorf("health report shows an upgrade span despite having no target:\n%s", health.String())
	}

	up := missionReport("upgrade")
	up.Upgrade.To = analyzer.MustParseVersion("1.36.0")
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, up, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "v1.35.3 → v1.36.0") {
		t.Errorf("upgrade report lost its version span:\n%s", buf.String())
	}
}

// TestWriteBannerRespectsNoColor covers the banner shown before terminal
// reports: it must carry the tagline and honor --no-color.
func TestWriteBannerRespectsNoColor(t *testing.T) {
	var plain bytes.Buffer
	WriteBanner(&plain, Options{NoColor: true})
	if !strings.Contains(plain.String(), "KUBERNETES PREFLIGHT & REVIEW ENGINE") {
		t.Errorf("banner lost its tagline:\n%s", plain.String())
	}
	if strings.Contains(plain.String(), "\033[") {
		t.Error("NoColor banner still contains ANSI escape codes")
	}

	var colored bytes.Buffer
	WriteBanner(&colored, Options{NoColor: false})
	if !strings.Contains(colored.String(), "\033[") {
		t.Error("colored banner has no ANSI codes; color option is ignored")
	}
}

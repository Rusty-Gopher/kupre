package analyzer

import (
	"context"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"
)

func TestVersionSupport(t *testing.T) {
	day := func(s string) time.Time { t, _ := time.Parse(time.DateOnly, s); return t }
	tests := []struct {
		name, today, current, target string
		want                         Status
		msg                          string
	}{
		{"supported", "2026-10-22", "1.36.4", "1.36.4", StatusPass, "until 2027-06-28"},
		{"eol within 90 days", "2027-01-15", "1.35.2", "1.35.2", StatusWarn, "in 44 days"},
		{"eol beyond 90 days passes", "2026-10-22", "1.35.2", "1.35.2", StatusPass, "until 2027-02-28"},
		{"eol in 5 days", "2026-10-22", "1.34.9", "1.34.9", StatusWarn, "in 5 days"},
		{"past eol", "2026-10-22", "1.33.1", "1.33.1", StatusWarn, "reached upstream end of life on 2026-06-28"},
		{"older than data is eol", "2026-10-22", "1.20.0", "1.20.0", StatusWarn, "end of life"},
		{"newer than data skips", "2026-10-22", "1.40.0", "1.40.0", StatusSkip, "no upstream end-of-life date"},
		{"eol target", "2026-10-22", "1.32.0", "1.33.0", StatusWarn, "upgrade target Kubernetes 1.33"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := now
			now = func() time.Time { return day(tt.today) }
			defer func() { now = old }()

			c := NewClusterForTest(fake.NewSimpleClientset(), MustParseVersion(tt.current))
			up := Upgrade{From: MustParseVersion(tt.current), To: MustParseVersion(tt.target)}
			got, err := checkVersionSupport(context.Background(), c, up)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != tt.want || !strings.Contains(got.Message, tt.msg) {
				t.Errorf("got %s %q, want %s containing %q", got.Status, got.Message, tt.want, tt.msg)
			}
		})
	}
}

package analyzer

import (
	"context"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func certManagerDeploy(image string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "cert-manager", Namespace: "cert-manager"},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "controller", Image: image}},
		}}},
	}
}

func TestCertManagerCompat(t *testing.T) {
	old := now
	now = func() time.Time { return time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC) }
	defer func() { now = old }()

	tests := []struct {
		name, image, from, to string
		want                  Status
		msg                   string
	}{
		{"supported", "quay.io/jetstack/cert-manager-controller:v1.21.1", "1.35.0", "1.36.0", StatusPass, "supported on Kubernetes 1.36"},
		{"detail has one v", "quay.io/jetstack/cert-manager-controller:v1.21.1", "1.36.4", "1.37.0", StatusWarn, "not 1.37"},
		{"no release supports 1.37 yet", "quay.io/jetstack/cert-manager-controller:v1.21.1", "1.36.4", "1.37.0", StatusWarn, "not 1.37"},
		{"target outside range", "quay.io/jetstack/cert-manager-controller:v1.20.2", "1.35.0", "1.36.0", StatusWarn, "not 1.36"},
		{"eol release", "quay.io/jetstack/cert-manager-controller:v1.18.0", "1.33.0", "1.33.0", StatusWarn, "end of life on 2026-03-10"},
		{"older than data", "registry.local:5000/cert-manager-controller:v1.8.0", "1.24.0", "1.24.0", StatusWarn, "predates"},
		{"newer than data", "quay.io/jetstack/cert-manager-controller:v1.22.0", "1.36.0", "1.37.0", StatusSkip, "newer than"},
		{"digest only", "quay.io/jetstack/cert-manager-controller@sha256:abc", "1.36.0", "1.37.0", StatusWarn, "carries no version"},
		{"not installed", "nginx:1.27", "1.36.0", "1.37.0", StatusSkip, "not detected"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClusterForTest(fake.NewSimpleClientset(certManagerDeploy(tt.image)), MustParseVersion(tt.from))
			up := Upgrade{From: MustParseVersion(tt.from), To: MustParseVersion(tt.to)}
			got, err := checkCertManagerCompat(context.Background(), c, up)
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != tt.want || !strings.Contains(got.Message, tt.msg) {
				t.Errorf("got %s %q, want %s containing %q", got.Status, got.Message, tt.want, tt.msg)
			}
			if got.Status == StatusWarn && got.Remediation == "" {
				t.Error("warning without remediation")
			}
			for _, r := range got.Resources {
				if strings.Contains(r.Detail, "vv") {
					t.Errorf("detail %q doubles the v", r.Detail)
				}
			}
		})
	}
}

func TestSplitImageTag(t *testing.T) {
	for in, want := range map[string][2]string{
		"quay.io/jetstack/cert-manager-controller:v1.21.1": {"quay.io/jetstack/cert-manager-controller", "v1.21.1"},
		"registry.local:5000/cert-manager-controller":      {"registry.local:5000/cert-manager-controller", ""},
		"cert-manager-controller":                          {"cert-manager-controller", ""},
	} {
		if r, tag := splitImageTag(in); r != want[0] || tag != want[1] {
			t.Errorf("splitImageTag(%q) = %q, %q", in, r, tag)
		}
	}
}

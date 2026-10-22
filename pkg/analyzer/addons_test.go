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

	"github.com/Rusty-Gopher/kupre/pkg/deprecation"
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
		{"supported", "quay.io/jetstack/cert-manager-controller:v1.21.1", "1.35.0", "1.36.0", StatusPass, "supports Kubernetes 1.36"},
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
			got, err := checkAddonCompat(context.Background(), c, up, addon(t, "cert-manager"))
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

func addon(t *testing.T, name string) deprecation.Addon {
	t.Helper()
	for _, a := range deprecation.Addons {
		if a.Name == name {
			return a
		}
	}
	t.Fatalf("no add-on %q", name)
	return deprecation.Addon{}
}

func ciliumDS(image string) *appsv1.DaemonSet {
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium", Namespace: "kube-system"},
		Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "cilium-agent", Image: image}},
		}}},
	}
}

func TestCiliumCompat(t *testing.T) {
	tests := []struct {
		name, image, from, to string
		want                  Status
		msg                   string
	}{
		{"tested", "quay.io/cilium/cilium:v1.20.3@sha256:abcd", "1.35.0", "1.36.0", StatusPass, "is e2e tested against Kubernetes 1.36"},
		{"1.37 untested, wording is the vendor's", "quay.io/cilium/cilium:v1.20.3", "1.36.4", "1.37.0", StatusWarn, "is e2e tested against Kubernetes 1.33 to 1.36, not 1.37"},
		{"unmaintained", "quay.io/cilium/cilium:v1.17.6", "1.31.0", "1.32.0", StatusWarn, "no longer a maintained release"},
		{"envoy image is not the agent", "quay.io/cilium/cilium-envoy:v1.34.0", "1.36.0", "1.37.0", StatusSkip, "not detected"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClusterForTest(fake.NewSimpleClientset(ciliumDS(tt.image)), MustParseVersion(tt.from))
			up := Upgrade{From: MustParseVersion(tt.from), To: MustParseVersion(tt.to)}
			got, err := checkAddonCompat(context.Background(), c, up, addon(t, "Cilium"))
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != tt.want || !strings.Contains(got.Message, tt.msg) {
				t.Errorf("got %s %q, want %s containing %q", got.Status, got.Message, tt.want, tt.msg)
			}
		})
	}
}

// Every add-on's data must be internally consistent: newest first, sane
// ranges, and at least one maintained release.
func TestAddonDataConsistent(t *testing.T) {
	for _, a := range deprecation.Addons {
		maintained := 0
		for i, r := range a.Releases {
			if !r.Covers(r.MinKube) || !r.Covers(r.MaxKube) {
				t.Errorf("%s %s: range %s-%s is inverted", a.Name, r.Minor, r.MinKube, r.MaxKube)
			}
			if i > 0 && MustParseVersion(r.Minor).Compare(MustParseVersion(a.Releases[i-1].Minor)) >= 0 {
				t.Errorf("%s: releases not newest first at %s", a.Name, r.Minor)
			}
			if r.EOL == "" && !r.Unmaintained {
				maintained++
			}
		}
		if maintained == 0 || a.Source == "" || a.Claim == "" {
			t.Errorf("%s: incomplete add-on data", a.Name)
		}
	}
}

func TestCalicoCompat(t *testing.T) {
	tests := []struct {
		name, image, from, to string
		want                  Status
		msg                   string
	}{
		{"3.33 is tested on 1.37", "quay.io/calico/node:v3.33.0", "1.36.4", "1.37.0", StatusPass, "is tested against Kubernetes 1.37"},
		{"3.32 is not", "docker.io/calico/node:v3.32.2", "1.36.4", "1.37.0", StatusWarn, "not 1.37"},
		{"older makes no maintenance claim", "calico/node:v3.29.1", "1.31.0", "1.32.0", StatusWarn, "nothing vouches"},
		{"operator image is not calico", "quay.io/tigera/operator:v1.40.0", "1.36.0", "1.37.0", StatusSkip, "not detected"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClusterForTest(fake.NewSimpleClientset(ciliumDS(tt.image)), MustParseVersion(tt.from))
			up := Upgrade{From: MustParseVersion(tt.from), To: MustParseVersion(tt.to)}
			got, err := checkAddonCompat(context.Background(), c, up, addon(t, "Calico"))
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != tt.want || !strings.Contains(got.Message, tt.msg) {
				t.Errorf("got %s %q, want %s containing %q", got.Status, got.Message, tt.want, tt.msg)
			}
			if strings.Contains(got.Message, "no longer maintained") {
				t.Errorf("Calico publishes no EOL policy, but kupre claimed one: %q", got.Message)
			}
		})
	}
}

package kubeadm

import (
	"context"
	"strings"
	"testing"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func kubeadmConfigCM(clusterConfig string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "kubeadm-config", Namespace: "kube-system"},
		Data:       map[string]string{"ClusterConfiguration": clusterConfig},
	}
}

func cluster(objs ...*corev1.ConfigMap) *analyzer.Cluster {
	cs := fake.NewSimpleClientset()
	for _, o := range objs {
		_, _ = cs.CoreV1().ConfigMaps(o.Namespace).Create(context.Background(), o, metav1.CreateOptions{})
	}
	return analyzer.NewClusterForTest(cs, analyzer.MustParseVersion("1.34.0"))
}

func up() analyzer.Upgrade {
	return analyzer.Upgrade{
		From: analyzer.MustParseVersion("1.34.0"),
		To:   analyzer.MustParseVersion("1.35.0"),
	}
}

func TestDetect(t *testing.T) {
	with := cluster(kubeadmConfigCM("kubernetesVersion: v1.34.0\n"))
	got, err := Provider{}.Detect(context.Background(), with)
	if err != nil || !got {
		t.Errorf("Detect(kubeadm cluster) = %v, %v; want true", got, err)
	}

	without := cluster()
	got, err = Provider{}.Detect(context.Background(), without)
	if err != nil || got {
		t.Errorf("Detect(managed cluster) = %v, %v; want false", got, err)
	}
}

func TestRemovedFeatureGates(t *testing.T) {
	tests := []struct {
		name       string
		config     string
		wantStatus analyzer.Status
		wantDetail string
	}{
		{
			name:       "clean config passes",
			config:     "kubernetesVersion: v1.34.0\nfeatureGates:\n  SomeCurrentGate: true\n",
			wantStatus: analyzer.StatusPass,
		},
		{
			name:       "removed gate in featureGates fails",
			config:     "kubernetesVersion: v1.34.0\nfeatureGates:\n  ComponentSLIs: true\n",
			wantStatus: analyzer.StatusFail,
			wantDetail: "ComponentSLIs",
		},
		{
			// v1beta3 map shape.
			name: "removed gate in v1beta3 extraArgs fails",
			config: "kubernetesVersion: v1.34.0\napiServer:\n  extraArgs:\n" +
				"    feature-gates: \"SizeMemoryBackedVolumes=true,Other=false\"\n",
			wantStatus: analyzer.StatusFail,
			wantDetail: "SizeMemoryBackedVolumes",
		},
		{
			// v1beta4 list shape.
			name: "removed gate in v1beta4 extraArgs fails",
			config: "kubernetesVersion: v1.34.0\napiServer:\n  extraArgs:\n" +
				"    - name: feature-gates\n      value: \"ComponentSLIs=true\"\n",
			wantStatus: analyzer.StatusFail,
			wantDetail: "ComponentSLIs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cluster(kubeadmConfigCM(tt.config))
			got, err := checkRemovedFeatureGates(context.Background(), c, up())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Status != tt.wantStatus {
				t.Fatalf("status = %v, want %v: %s", got.Status, tt.wantStatus, got.Message)
			}
			if tt.wantDetail != "" {
				found := false
				for _, r := range got.Resources {
					if strings.Contains(r.Detail, tt.wantDetail) {
						found = true
					}
				}
				if !found {
					t.Errorf("no resource names %q: %+v", tt.wantDetail, got.Resources)
				}
			}
		})
	}
}

func TestPinnedComponentVersions(t *testing.T) {
	c := cluster(kubeadmConfigCM(
		"kubernetesVersion: v1.34.0\ndns:\n  imageTag: v1.11.1\netcd:\n  local:\n    imageTag: 3.5.9-0\n"))
	got, err := checkPinnedComponentVersions(context.Background(), c, up())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Status != analyzer.StatusWarn {
		t.Fatalf("status = %v, want Warn for stale pins: %s", got.Status, got.Message)
	}
	if len(got.Resources) != 2 {
		t.Errorf("resources = %d, want 2 (CoreDNS pin + etcd pin)", len(got.Resources))
	}
}

func TestNonKubeadmClusterSkips(t *testing.T) {
	c := cluster()
	got, err := checkRemovedFeatureGates(context.Background(), c, up())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Status != analyzer.StatusSkip {
		t.Errorf("status = %v, want Skip on a managed cluster", got.Status)
	}
}

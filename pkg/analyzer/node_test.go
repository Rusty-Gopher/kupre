package analyzer

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// node builds a Node with the given kubelet version and readiness.
func node(name, kubeletVersion string, ready bool) *corev1.Node {
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{
			NodeInfo:   corev1.NodeSystemInfo{KubeletVersion: kubeletVersion},
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: status}},
		},
	}
}

func TestCheckKubeletSkew(t *testing.T) {
	tests := []struct {
		name       string
		kubelets   []string
		target     string
		wantStatus Status
		wantCount  int
	}{
		{
			name:     "matching version passes",
			kubelets: []string{"v1.35.3", "v1.35.3"}, target: "1.36.0",
			wantStatus: StatusPass,
		},
		{
			name: "three minors behind is the supported limit",
			// Kubernetes supports kubelet up to three minor versions older than
			// the API server, so 1.33 against a 1.36 target is still legal.
			kubelets: []string{"v1.33.0"}, target: "1.36.0",
			wantStatus: StatusPass,
		},
		{
			name:     "four minors behind fails",
			kubelets: []string{"v1.32.0"}, target: "1.36.0",
			wantStatus: StatusFail, wantCount: 1,
		},
		{
			name:     "kubelet newer than control plane fails",
			kubelets: []string{"v1.37.0"}, target: "1.36.0",
			wantStatus: StatusFail, wantCount: 1,
		},
		{
			name:     "unparseable version fails",
			kubelets: []string{"unknown"}, target: "1.36.0",
			wantStatus: StatusFail, wantCount: 1,
		},
		{
			name:     "only offending nodes are reported",
			kubelets: []string{"v1.35.0", "v1.30.0", "v1.35.1"}, target: "1.36.0",
			wantStatus: StatusFail, wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objs []any
			for i, kv := range tt.kubelets {
				objs = append(objs, node("n"+string(rune('a'+i)), kv, true))
			}
			c := newTestCluster(objs...)
			up := Upgrade{From: MustParseVersion("1.35.3"), To: MustParseVersion(tt.target)}

			got, err := checkKubeletSkew(context.Background(), c, up)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Status != tt.wantStatus {
				t.Errorf("status = %v, want %v (message: %s)", got.Status, tt.wantStatus, got.Message)
			}
			if len(got.Resources) != tt.wantCount {
				t.Errorf("resources = %d, want %d", len(got.Resources), tt.wantCount)
			}
		})
	}
}

func TestCheckNodesReady(t *testing.T) {
	tests := []struct {
		name       string
		nodes      []*corev1.Node
		wantStatus Status
		wantCount  int
	}{
		{
			name:       "all ready passes",
			nodes:      []*corev1.Node{node("a", "v1.35.3", true), node("b", "v1.35.3", true)},
			wantStatus: StatusPass,
		},
		{
			name:       "not ready fails",
			nodes:      []*corev1.Node{node("a", "v1.35.3", false)},
			wantStatus: StatusFail, wantCount: 1,
		},
		{
			name: "cordoned node fails",
			nodes: []*corev1.Node{func() *corev1.Node {
				n := node("a", "v1.35.3", true)
				n.Spec.Unschedulable = true
				return n
			}()},
			wantStatus: StatusFail, wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := make([]any, 0, len(tt.nodes))
			for _, n := range tt.nodes {
				objs = append(objs, n)
			}
			c := newTestCluster(objs...)

			got, err := checkNodesReady(context.Background(), c, testUpgrade())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Status != tt.wantStatus {
				t.Errorf("status = %v, want %v", got.Status, tt.wantStatus)
			}
			if len(got.Resources) != tt.wantCount {
				t.Errorf("resources = %d, want %d", len(got.Resources), tt.wantCount)
			}
		})
	}
}

func TestCheckNodesReadyErrorsOnEmptyCluster(t *testing.T) {
	// A cluster reporting zero nodes means the scan is not seeing what it should.
	// That is a tool error, not a passing check.
	c := newTestCluster()
	if _, err := checkNodesReady(context.Background(), c, testUpgrade()); err == nil {
		t.Fatal("expected an error for a cluster with no nodes, got nil")
	}
}

func TestRuntimeConcern(t *testing.T) {
	tests := []struct {
		name    string
		runtime string
		wantHit bool
	}{
		{name: "modern containerd is fine", runtime: "containerd://1.7.29", wantHit: false},
		{name: "containerd 2.x is fine", runtime: "containerd://2.0.1", wantHit: false},
		{name: "ancient containerd flagged", runtime: "containerd://1.4.9", wantHit: true},
		{name: "docker flagged", runtime: "docker://20.10.7", wantHit: true},
		{name: "cri-o not flagged", runtime: "cri-o://1.30.2", wantHit: false},
		{name: "malformed flagged", runtime: "weird", wantHit: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runtimeConcern(tt.runtime)
			if (got != "") != tt.wantHit {
				t.Errorf("runtimeConcern(%q) = %q, wantHit %v", tt.runtime, got, tt.wantHit)
			}
		})
	}
}

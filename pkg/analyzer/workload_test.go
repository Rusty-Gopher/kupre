package analyzer

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
)

// pdb builds a PodDisruptionBudget with the given status for testing.
func pdb(name string, minAvailable int, expected, healthy, allowed int32) *policyv1.PodDisruptionBudget {
	ma := intstr.FromInt32(int32(minAvailable))
	return &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec:       policyv1.PodDisruptionBudgetSpec{MinAvailable: &ma},
		Status: policyv1.PodDisruptionBudgetStatus{
			ObservedGeneration: 1,
			ExpectedPods:       expected,
			CurrentHealthy:     healthy,
			DesiredHealthy:     int32(minAvailable),
			DisruptionsAllowed: allowed,
		},
	}
}

func TestCheckPDBBlocksDrain(t *testing.T) {
	tests := []struct {
		name       string
		pdbs       []*policyv1.PodDisruptionBudget
		wantStatus Status
		wantCount  int
	}{
		{
			name:       "no pdbs skips",
			pdbs:       nil,
			wantStatus: StatusSkip,
		},
		{
			name:       "healthy pdb passes",
			pdbs:       []*policyv1.PodDisruptionBudget{pdb("ok", 1, 3, 3, 2)},
			wantStatus: StatusPass,
		},
		{
			name:       "zero disruptions blocks",
			pdbs:       []*policyv1.PodDisruptionBudget{pdb("blocked", 1, 1, 1, 0)},
			wantStatus: StatusFail,
			wantCount:  1,
		},
		{
			name: "only the blocking pdb is reported",
			pdbs: []*policyv1.PodDisruptionBudget{
				pdb("ok", 1, 3, 3, 2),
				pdb("blocked", 2, 2, 2, 0),
			},
			wantStatus: StatusFail,
			wantCount:  1,
		},
		{
			name: "pdb matching no pods cannot block a drain",
			// ExpectedPods=0 means the selector matches nothing, so no eviction
			// can ever be rejected. This must not be reported as a blocker.
			pdbs:       []*policyv1.PodDisruptionBudget{pdb("stale", 1, 0, 0, 0)},
			wantStatus: StatusPass,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := make([]any, 0, len(tt.pdbs))
			for _, p := range tt.pdbs {
				objs = append(objs, p)
			}
			c := newTestCluster(objs...)

			got, err := checkPDBBlocksDrain(context.Background(), c, testUpgrade())
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

func TestCheckSingleReplica(t *testing.T) {
	one, three := int32(1), int32(3)

	tests := []struct {
		name       string
		replicas   []*int32
		wantStatus Status
		wantCount  int
	}{
		{name: "all multi-replica passes", replicas: []*int32{&three, &three}, wantStatus: StatusPass},
		{name: "single replica warns", replicas: []*int32{&one}, wantStatus: StatusWarn, wantCount: 1},
		{name: "mixed reports only singles", replicas: []*int32{&one, &three, &one}, wantStatus: StatusWarn, wantCount: 2},
		{name: "nil replicas ignored", replicas: []*int32{nil}, wantStatus: StatusPass},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objs []any
			for i, r := range tt.replicas {
				objs = append(objs, newDeployment("d"+string(rune('a'+i)), r))
			}
			c := newTestCluster(objs...)

			got, err := checkSingleReplica(context.Background(), c, testUpgrade())
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

func TestUnhealthyReason(t *testing.T) {
	tests := []struct {
		name string
		pod  corev1.Pod
		want string
	}{
		{
			name: "running and ready is healthy",
			pod: corev1.Pod{Status: corev1.PodStatus{
				Phase:      corev1.PodRunning,
				Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			}},
			want: "",
		},
		{
			name: "succeeded job pod is healthy",
			pod:  corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodSucceeded}},
			want: "",
		},
		{
			name: "failed phase",
			pod:  corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodFailed}},
			want: "phase=Failed",
		},
		{
			name: "waiting container surfaces its reason",
			pod: corev1.Pod{Status: corev1.PodStatus{
				Phase: corev1.PodPending,
				ContainerStatuses: []corev1.ContainerStatus{{
					Name:  "app",
					State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
				}},
			}},
			want: "container app: CrashLoopBackOff",
		},
		{
			name: "ContainerCreating is transient, not a finding",
			pod: corev1.Pod{Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				ContainerStatuses: []corev1.ContainerStatus{{
					Name:  "app",
					State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}},
				}},
				Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			}},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unhealthyReason(tt.pod); got != tt.want {
				t.Errorf("unhealthyReason() = %q, want %q", got, tt.want)
			}
		})
	}
}

// newTestCluster builds a Cluster backed by a fake clientset seeded with objs.
func newTestCluster(objs ...any) *Cluster {
	converted := make([]runtime.Object, 0, len(objs))
	for _, o := range objs {
		converted = append(converted, o.(runtime.Object))
	}
	return NewClusterForTest(fake.NewSimpleClientset(converted...), MustParseVersion("1.35.3"))
}

// newDeployment builds a Deployment with the given replica count.
func newDeployment(name string, replicas *int32) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec:       appsv1.DeploymentSpec{Replicas: replicas},
	}
}

func testUpgrade() Upgrade {
	return Upgrade{From: MustParseVersion("1.35.3"), To: MustParseVersion("1.36.0")}
}

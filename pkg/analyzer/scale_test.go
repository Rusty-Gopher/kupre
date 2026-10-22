package analyzer

import (
	"context"
	"fmt"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
)

// largeCluster builds a synthetic cluster: nodes, namespaces, and per
// namespace a set of deployments, each with pods, a service and a PDB.
func largeCluster(nodes, namespaces, deploysPerNS, podsPerDeploy int) []runtime.Object {
	var objs []runtime.Object
	for i := range nodes {
		objs = append(objs, &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("node-%d", i)},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
				NodeInfo:   corev1.NodeSystemInfo{KubeletVersion: "v1.36.4", ContainerRuntimeVersion: "containerd://2.1.0"},
			},
		})
	}
	one := int32(1)
	for n := range namespaces {
		ns := fmt.Sprintf("team-%d", n)
		objs = append(objs, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
		for d := range deploysPerNS {
			app := fmt.Sprintf("app-%d", d)
			labels := map[string]string{"app": app}
			replicas := int32(podsPerDeploy)
			objs = append(objs,
				&appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{Name: app, Namespace: ns},
					Spec: appsv1.DeploymentSpec{
						Replicas: &replicas,
						Selector: &metav1.LabelSelector{MatchLabels: labels},
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{Labels: labels},
							Spec: corev1.PodSpec{Containers: []corev1.Container{{
								Name: "app", Image: "registry.example/app:1.0",
							}}},
						},
					},
					Status: appsv1.DeploymentStatus{Replicas: replicas, ReadyReplicas: replicas, AvailableReplicas: replicas},
				},
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{Name: app, Namespace: ns},
					Spec:       corev1.ServiceSpec{Selector: labels},
				},
				&policyv1.PodDisruptionBudget{
					ObjectMeta: metav1.ObjectMeta{Name: app, Namespace: ns},
					Spec: policyv1.PodDisruptionBudgetSpec{
						MinAvailable: &intstr.IntOrString{IntVal: one},
						Selector:     &metav1.LabelSelector{MatchLabels: labels},
					},
					Status: policyv1.PodDisruptionBudgetStatus{CurrentHealthy: replicas, DesiredHealthy: 1, DisruptionsAllowed: replicas - 1, ExpectedPods: replicas},
				},
			)
			for p := range podsPerDeploy {
				objs = append(objs, &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s-%d", app, p), Namespace: ns, Labels: labels},
					Spec:       corev1.PodSpec{NodeName: fmt.Sprintf("node-%d", p%nodes)},
					Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{
						Type: corev1.PodReady, Status: corev1.ConditionTrue,
					}}},
				})
			}
		}
	}
	return objs
}

// TestUpgradeScanScales guards against quadratic checks: every mission over a
// large synthetic cluster must finish well inside the CLI's default 2m
// timeout. Measured 2026-10-22: linear, ~0.3s at 81,500 objects; on a real
// cluster, API list latency dominates.
// 200 nodes, 100 namespaces x 20 deployments x 5 pods = 10,000 pods.
func TestUpgradeScanScales(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test")
	}
	objs := largeCluster(200, 100, 20, 5)
	up := Upgrade{From: MustParseVersion("1.36.4"), To: MustParseVersion("1.37.0")}

	for _, m := range Missions() {
		t.Run(m.Name, func(t *testing.T) {
			// A fresh Cluster per mission: memoized lists must not hide cost.
			c := NewClusterForTest(fake.NewSimpleClientset(objs...), MustParseVersion("1.36.4"))
			scanWithin(t, c, up, m.Checks(), len(objs))
		})
	}
}

func scanWithin(t *testing.T, c *Cluster, up Upgrade, checks []Check, objects int) {
	t.Helper()
	start := time.Now()
	rep := NewEngine(checks...).Run(context.Background(), c, up)
	elapsed := time.Since(start)

	if len(rep.Errors) > 0 {
		t.Fatalf("scan errors: %v", rep.Errors)
	}
	var slowest Finding
	for _, f := range rep.Findings {
		if f.Duration > slowest.Duration {
			slowest = f
		}
	}
	t.Logf("%d objects, %d checks, %s total; slowest %s %s", objects, len(rep.Findings),
		elapsed.Round(time.Millisecond), slowest.Check, slowest.Duration.Round(time.Millisecond))
	if elapsed > 20*time.Second {
		t.Errorf("scan took %s; something scales badly (slowest: %s)", elapsed, slowest.Check)
	}
}

package analyzer

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// TestHealthChecksAgainstFixtures drives the health mission's own checks
// against the testdata manifests, following the TestChecksAgainstFixtures
// pattern: each fixture documents the exact cluster state the check exists to
// catch, plus a healthy counterpart that must stay quiet.
func TestHealthChecksAgainstFixtures(t *testing.T) {
	tests := []struct {
		name       string
		fixtures   []string
		run        func(context.Context, *Cluster, Upgrade) (*Result, error)
		wantStatus Status
		wantCount  int
	}{
		{
			name:     "broken pod is caught with a cause",
			fixtures: []string{"failing_pod.yaml", "failing_pod_event.yaml"},
			run:      checkPodFailureCauses, wantStatus: StatusFail, wantCount: 1,
		},
		{
			name:     "healthy pod produces no failure causes",
			fixtures: []string{"healthy_pod.yaml"},
			run:      checkPodFailureCauses, wantStatus: StatusPass,
		},
		{
			name:     "unschedulable pod is caught with the scheduler's reason",
			fixtures: []string{"pending_pod_unschedulable.yaml"},
			run:      checkPendingPodsExplained, wantStatus: StatusFail, wantCount: 1,
		},
		{
			name:     "running pods are not called unschedulable",
			fixtures: []string{"healthy_pod.yaml"},
			run:      checkPendingPodsExplained, wantStatus: StatusPass,
		},
		{
			name:     "OOM-killed container is caught even on a Ready pod",
			fixtures: []string{"oom_pod.yaml"},
			run:      checkOOMKilled, wantStatus: StatusWarn, wantCount: 1,
		},
		{
			name:     "clean restart history passes",
			fixtures: []string{"healthy_pod.yaml"},
			run:      checkOOMKilled, wantStatus: StatusPass,
		},
		{
			name:     "OOM history alone does not make the pod a failure cause",
			fixtures: []string{"oom_pod.yaml"},
			run:      checkPodFailureCauses, wantStatus: StatusPass,
		},
		{
			name:     "stuck rollout is caught",
			fixtures: []string{"stuck_deployment.yaml"},
			run:      checkRolloutsStuck, wantStatus: StatusWarn, wantCount: 1,
		},
		{
			name:     "deployment at desired state passes",
			fixtures: []string{"healthy_deployment.yaml"},
			run:      checkRolloutsStuck, wantStatus: StatusPass,
		},
		{
			name:     "one stuck rollout among healthy ones is still caught",
			fixtures: []string{"healthy_deployment.yaml", "stuck_deployment.yaml"},
			run:      checkRolloutsStuck, wantStatus: StatusWarn, wantCount: 1,
		},
		{
			name:     "container without requests is caught",
			fixtures: []string{"no_requests_deployment.yaml"},
			run:      checkMissingRequests, wantStatus: StatusWarn, wantCount: 1,
		},
		{
			name:     "container with requests passes",
			fixtures: []string{"healthy_deployment.yaml"},
			run:      checkMissingRequests, wantStatus: StatusPass,
		},
		{
			name:     "requestless deployment at desired state is not a stuck rollout",
			fixtures: []string{"no_requests_deployment.yaml"},
			run:      checkRolloutsStuck, wantStatus: StatusPass,
		},
		{
			name:     "failed Job is caught",
			fixtures: []string{"failed_job.yaml"},
			run:      checkFailedJobs, wantStatus: StatusWarn, wantCount: 1,
		},
		{
			name:     "succeeded Job passes",
			fixtures: []string{"succeeded_job.yaml"},
			run:      checkFailedJobs, wantStatus: StatusPass,
		},
		{
			name:     "no Jobs at all is a skip, not a pass",
			fixtures: nil,
			run:      checkFailedJobs, wantStatus: StatusSkip,
		},
	}

	up := Upgrade{From: MustParseVersion("1.35.3"), To: MustParseVersion("1.35.3")}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := clusterFromFixtures(t, tt.fixtures...)

			got, err := tt.run(context.Background(), c, up)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Status != tt.wantStatus {
				t.Errorf("status = %v, want %v (message: %s)", got.Status, tt.wantStatus, got.Message)
			}
			if tt.wantCount > 0 && len(got.Resources) != tt.wantCount {
				t.Errorf("resources = %d, want %d", len(got.Resources), tt.wantCount)
			}
		})
	}
}

// TestPodFailureCauseUsesTheClustersOwnWords verifies the events join: the
// kubelet's warning event is the reported cause when present, and the
// container wait reason is the fallback when the event has expired.
func TestPodFailureCauseUsesTheClustersOwnWords(t *testing.T) {
	up := Upgrade{From: MustParseVersion("1.35.3"), To: MustParseVersion("1.35.3")}

	t.Run("event message wins", func(t *testing.T) {
		c := clusterFromFixtures(t, "failing_pod.yaml", "failing_pod_event.yaml")
		got, err := checkPodFailureCauses(context.Background(), c, up)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got.Resources) != 1 {
			t.Fatalf("resources = %d, want 1", len(got.Resources))
		}
		if detail := got.Resources[0].Detail; !strings.Contains(detail, `secret "web-credentials" not found`) {
			t.Errorf("cause %q does not carry the event's message", detail)
		}
	})

	t.Run("container state is the fallback once events expire", func(t *testing.T) {
		c := clusterFromFixtures(t, "failing_pod.yaml")
		got, err := checkPodFailureCauses(context.Background(), c, up)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got.Resources) != 1 {
			t.Fatalf("resources = %d, want 1", len(got.Resources))
		}
		if detail := got.Resources[0].Detail; !strings.Contains(detail, "CreateContainerConfigError") {
			t.Errorf("cause %q does not fall back to the container wait reason", detail)
		}
	})
}

// nodeMetricsGVR is the metrics-server node metrics resource.
var nodeMetricsGVR = schema.GroupVersionResource{
	Group: "metrics.k8s.io", Version: "v1beta1", Resource: "nodes",
}

// metricsCluster builds a cluster with one 4-CPU/8Gi node and a metrics API
// reporting the given live usage for it.
func metricsCluster(t *testing.T, usageCPU, usageMem string) *Cluster {
	t.Helper()

	n := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
		Status: corev1.NodeStatus{
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("4"),
				corev1.ResourceMemory: resource.MustParse("8Gi"),
			},
		},
	}
	cs := fake.NewSimpleClientset(n)
	cs.Resources = append(fakeAPIResources(), &metav1.APIResourceList{
		GroupVersion: "metrics.k8s.io/v1beta1",
		APIResources: []metav1.APIResource{{Name: "nodes", Kind: "NodeMetrics"}},
	})
	c := NewClusterForTest(cs, MustParseVersion("1.35.3"))

	m := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "metrics.k8s.io/v1beta1",
		"kind":       "NodeMetrics",
		"metadata":   map[string]any{"name": "worker-1"},
		"usage":      map[string]any{"cpu": usageCPU, "memory": usageMem},
	}}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{nodeMetricsGVR: "NodeMetricsList"})
	// Register under the real GVR: the tracker's kind-to-resource guess would
	// file NodeMetrics under "nodemetricses", which nothing ever lists.
	if err := dyn.Tracker().Create(nodeMetricsGVR, m, ""); err != nil {
		t.Fatalf("seed node metrics: %v", err)
	}
	c.dynamic = dyn
	return c
}

func TestNodeUtilization(t *testing.T) {
	up := Upgrade{From: MustParseVersion("1.35.3"), To: MustParseVersion("1.35.3")}

	t.Run("no metrics API is a skip, never a pass", func(t *testing.T) {
		c := clusterFromFixtures(t) // discovery has no metrics.k8s.io group
		got, err := checkNodeUtilization(context.Background(), c, up)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Status != StatusSkip {
			t.Errorf("status = %v, want Skip - without metrics the check knows nothing: %s",
				got.Status, got.Message)
		}
	})

	t.Run("hot node warns", func(t *testing.T) {
		// 3800m of 4 CPU (95%) and 7400Mi of 8Gi (~90%) - both over threshold.
		c := metricsCluster(t, "3800m", "7400Mi")
		got, err := checkNodeUtilization(context.Background(), c, up)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Status != StatusWarn {
			t.Fatalf("status = %v, want Warn: %s", got.Status, got.Message)
		}
		if len(got.Resources) != 1 || got.Resources[0].Name != "worker-1" {
			t.Errorf("resources = %+v, want the hot node", got.Resources)
		}
	})

	t.Run("cool node passes", func(t *testing.T) {
		c := metricsCluster(t, "500m", "1Gi")
		got, err := checkNodeUtilization(context.Background(), c, up)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Status != StatusPass {
			t.Errorf("status = %v, want Pass: %s", got.Status, got.Message)
		}
	})
}

// tlsSecret wraps PEM bytes in a kubernetes.io/tls Secret. Certificates are
// generated at run time because expiry is relative to the wall clock; a static
// fixture would change meaning as it aged.
func tlsSecret(name string, crt []byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "shop"},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": crt},
	}
}

func TestTLSSecretExpiry(t *testing.T) {
	up := testUpgrade()

	tests := []struct {
		name       string
		secrets    []runtime.Object
		wantStatus Status
	}{
		{
			name:       "healthy certificate passes",
			secrets:    []runtime.Object{tlsSecret("web-tls", testCertPEM(t, time.Now().Add(365*24*time.Hour)))},
			wantStatus: StatusPass,
		},
		{
			name:       "certificate inside the warning window warns",
			secrets:    []runtime.Object{tlsSecret("web-tls", testCertPEM(t, time.Now().Add(10*24*time.Hour)))},
			wantStatus: StatusWarn,
		},
		{
			name:       "expired certificate fails",
			secrets:    []runtime.Object{tlsSecret("web-tls", testCertPEM(t, time.Now().Add(-24*time.Hour)))},
			wantStatus: StatusFail,
		},
		{
			name:       "unparseable tls.crt is a failure, not a skip",
			secrets:    []runtime.Object{tlsSecret("mangled", []byte("not a certificate"))},
			wantStatus: StatusFail,
		},
		{
			name: "one expired certificate among healthy ones still fails",
			secrets: []runtime.Object{
				tlsSecret("good-tls", testCertPEM(t, time.Now().Add(365*24*time.Hour))),
				tlsSecret("dead-tls", testCertPEM(t, time.Now().Add(-24*time.Hour))),
			},
			wantStatus: StatusFail,
		},
		{
			name:       "no TLS secrets is a skip, not a pass",
			secrets:    nil,
			wantStatus: StatusSkip,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClusterForTest(fake.NewSimpleClientset(tt.secrets...), MustParseVersion("1.35.3"))
			got, err := checkTLSSecretExpiry(context.Background(), c, up)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Status != tt.wantStatus {
				t.Errorf("status = %v, want %v: %s", got.Status, tt.wantStatus, got.Message)
			}
		})
	}

	t.Run("expired secret is named in the finding", func(t *testing.T) {
		cs := fake.NewSimpleClientset(
			tlsSecret("good-tls", testCertPEM(t, time.Now().Add(365*24*time.Hour))),
			tlsSecret("dead-tls", testCertPEM(t, time.Now().Add(-24*time.Hour))),
		)
		c := NewClusterForTest(cs, MustParseVersion("1.35.3"))
		got, err := checkTLSSecretExpiry(context.Background(), c, up)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got.Resources) != 1 || got.Resources[0].Name != "dead-tls" {
			t.Errorf("resources = %+v, want exactly the expired secret", got.Resources)
		}
	})

	t.Run("forbidden secret list is a skip, not a pass", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		forbid(cs, "secrets")
		c := NewClusterForTest(cs, MustParseVersion("1.35.3"))
		got, err := checkTLSSecretExpiry(context.Background(), c, up)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Status != StatusSkip {
			t.Errorf("status = %v, want Skip - unreadable secrets are unknown, not clean: %s",
				got.Status, got.Message)
		}
	})
}

// certManagerCluster builds a cluster that serves the cert-manager Certificate
// API and returns the given Certificate objects from it.
func certManagerCluster(t *testing.T, certs ...*unstructured.Unstructured) *Cluster {
	t.Helper()

	cs := fake.NewSimpleClientset()
	cs.Resources = append(fakeAPIResources(), &metav1.APIResourceList{
		GroupVersion: "cert-manager.io/v1",
		APIResources: []metav1.APIResource{{Name: "certificates", Namespaced: true, Kind: "Certificate"}},
	})
	c := NewClusterForTest(cs, MustParseVersion("1.35.3"))

	objs := make([]runtime.Object, 0, len(certs))
	for _, crt := range certs {
		objs = append(objs, crt)
	}
	c.dynamic = dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{certManagerCertGVR: "CertificateList"}, objs...)
	return c
}

// cmCertificate builds a cert-manager Certificate with the given Ready status.
func cmCertificate(name, readyStatus, message string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cert-manager.io/v1",
		"kind":       "Certificate",
		"metadata":   map[string]any{"name": name, "namespace": "shop"},
		"status": map[string]any{
			"conditions": []any{map[string]any{
				"type": "Ready", "status": readyStatus, "message": message,
			}},
		},
	}}
}

func TestCertManagerCertificates(t *testing.T) {
	up := testUpgrade()

	t.Run("not installed is a skip", func(t *testing.T) {
		c := clusterFromFixtures(t) // discovery has no cert-manager.io group
		got, err := checkCertManagerCertificates(context.Background(), c, up)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Status != StatusSkip {
			t.Errorf("status = %v, want Skip: %s", got.Status, got.Message)
		}
	})

	t.Run("failing certificate warns with cert-manager's message", func(t *testing.T) {
		c := certManagerCluster(t,
			cmCertificate("web-tls", "False", "ACME DNS-01 challenge failed"),
			cmCertificate("ok-tls", "True", ""),
		)
		got, err := checkCertManagerCertificates(context.Background(), c, up)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Status != StatusWarn {
			t.Fatalf("status = %v, want Warn: %s", got.Status, got.Message)
		}
		if len(got.Resources) != 1 || got.Resources[0].Name != "web-tls" {
			t.Fatalf("resources = %+v, want exactly the failing Certificate", got.Resources)
		}
		if !strings.Contains(got.Resources[0].Detail, "ACME DNS-01") {
			t.Errorf("detail %q lost cert-manager's own message", got.Resources[0].Detail)
		}
	})

	t.Run("all certificates ready passes", func(t *testing.T) {
		c := certManagerCluster(t, cmCertificate("web-tls", "True", ""))
		got, err := checkCertManagerCertificates(context.Background(), c, up)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Status != StatusPass {
			t.Errorf("status = %v, want Pass: %s", got.Status, got.Message)
		}
	})

	t.Run("installed with zero certificates is a skip", func(t *testing.T) {
		c := certManagerCluster(t)
		got, err := checkCertManagerCertificates(context.Background(), c, up)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Status != StatusSkip {
			t.Errorf("status = %v, want Skip: %s", got.Status, got.Message)
		}
	})

	t.Run("forbidden certificate list is a skip, not a pass", func(t *testing.T) {
		c := certManagerCluster(t)
		c.dynamic.(*dynamicfake.FakeDynamicClient).PrependReactor("list", "certificates",
			func(ktesting.Action) (bool, runtime.Object, error) {
				return true, nil, apierrors.NewForbidden(
					schema.GroupResource{Group: "cert-manager.io", Resource: "certificates"},
					"", errors.New("denied"))
			})
		got, err := checkCertManagerCertificates(context.Background(), c, up)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Status != StatusSkip {
			t.Errorf("status = %v, want Skip: %s", got.Status, got.Message)
		}
	})
}

// healthOnlyChecks are the checks that exist only in the health mission.
var healthOnlyChecks = []string{
	"pod-failure-causes", "pending-pods-explained", "oom-killed-containers",
	"rollouts-stuck", "node-utilization", "missing-resource-requests", "failed-jobs",
}

// certsOnlyChecks are the checks that exist only in the certificate audit.
var certsOnlyChecks = []string{"tls-secret-expiry", "certmanager-certificates"}

// healthReusedChecks mirrors the reused map in HealthChecks. Because reuse is
// by name lookup over AllChecks, a renamed or removed upgrade check would
// silently vanish from the health mission; this list makes that loud.
var healthReusedChecks = []string{
	"node-ready", "node-pressure", "mixed-container-runtimes",
	"schedulable-node-count", "pdb-unhealthy", "unhealthy-pvs",
	"apiservice-availability", "webhook-backend-fragility",
	"trust-bundle-expiry", "apiserver-cert-expiry", "ingress-nginx-retired",
}

// checkNames returns the check names of a suite, failing on duplicates.
func checkNames(t *testing.T, suite []Check) map[string]bool {
	t.Helper()
	names := make(map[string]bool, len(suite))
	for _, c := range suite {
		if names[c.Name] {
			t.Errorf("check %q appears twice in the suite", c.Name)
		}
		names[c.Name] = true
	}
	return names
}

// TestMissionCheckSelection pins which checks each mission runs: health-only
// and certs-only checks must not leak into the upgrade preflight, and every
// reused upgrade check must actually make it into the health suite.
func TestMissionCheckSelection(t *testing.T) {
	upgrade := checkNames(t, AllChecks())
	health := checkNames(t, HealthChecks())
	certs := checkNames(t, CertAuditChecks())

	for _, name := range healthOnlyChecks {
		if !health[name] {
			t.Errorf("health mission lost its own check %q", name)
		}
		if upgrade[name] {
			t.Errorf("health-only check %q runs in the upgrade preflight", name)
		}
		if certs[name] {
			t.Errorf("health-only check %q runs in the certificate audit", name)
		}
	}

	for _, name := range certsOnlyChecks {
		if !certs[name] {
			t.Errorf("certificate audit lost its own check %q", name)
		}
		if upgrade[name] {
			t.Errorf("certs-only check %q runs in the upgrade preflight", name)
		}
		if health[name] {
			t.Errorf("certs-only check %q runs in the health mission", name)
		}
	}

	// The reused map selects by name from AllChecks: a name that no longer
	// exists there disappears from health without any error.
	for _, name := range healthReusedChecks {
		if !upgrade[name] {
			t.Errorf("reused check %q no longer exists in AllChecks; the health mission silently lost it", name)
		}
		if !health[name] {
			t.Errorf("reused check %q did not make it into the health mission", name)
		}
	}
	if want := len(healthOnlyChecks) + len(healthReusedChecks); len(health) != want {
		t.Errorf("health mission runs %d checks, want %d (own + reused); update healthReusedChecks if the reuse set changed",
			len(health), want)
	}

	// The certificate audit is exactly the shared cert checks plus its own two.
	wantCerts := map[string]bool{
		"trust-bundle-expiry": true, "apiserver-cert-expiry": true,
		"tls-secret-expiry": true, "certmanager-certificates": true,
	}
	for name := range wantCerts {
		if !certs[name] {
			t.Errorf("certificate audit is missing %q", name)
		}
	}
	for name := range certs {
		if !wantCerts[name] {
			t.Errorf("certificate audit unexpectedly runs %q", name)
		}
	}
}

// TestMissionRoster pins the mission list itself: names, order, and which
// missions require a target version.
func TestMissionRoster(t *testing.T) {
	ms := Missions()
	if len(ms) != 3 {
		t.Fatalf("Missions() = %d entries, want 3", len(ms))
	}
	wantOrder := []string{"upgrade", "health", "certs"}
	for i, want := range wantOrder {
		if ms[i].Name != want {
			t.Errorf("Missions()[%d] = %q, want %q", i, ms[i].Name, want)
		}
		if len(ms[i].Checks()) == 0 {
			t.Errorf("mission %q has no checks", ms[i].Name)
		}
	}

	needsTarget := map[string]bool{"upgrade": true, "health": false, "certs": false}
	for _, m := range ms {
		if m.NeedsTarget != needsTarget[m.Name] {
			t.Errorf("mission %q NeedsTarget = %v, want %v", m.Name, m.NeedsTarget, needsTarget[m.Name])
		}
	}

	if _, ok := MissionByName("health"); !ok {
		t.Error("MissionByName(health) not found")
	}
	if _, ok := MissionByName("frobnicate"); ok {
		t.Error("MissionByName accepted an unknown mission name")
	}
}

// TestMissionProviderCheckFilter pins which provider checks join each mission:
// upgrade takes everything, health takes only current-state checks, and the
// certificate audit takes none.
func TestMissionProviderCheckFilter(t *testing.T) {
	upgrade, _ := MissionByName("upgrade")
	health, _ := MissionByName("health")
	certs, _ := MissionByName("certs")

	for _, name := range []string{"openstack-cinder-inline-ephemeral", "kubeadm-config", "anything-at-all"} {
		if !upgrade.ProviderChecks(name) {
			t.Errorf("upgrade mission rejected provider check %q; it must accept all", name)
		}
	}

	healthAccepts := []string{
		"openstack-cinder-csi-health", "openstack-loadbalancer-health",
		"openstack-node-provider-id", "capi-machines-consistent",
	}
	for _, name := range healthAccepts {
		if !health.ProviderChecks(name) {
			t.Errorf("health mission rejected %q, an accepted current-state check", name)
		}
	}
	for _, name := range []string{"openstack-cinder-inline-ephemeral", "openstack-cinder-csi-version"} {
		if health.ProviderChecks(name) {
			t.Errorf("health mission accepted %q, an upgrade-readiness check", name)
		}
	}

	// cmd/kupre registers provider checks only when ProviderChecks is non-nil;
	// nil is how the certificate audit opts out entirely.
	if certs.ProviderChecks != nil {
		t.Error("certs mission has a ProviderChecks filter; expected nil (no provider checks)")
	}
}

// TestBucketTitleFor covers the per-mission worklist vocabulary and its
// fallbacks.
func TestBucketTitleFor(t *testing.T) {
	tests := []struct {
		name    string
		bucket  Bucket
		mission string
		want    string
	}{
		{name: "health overrides the blocking title", bucket: BucketFixBeforeStart,
			mission: "health", want: "BROKEN: fix now"},
		{name: "certs overrides the lead-time title", bucket: BucketPlanAhead,
			mission: "certs", want: "EXPIRING SOON: renew now"},
		{name: "empty mission falls back to upgrade titles", bucket: BucketFixBeforeStart,
			mission: "", want: BucketFixBeforeStart.Title()},
		{name: "unknown mission falls back to upgrade titles", bucket: BucketPlanAhead,
			mission: "frobnicate", want: BucketPlanAhead.Title()},
		{name: "bucket missing from a mission's map falls back", bucket: BucketInconclusive,
			mission: "certs", want: BucketInconclusive.Title()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.bucket.TitleFor(tt.mission); got != tt.want {
				t.Errorf("TitleFor(%q) = %q, want %q", tt.mission, got, tt.want)
			}
		})
	}
}

// TestHealthMissionEndToEnd runs the full health suite against a cluster
// assembled from the health fixtures and confirms the mission produces a
// blocking verdict from its own checks, without any upgrade- or certs-only
// findings appearing.
func TestHealthMissionEndToEnd(t *testing.T) {
	c := clusterFromFixtures(t,
		"failing_pod.yaml", "failing_pod_event.yaml", "pending_pod_unschedulable.yaml",
		"oom_pod.yaml", "stuck_deployment.yaml", "failed_job.yaml",
	)
	// The reused node checks error on a nodeless cluster; give it one healthy node.
	seedHealthyNode(t, c)

	up := Upgrade{From: c.ServerVersion, To: c.ServerVersion}
	rep := NewEngine(HealthChecks()...).Run(context.Background(), c, up)

	byCheck := map[string]Finding{}
	for _, f := range rep.Findings {
		byCheck[f.Check] = f
	}

	for _, name := range []string{"pod-failure-causes", "pending-pods-explained"} {
		f, ok := byCheck[name]
		if !ok {
			t.Fatalf("health report has no %s finding", name)
		}
		if f.Error != "" {
			t.Fatalf("%s errored: %s", name, f.Error)
		}
		if f.Result.Status != StatusFail {
			t.Errorf("%s = %v, want Fail: %s", name, f.Result.Status, f.Result.Message)
		}
	}
	for _, name := range []string{"oom-killed-containers", "rollouts-stuck", "failed-jobs"} {
		f, ok := byCheck[name]
		if !ok {
			t.Fatalf("health report has no %s finding", name)
		}
		if f.Error != "" {
			t.Fatalf("%s errored: %s", name, f.Error)
		}
		if f.Result.Status != StatusWarn {
			t.Errorf("%s = %v, want Warn: %s", name, f.Result.Status, f.Result.Message)
		}
	}

	for _, name := range append([]string{"pdb-blocks-drain", "api-removals-on-path"}, certsOnlyChecks...) {
		if _, ok := byCheck[name]; ok {
			t.Errorf("check %q ran in the health mission; it belongs to another mission", name)
		}
	}

	if got := rep.ExitCode(); got != ExitBlocked {
		t.Errorf("ExitCode() = %d, want %d (broken pods block the health verdict); summary %+v",
			got, ExitBlocked, rep.Summarize())
	}
}

// TestCertsMissionEndToEnd runs the certificate audit against a cluster whose
// only problem is an expired TLS secret.
func TestCertsMissionEndToEnd(t *testing.T) {
	cs := fake.NewSimpleClientset(tlsSecret("dead-tls", testCertPEM(t, time.Now().Add(-time.Hour))))
	cs.Resources = fakeAPIResources()
	c := NewClusterForTest(cs, MustParseVersion("1.35.3"))

	up := Upgrade{From: c.ServerVersion, To: c.ServerVersion}
	rep := NewEngine(CertAuditChecks()...).Run(context.Background(), c, up)

	if len(rep.Findings) != len(CertAuditChecks()) {
		t.Fatalf("findings = %d, want %d", len(rep.Findings), len(CertAuditChecks()))
	}
	var tlsFinding *Finding
	for i := range rep.Findings {
		if rep.Findings[i].Check == "tls-secret-expiry" {
			tlsFinding = &rep.Findings[i]
		}
	}
	if tlsFinding == nil {
		t.Fatal("certs report has no tls-secret-expiry finding")
	}
	if tlsFinding.Error != "" || tlsFinding.Result.Status != StatusFail {
		t.Fatalf("tls-secret-expiry did not fail on an expired secret: %+v", tlsFinding)
	}
	if !tlsFinding.Blocking() {
		t.Error("an expired TLS certificate should be a blocking finding")
	}
	if got := rep.ExitCode(); got != ExitBlocked {
		t.Errorf("ExitCode() = %d, want %d; summary %+v", got, ExitBlocked, rep.Summarize())
	}
}

// seedHealthyNode adds one Ready, schedulable node matching the cluster
// version, so node-family checks have something real to verify.
func seedHealthyNode(t *testing.T, c *Cluster) {
	t.Helper()
	n := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-ok"},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
			NodeInfo: corev1.NodeSystemInfo{
				KubeletVersion:          "v" + c.ServerVersion.String(),
				ContainerRuntimeVersion: "containerd://1.7.29",
			},
		},
	}
	if _, err := c.clientset.CoreV1().Nodes().Create(context.Background(), n, metav1.CreateOptions{}); err != nil {
		t.Fatalf("seed node: %v", err)
	}
}

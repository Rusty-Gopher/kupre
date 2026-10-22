package analyzer

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ktesting "k8s.io/client-go/testing"

	"k8s.io/client-go/kubernetes/fake"
)

// forbid installs a reactor that answers every list of the given resource with
// an RBAC denial, simulating a restricted service account.
func forbid(cs *fake.Clientset, resource string) {
	cs.PrependReactor("list", resource, func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(
			schema.GroupResource{Resource: resource}, "", nil)
	})
}

// TestForbiddenIsNeverAPass is the mechanical form of the README claim that
// "could not check" is never reported as a pass. Each case denies the read a
// check depends on and asserts the result is Skip or a warning that says the
// data is unknown, never StatusPass.
func TestForbiddenIsNeverAPass(t *testing.T) {
	up := testUpgrade()

	t.Run("tls-secret-expiry without secrets access skips", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		forbid(cs, "secrets")
		c := NewClusterForTest(cs, MustParseVersion("1.35.3"))

		got, err := checkTLSSecretExpiry(context.Background(), c, up)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Status != StatusSkip {
			t.Errorf("status = %v, want Skip: %s", got.Status, got.Message)
		}
		if !strings.Contains(strings.ToLower(got.Message), "permission") {
			t.Errorf("skip should name the missing permission: %s", got.Message)
		}
	})

	t.Run("helm scan without secrets access skips", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		forbid(cs, "secrets")
		c := NewClusterForTest(cs, MustParseVersion("1.35.3"))

		got, err := checkHelmReleaseRemovedAPIs(context.Background(), c, up)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Status != StatusSkip {
			t.Errorf("status = %v, want Skip: %s", got.Status, got.Message)
		}
	})

	t.Run("ingress-nginx scan without ingressclasses access skips", func(t *testing.T) {
		cs := fake.NewSimpleClientset()
		forbid(cs, "ingressclasses")
		c := NewClusterForTest(cs, MustParseVersion("1.35.3"))

		got, err := checkIngressNginxRetired(context.Background(), c, up)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Status != StatusSkip {
			t.Errorf("status = %v, want Skip - an unreadable list is not an absent controller: %s",
				got.Status, got.Message)
		}
		if !strings.Contains(strings.ToLower(got.Message), "permission") {
			t.Errorf("skip should name the missing permission: %s", got.Message)
		}
	})

	t.Run("forbidden ingress lists do not hide a labelled controller pod", func(t *testing.T) {
		pod := &corev1.Pod{}
		pod.Name, pod.Namespace = "ingress-nginx-controller", "ingress-nginx"
		pod.Labels = map[string]string{"app.kubernetes.io/name": "ingress-nginx"}
		cs := fake.NewSimpleClientset(pod)
		forbid(cs, "ingressclasses")
		forbid(cs, "ingresses")
		c := NewClusterForTest(cs, MustParseVersion("1.35.3"))

		got, err := checkIngressNginxRetired(context.Background(), c, up)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Status != StatusWarn {
			t.Errorf("status = %v, want Warn on pod evidence alone: %s", got.Status, got.Message)
		}
	})

	t.Run("non-RBAC secret errors stay tool errors", func(t *testing.T) {
		// A network failure must not be soft-pedaled into a permission skip:
		// skip means "known limitation", an error means "scan is incomplete".
		cs := fake.NewSimpleClientset()
		cs.PrependReactor("list", "secrets", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewServiceUnavailable("etcd timeout")
		})
		c := NewClusterForTest(cs, MustParseVersion("1.35.3"))

		if _, err := checkTLSSecretExpiry(context.Background(), c, up); err == nil {
			t.Error("tls-secret-expiry swallowed a non-RBAC failure")
		}
		if _, err := checkHelmReleaseRemovedAPIs(context.Background(), c, up); err == nil {
			t.Error("helm scan swallowed a non-RBAC failure")
		}
	})

	t.Run("forbidden events degrade pod causes, not the verdict", func(t *testing.T) {
		pod := &corev1.Pod{}
		pod.Name, pod.Namespace = "broken", "default"
		pod.Status.Phase = corev1.PodFailed
		cs := fake.NewSimpleClientset(pod)
		forbid(cs, "events")
		c := NewClusterForTest(cs, MustParseVersion("1.35.3"))

		got, err := checkPodFailureCauses(context.Background(), c, up)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// The finding must survive on container-state evidence alone.
		if got.Status != StatusFail {
			t.Errorf("status = %v, want Fail even without event access: %s", got.Status, got.Message)
		}
	})
}

// TestDiscoveryFailureSurfacesInServes proves a group that failed discovery is
// reported as an error by Serves, not as "not served" - the distinction that
// keeps a blind scan from producing a clean verdict.
func TestDiscoveryFailureSurfacesInServes(t *testing.T) {
	c := clusterFromFixtures(t)
	// Seed the memoized snapshot directly (same-package test seam): one healthy
	// group plus one that failed discovery.
	c.cache["servedresources"] = &memoEntry[servedResourceSnapshot]{
		val: servedResourceSnapshot{
			resources: map[string][]metav1.APIResource{
				"apps/v1": {{Name: "deployments"}},
			},
			failures: map[string]error{
				"metrics.k8s.io/v1beta1": apierrors.NewServiceUnavailable("aggregated API down"),
			},
		},
	}

	_, err := c.Serves(context.Background(), schema.GroupVersionResource{
		Group: "metrics.k8s.io", Version: "v1beta1", Resource: "nodes",
	})
	if err == nil {
		t.Fatal("Serves treated a failed discovery group as absent instead of erroring")
	}

	ok, err := c.Serves(context.Background(), schema.GroupVersionResource{
		Group: "apps", Version: "v1", Resource: "deployments",
	})
	if err != nil || !ok {
		t.Errorf("healthy group misreported: ok=%v err=%v", ok, err)
	}

	// And the public failure list names the group.
	failures, err := c.DiscoveryFailures(context.Background())
	if err != nil || len(failures) != 1 || failures[0] != "metrics.k8s.io/v1beta1" {
		t.Errorf("DiscoveryFailures = %v, %v; want the one failed group", failures, err)
	}
}

package analyzer

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
)

// cronJobGVR is a removed API (batch/v1beta1, gone in 1.25) with objects that
// are still readable through the old endpoint after conversion.
var cronJobGVR = schema.GroupVersionResource{
	Group: "batch", Version: "v1beta1", Resource: "cronjobs",
}

// clusterServingRemovedAPI builds a cluster that serves batch/v1beta1 cronjobs
// and returns the given objects through that endpoint.
func clusterServingRemovedAPI(objs ...*unstructured.Unstructured) *Cluster {
	cs := fake.NewSimpleClientset()
	cs.Resources = []*metav1.APIResourceList{{
		GroupVersion: "batch/v1beta1",
		APIResources: []metav1.APIResource{
			{Name: "cronjobs", Namespaced: true, Kind: "CronJob"},
		},
	}}

	runtimeObjs := make([]runtime.Object, 0, len(objs))
	for _, o := range objs {
		runtimeObjs = append(runtimeObjs, o)
	}
	// A fresh scheme, not the clientset's: the typed scheme does not know
	// batch/v1beta1 CronJob as an unstructured kind, and the fake silently
	// returns nothing rather than erroring when it cannot map the GVR.
	sch := runtime.NewScheme()
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		sch,
		map[schema.GroupVersionResource]string{cronJobGVR: "CronJobList"},
		runtimeObjs...,
	)

	c := NewClusterForTest(cs, MustParseVersion("1.24.0"))
	c.dynamic = dyn
	return c
}

// cronJob builds an unstructured CronJob, optionally carrying a
// last-applied-configuration recording the apiVersion it was written with.
func cronJob(name, lastAppliedAPIVersion string) *unstructured.Unstructured {
	o := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "batch/v1beta1",
		"kind":       "CronJob",
		"metadata": map[string]any{
			"name":      name,
			"namespace": "default",
		},
	}}
	if lastAppliedAPIVersion != "" {
		o.SetAnnotations(map[string]string{
			lastAppliedAnnotation: `{"apiVersion":"` + lastAppliedAPIVersion +
				`","kind":"CronJob","metadata":{"name":"` + name + `"}}`,
		})
	}
	return o
}

// TestConvertedObjectsAreNotCalledDeprecatedUsage is the regression guard for
// the tool's most dangerous overclaim.
//
// The API server converts objects to whichever version the client asks for, so
// listing through a deprecated endpoint returns objects that were authored under
// the *current* version too. An earlier version of this check reported every
// such object as "using a removed API version", which is simply false.
func TestConvertedObjectsAreNotCalledDeprecatedUsage(t *testing.T) {
	up := Upgrade{From: MustParseVersion("1.24.0"), To: MustParseVersion("1.25.0")}

	t.Run("object applied as the modern version is not reported at all", func(t *testing.T) {
		c := clusterServingRemovedAPI(cronJob("modern", "batch/v1"))

		got, err := checkRemovedAPIObjects(context.Background(), c, up)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Status != StatusPass {
			t.Errorf("status = %v, want Pass - this object was applied as batch/v1 and only "+
				"appears via the old endpoint because the API server converted it. Message: %s",
				got.Status, got.Message)
		}
	})

	t.Run("object with no annotation is unknown, not confirmed usage", func(t *testing.T) {
		c := clusterServingRemovedAPI(cronJob("helm-managed", ""))

		got, err := checkRemovedAPIObjects(context.Background(), c, up)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Status == StatusFail {
			t.Errorf("status = Fail, but authorship is unknowable for this object - "+
				"Helm and server-side apply do not write last-applied. Message: %s", got.Message)
		}
		if !strings.Contains(strings.ToLower(got.Message), "unknown") {
			t.Errorf("message should say authorship is unknown, got: %s", got.Message)
		}
	})

	t.Run("object applied as the removed version is confirmed", func(t *testing.T) {
		c := clusterServingRemovedAPI(cronJob("legacy", "batch/v1beta1"))

		got, err := checkRemovedAPIObjects(context.Background(), c, up)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Status != StatusFail {
			t.Errorf("status = %v, want Fail - last-applied names the removed version, "+
				"which is real evidence. Message: %s", got.Status, got.Message)
		}
	})

	t.Run("mixed cluster separates confirmed from unknown", func(t *testing.T) {
		c := clusterServingRemovedAPI(
			cronJob("legacy", "batch/v1beta1"),
			cronJob("modern", "batch/v1"),
			cronJob("helm-managed", ""),
		)

		got, err := checkRemovedAPIObjects(context.Background(), c, up)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// One confirmed plus one unknown; the batch/v1 object must not appear.
		if len(got.Resources) != 2 {
			t.Fatalf("reported %d resources, want 2 (confirmed + unknown, not the batch/v1 one)",
				len(got.Resources))
		}
		for _, r := range got.Resources {
			if r.Name == "modern" {
				t.Error("an object applied as batch/v1 was reported as deprecated usage")
			}
		}
	})
}

// TestServedAPIIsNotTreatedAsAFailure guards the other overclaim: a cluster on
// the source version is *expected* to serve what the target removes. Treating
// that as an error would fail every legitimate upgrade crossing a removal.
func TestServedAPIIsNotTreatedAsAFailure(t *testing.T) {
	c := clusterServingRemovedAPI()
	up := Upgrade{From: MustParseVersion("1.24.0"), To: MustParseVersion("1.25.0")}

	got, err := checkAPIRemovalsOnPath(context.Background(), c, up)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Status == StatusFail {
		t.Errorf("serving batch/v1beta1 on a 1.24 cluster is normal, not a failure: %s", got.Message)
	}
	if got.Status != StatusWarn {
		t.Errorf("status = %v, want Warn (an availability change worth surfacing)", got.Status)
	}
	if !strings.Contains(got.Remediation, "kubent") && !strings.Contains(got.Remediation, "Pluto") {
		t.Error("remediation should point at tools that can establish actual usage")
	}
}

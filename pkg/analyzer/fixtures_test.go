package analyzer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Rusty-Gopher/kupre/pkg/deprecation"

	apiextfake "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
	ktesting "k8s.io/client-go/testing"
)

type partialDiscovery struct {
	discovery.DiscoveryInterface
	resources []*metav1.APIResourceList
	err       error
}

func (d partialDiscovery) ServerGroupsAndResources() ([]*metav1.APIGroup, []*metav1.APIResourceList, error) {
	return nil, d.resources, d.err
}

// loadFixture decodes a YAML manifest from testdata into a typed object.
func loadFixture(t *testing.T, name string) runtime.Object {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	obj, _, err := scheme.Codecs.UniversalDeserializer().Decode(data, nil, nil)
	if err != nil {
		t.Fatalf("decode fixture %s: %v", name, err)
	}
	return obj
}

// clusterFromFixtures builds a Cluster seeded with the named testdata manifests.
func clusterFromFixtures(t *testing.T, names ...string) *Cluster {
	t.Helper()

	objs := make([]runtime.Object, 0, len(names))
	for _, n := range names {
		objs = append(objs, loadFixture(t, n))
	}

	cs := fake.NewSimpleClientset(objs...)
	// Seed discovery. Without it the fake server advertises no API resources at
	// all, which checkAPIRemovalsOnPath correctly treats as a failed scan rather
	// than a clean cluster.
	cs.Resources = fakeAPIResources()
	return NewClusterForTest(cs, MustParseVersion("1.35.3"))
}

// fakeAPIResources describes a modern 1.35 API surface for the fake discovery
// client: the groups a current cluster serves, with no removed versions.
func fakeAPIResources() []*metav1.APIResourceList {
	return []*metav1.APIResourceList{
		{GroupVersion: "v1", APIResources: []metav1.APIResource{
			{Name: "pods", Namespaced: true, Kind: "Pod"},
			{Name: "services", Namespaced: true, Kind: "Service"},
			{Name: "nodes", Kind: "Node"},
			{Name: "persistentvolumes", Kind: "PersistentVolume"},
			{Name: "endpoints", Namespaced: true, Kind: "Endpoints"},
		}},
		{GroupVersion: "apps/v1", APIResources: []metav1.APIResource{
			{Name: "deployments", Namespaced: true, Kind: "Deployment"},
			{Name: "daemonsets", Namespaced: true, Kind: "DaemonSet"},
			{Name: "statefulsets", Namespaced: true, Kind: "StatefulSet"},
		}},
		{GroupVersion: "policy/v1", APIResources: []metav1.APIResource{
			{Name: "poddisruptionbudgets", Namespaced: true, Kind: "PodDisruptionBudget"},
		}},
		{GroupVersion: "storage.k8s.io/v1", APIResources: []metav1.APIResource{
			{Name: "storageclasses", Kind: "StorageClass"},
			{Name: "csidrivers", Kind: "CSIDriver"},
		}},
		{GroupVersion: "admissionregistration.k8s.io/v1", APIResources: []metav1.APIResource{
			{Name: "validatingwebhookconfigurations", Kind: "ValidatingWebhookConfiguration"},
			{Name: "mutatingwebhookconfigurations", Kind: "MutatingWebhookConfiguration"},
		}},
		{GroupVersion: "flowcontrol.apiserver.k8s.io/v1", APIResources: []metav1.APIResource{
			{Name: "flowschemas", Kind: "FlowSchema"},
			{Name: "prioritylevelconfigurations", Kind: "PriorityLevelConfiguration"},
		}},
	}
}

// TestDiscoveryFailureIsAnError confirms that a cluster whose discovery returns
// nothing is reported as a failed scan. Treating a blind scan as "no removed
// APIs found" would be the most dangerous possible false negative.
func TestDiscoveryFailureIsAnError(t *testing.T) {
	c := NewClusterForTest(fake.NewSimpleClientset(), MustParseVersion("1.35.3"))
	up := Upgrade{From: MustParseVersion("1.24.0"), To: MustParseVersion("1.25.0")}

	if _, err := checkAPIRemovalsOnPath(context.Background(), c, up); err == nil {
		t.Fatal("expected an error when discovery returns nothing, got nil")
	}
}

func TestPartialDiscoveryFailureIsTargeted(t *testing.T) {
	c := clusterFromFixtures(t)
	c.discovery = partialDiscovery{
		DiscoveryInterface: c.discovery,
		resources:          fakeAPIResources(),
		err: &discovery.ErrGroupDiscoveryFailed{Groups: map[schema.GroupVersion]error{
			{Group: "policy", Version: "v1beta1"}: errors.New("aggregated discovery failed"),
		}},
	}

	apps := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	if ok, err := c.Serves(context.Background(), apps); err != nil || !ok {
		t.Fatalf("unrelated successful discovery was lost: serves=%v err=%v", ok, err)
	}

	up := Upgrade{From: MustParseVersion("1.24.0"), To: MustParseVersion("1.25.0")}
	if _, err := checkAPIRemovalsOnPath(context.Background(), c, up); err == nil {
		t.Fatal("scheduled API in a failed discovery group produced no error")
	}
}

func TestForbiddenRemovedAPIListNeverPasses(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.Resources = append(fakeAPIResources(), &metav1.APIResourceList{
		GroupVersion: "policy/v1beta1",
		APIResources: []metav1.APIResource{{
			Name: "poddisruptionbudgets", Namespaced: true, Kind: "PodDisruptionBudget",
		}},
	})
	c := NewClusterForTest(cs, MustParseVersion("1.24.0"))
	pdbGVR := schema.GroupVersionResource{
		Group: "policy", Version: "v1beta1", Resource: "poddisruptionbudgets",
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(), map[schema.GroupVersionResource]string{
			pdbGVR: "PodDisruptionBudgetList",
		})
	dyn.PrependReactor("list", "poddisruptionbudgets", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(
			schema.GroupResource{Group: "policy", Resource: "poddisruptionbudgets"},
			"", errors.New("denied"))
	})
	c.dynamic = dyn

	up := Upgrade{From: MustParseVersion("1.24.0"), To: MustParseVersion("1.25.0")}
	got, err := checkRemovedAPIObjects(context.Background(), c, up)
	if err != nil {
		t.Fatalf("unexpected check error: %v", err)
	}
	if got.Status != StatusSkip {
		t.Fatalf("forbidden list status = %s, want skip; message: %s", got.Status, got.Message)
	}
}

func TestForbiddenCRDListReturnsError(t *testing.T) {
	c := clusterFromFixtures(t)
	ext := apiextfake.NewSimpleClientset()
	ext.PrependReactor("list", "customresourcedefinitions", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(
			schema.GroupResource{Group: "apiextensions.k8s.io", Resource: "customresourcedefinitions"},
			"", errors.New("denied"))
	})
	c.apiext = ext

	if _, err := c.CustomResourceDefinitions(context.Background()); err == nil {
		t.Fatal("forbidden CRD list returned no error")
	}
}

// TestChecksAgainstFixtures runs individual checks against the manifests in
// testdata/, which document the exact cluster states each check exists to catch.
func TestChecksAgainstFixtures(t *testing.T) {
	tests := []struct {
		name       string
		fixtures   []string
		run        func(context.Context, *Cluster, Upgrade) (*Result, error)
		wantStatus Status
		wantCount  int
	}{
		{
			name:     "blocking PDB is caught",
			fixtures: []string{"blocking_pdb.yaml"},
			run:      checkPDBBlocksDrain, wantStatus: StatusFail, wantCount: 1,
		},
		{
			name:     "healthy PDB passes",
			fixtures: []string{"healthy_pdb.yaml"},
			run:      checkPDBBlocksDrain, wantStatus: StatusPass,
		},
		{
			name:     "one blocking PDB among healthy ones is still caught",
			fixtures: []string{"healthy_pdb.yaml", "blocking_pdb.yaml"},
			run:      checkPDBBlocksDrain, wantStatus: StatusFail, wantCount: 1,
		},
		{
			name:     "gitRepo volume is caught",
			fixtures: []string{"gitrepo_pod.yaml"},
			run:      checkGitRepoVolumes, wantStatus: StatusFail, wantCount: 1,
		},
		{
			name:     "in-tree cinder StorageClass is caught",
			fixtures: []string{"intree_cinder_storageclass.yaml"},
			run:      checkInTreeProvisioners, wantStatus: StatusFail, wantCount: 1,
		},
		{
			name:     "CSI StorageClass passes",
			fixtures: []string{"csi_cinder_storageclass.yaml"},
			run:      checkInTreeProvisioners, wantStatus: StatusPass,
		},
		{
			name:     "default StorageClass is detected",
			fixtures: []string{"csi_cinder_storageclass.yaml"},
			run:      checkDefaultStorageClass, wantStatus: StatusPass,
		},
		{
			name:     "StorageClass with no default warns",
			fixtures: []string{"intree_cinder_storageclass.yaml"},
			run:      checkDefaultStorageClass, wantStatus: StatusWarn,
		},
		{
			name:     "webhook without v1 support is caught",
			fixtures: []string{"webhook_no_v1.yaml"},
			run:      checkWebhookAdmissionVersions, wantStatus: StatusFail, wantCount: 1,
		},
		{
			name:     "fail-closed webhook is flagged",
			fixtures: []string{"webhook_no_v1.yaml"},
			run:      checkWebhookFailurePolicy, wantStatus: StatusWarn, wantCount: 1,
		},
		{
			name:     "stale kubelet is caught",
			fixtures: []string{"stale_kubelet_node.yaml"},
			run:      checkKubeletSkew, wantStatus: StatusFail, wantCount: 1,
		},
		{
			name: "retired ingress-nginx is caught with full blast radius",
			fixtures: []string{
				"ingress_nginx_pod.yaml", "ingress_nginx_class.yaml",
				"ingress_nginx_ingress.yaml", "ingress_nginx_annotated_ingress.yaml",
			},
			run: checkIngressNginxRetired, wantStatus: StatusWarn, wantCount: 4,
		},
		{
			name:     "ingress-nginx IngressClass alone is caught",
			fixtures: []string{"ingress_nginx_class.yaml"},
			run:      checkIngressNginxRetired, wantStatus: StatusWarn, wantCount: 1,
		},
		{
			name:     "deprecated nginx ingress.class annotation alone is caught",
			fixtures: []string{"ingress_nginx_annotated_ingress.yaml"},
			run:      checkIngressNginxRetired, wantStatus: StatusWarn, wantCount: 1,
		},
		{
			name:     "unrelated ingress controller does not fire ingress-nginx-retired",
			fixtures: []string{"traefik_ingressclass.yaml", "traefik_pod.yaml"},
			run:      checkIngressNginxRetired, wantStatus: StatusPass,
		},
	}

	up := Upgrade{From: MustParseVersion("1.35.3"), To: MustParseVersion("1.36.0")}

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

// TestFindingsCarryRemediation verifies that every failing or warning result
// tells the operator what to do about it. A finding without remediation is not
// actionable, which defeats the purpose of a preflight tool.
func TestFindingsCarryRemediation(t *testing.T) {
	fixtures := []string{
		"blocking_pdb.yaml", "gitrepo_pod.yaml", "intree_cinder_storageclass.yaml",
		"webhook_no_v1.yaml", "stale_kubelet_node.yaml",
	}
	c := clusterFromFixtures(t, fixtures...)
	up := Upgrade{From: MustParseVersion("1.35.3"), To: MustParseVersion("1.36.0")}

	rep := NewEngine(AllChecks()...).Run(context.Background(), c, up)

	for _, f := range rep.Findings {
		if f.Error != "" || f.Result == nil {
			continue
		}
		if f.Result.Status != StatusFail && f.Result.Status != StatusWarn {
			continue
		}
		if f.Result.Remediation == "" {
			t.Errorf("check %q reported %s without remediation: %s",
				f.Check, f.Result.Status, f.Result.Message)
		}
		if f.Result.Message == "" {
			t.Errorf("check %q reported %s with an empty message", f.Check, f.Result.Status)
		}
	}
}

// TestFixtureClusterIsBlocked confirms that a cluster assembled from the
// problem fixtures produces a blocking verdict end to end.
func TestFixtureClusterIsBlocked(t *testing.T) {
	c := clusterFromFixtures(t, "blocking_pdb.yaml", "gitrepo_pod.yaml", "stale_kubelet_node.yaml")
	up := Upgrade{From: MustParseVersion("1.35.3"), To: MustParseVersion("1.36.0")}

	rep := NewEngine(AllChecks()...).Run(context.Background(), c, up)

	if got := rep.ExitCode(); got != ExitBlocked {
		t.Errorf("ExitCode() = %d, want %d (blocked)", got, ExitBlocked)
	}
	if sum := rep.Summarize(); sum.Blocking < 3 {
		t.Errorf("blocking findings = %d, want at least 3 (PDB, gitRepo, kubelet skew)", sum.Blocking)
	}
}

// TestNoFalsePassBeyondDataHorizon guards the tool's most dangerous possible
// failure: reporting a clean result for a Kubernetes release it has no data for.
//
// Before this guard existed, targeting a release past the deprecation
// database's horizon returned StatusPass - an uninformed answer that reads as
// "I checked and it is fine".
func TestNoFalsePassBeyondDataHorizon(t *testing.T) {
	beyond := nextMinorAfter(deprecation.DataHorizon)
	c := clusterFromFixtures(t)
	up := Upgrade{From: MustParseVersion(deprecation.DataHorizon), To: MustParseVersion(beyond)}

	dbChecks := map[string]func(context.Context, *Cluster, Upgrade) (*Result, error){
		"api-removals-on-path": checkAPIRemovalsOnPath,
		"removed-api-objects":  checkRemovedAPIObjects,
	}

	for name, run := range dbChecks {
		t.Run(name, func(t *testing.T) {
			got, err := run(context.Background(), c, up)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Status == StatusPass {
				t.Errorf("%s reported Pass for %s, which is beyond the data horizon (%s). "+
					"A check with no data must not claim the cluster is clean. Message: %s",
					name, beyond, deprecation.DataHorizon, got.Message)
			}
			if got.Remediation == "" {
				t.Errorf("%s gave no guidance about the missing data", name)
			}
		})
	}
}

// TestWithinHorizonStillPasses confirms the guard did not make every result a
// warning - a target at the horizon must still be able to pass cleanly.
func TestWithinHorizonStillPasses(t *testing.T) {
	c := clusterFromFixtures(t)
	up := Upgrade{From: MustParseVersion("1.35.0"), To: MustParseVersion(deprecation.DataHorizon)}

	got, err := checkAPIRemovalsOnPath(context.Background(), c, up)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Status != StatusPass {
		t.Errorf("status = %v, want Pass for a target at the data horizon (%s): %s",
			got.Status, deprecation.DataHorizon, got.Message)
	}
}

// nextMinorAfter returns the minor release following the given "MAJOR.MINOR".
func nextMinorAfter(minor string) string {
	v := MustParseVersion(minor)
	return fmt.Sprintf("%d.%d", v.Major, v.Minor+1)
}

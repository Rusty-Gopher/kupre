package openstack

import (
	"context"
	"strings"
	"testing"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

// testCluster builds an analyzer.Cluster over a fake clientset.
func testCluster(objs ...runtime.Object) *analyzer.Cluster {
	return analyzer.NewClusterForTest(
		fake.NewSimpleClientset(objs...), analyzer.MustParseVersion("1.35.3"))
}

func TestImageVersion(t *testing.T) {
	tests := []struct {
		name   string
		image  string
		want   string
		wantOK bool
	}{
		{
			name:  "standard cinder csi tag",
			image: "registry.k8s.io/provider-os/cinder-csi-plugin:v1.33.1",
			want:  "v1.33.1", wantOK: true,
		},
		{
			name:  "no v prefix",
			image: "registry.k8s.io/provider-os/cinder-csi-plugin:1.34.0",
			want:  "v1.34.0", wantOK: true,
		},
		{
			name:  "major.minor only",
			image: "example.com/thing:1.36",
			want:  "v1.36.0", wantOK: true,
		},
		{
			name: "digest is not mistaken for a tag",
			// A digest is hex and must not be parsed as a version; the tag in
			// front of it is the real one.
			image: "registry.k8s.io/provider-os/cinder-csi-plugin:v1.33.1@sha256:abc123",
			want:  "v1.33.1", wantOK: true,
		},
		{
			name:   "digest only, no tag",
			image:  "registry.k8s.io/provider-os/cinder-csi-plugin@sha256:abc123",
			wantOK: false,
		},
		{name: "no tag at all", image: "nginx", wantOK: false},
		{name: "latest is not a version", image: "nginx:latest", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := imageVersion(tt.image)
			if ok != tt.wantOK {
				t.Fatalf("imageVersion(%q) ok = %v, want %v", tt.image, ok, tt.wantOK)
			}
			if ok && got.String() != tt.want {
				t.Errorf("imageVersion(%q) = %s, want %s", tt.image, got, tt.want)
			}
		})
	}
}

func TestDetect(t *testing.T) {
	tests := []struct {
		name string
		objs []runtime.Object
		want bool
	}{
		{
			name: "provider ID identifies openstack",
			objs: []runtime.Object{&corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "n1"},
				Spec:       corev1.NodeSpec{ProviderID: "openstack://abc-123"},
			}},
			want: true,
		},
		{
			name: "cinder csi driver identifies openstack",
			objs: []runtime.Object{&storagev1.CSIDriver{
				ObjectMeta: metav1.ObjectMeta{Name: "cinder.csi.openstack.org"},
			}},
			want: true,
		},
		{
			name: "in-tree cinder storageclass identifies openstack",
			objs: []runtime.Object{&storagev1.StorageClass{
				ObjectMeta:  metav1.ObjectMeta{Name: "standard"},
				Provisioner: "kubernetes.io/cinder",
			}},
			want: true,
		},
		{
			name: "aws cluster is not openstack",
			objs: []runtime.Object{
				&corev1.Node{
					ObjectMeta: metav1.ObjectMeta{Name: "n1"},
					Spec:       corev1.NodeSpec{ProviderID: "aws:///us-east-1a/i-abc"},
				},
				&storagev1.CSIDriver{ObjectMeta: metav1.ObjectMeta{Name: "ebs.csi.aws.com"}},
			},
			want: false,
		},
		{name: "empty cluster is not openstack", objs: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Provider{}.Detect(context.Background(), testCluster(tt.objs...))
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if got != tt.want {
				t.Errorf("Detect() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckCinderInlineEphemeral(t *testing.T) {
	inlinePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "uses-inline", Namespace: "default"},
		Spec: corev1.PodSpec{Volumes: []corev1.Volume{{
			Name: "scratch",
			VolumeSource: corev1.VolumeSource{
				CSI: &corev1.CSIVolumeSource{Driver: "cinder.csi.openstack.org"},
			},
		}}},
	}
	otherDriverPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "other-driver", Namespace: "default"},
		Spec: corev1.PodSpec{Volumes: []corev1.Volume{{
			Name: "secrets",
			VolumeSource: corev1.VolumeSource{
				CSI: &corev1.CSIVolumeSource{Driver: "secrets-store.csi.k8s.io"},
			},
		}}},
	}
	pvcPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "uses-pvc", Namespace: "default"},
		Spec: corev1.PodSpec{Volumes: []corev1.Volume{{
			Name: "data",
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data"},
			},
		}}},
	}

	tests := []struct {
		name       string
		pods       []runtime.Object
		wantStatus analyzer.Status
		wantCount  int
	}{
		{name: "no pods passes", pods: nil, wantStatus: analyzer.StatusPass},
		{name: "pvc-backed volume passes", pods: []runtime.Object{pvcPod}, wantStatus: analyzer.StatusPass},
		{name: "other csi driver passes", pods: []runtime.Object{otherDriverPod}, wantStatus: analyzer.StatusPass},
		{name: "inline cinder fails", pods: []runtime.Object{inlinePod}, wantStatus: analyzer.StatusFail, wantCount: 1},
		{
			name:       "only the inline pod is reported",
			pods:       []runtime.Object{inlinePod, otherDriverPod, pvcPod},
			wantStatus: analyzer.StatusFail, wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testCluster(tt.pods...)
			up := analyzer.Upgrade{
				From: analyzer.MustParseVersion("1.35.3"),
				To:   analyzer.MustParseVersion("1.36.0"),
			}

			got, err := checkCinderInlineEphemeral(context.Background(), c, up)
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

func TestCheckNodeProviderIDs(t *testing.T) {
	goodNode := func(name string) *corev1.Node {
		return &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name:   name,
				Labels: map[string]string{corev1.LabelTopologyZone: "fes1a"},
			},
			Spec: corev1.NodeSpec{ProviderID: "openstack://" + name},
		}
	}

	tests := []struct {
		name       string
		nodes      []runtime.Object
		wantStatus analyzer.Status
		wantCount  int
	}{
		{
			name:       "fully labelled nodes pass",
			nodes:      []runtime.Object{goodNode("a"), goodNode("b")},
			wantStatus: analyzer.StatusPass,
		},
		{
			name: "missing provider ID warns",
			nodes: []runtime.Object{&corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "a",
					Labels: map[string]string{corev1.LabelTopologyZone: "fes1a"},
				},
			}},
			wantStatus: analyzer.StatusWarn, wantCount: 1,
		},
		{
			name: "missing zone label warns",
			nodes: []runtime.Object{&corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "a"},
				Spec:       corev1.NodeSpec{ProviderID: "openstack://a"},
			}},
			wantStatus: analyzer.StatusWarn, wantCount: 1,
		},
		{
			name:       "no nodes skips",
			nodes:      nil,
			wantStatus: analyzer.StatusSkip,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testCluster(tt.nodes...)
			up := analyzer.Upgrade{
				From: analyzer.MustParseVersion("1.35.3"),
				To:   analyzer.MustParseVersion("1.36.0"),
			}

			got, err := checkNodeProviderIDs(context.Background(), c, up)
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

// TestCheckCinderInTreeMigration guards the translation-shim distinction: the
// in-tree plugin's removal in 1.26 did not remove the CSI translation shim
// (verified fact, see CLAUDE.md), so legacy objects are a blocker only when
// the cinder.csi.openstack.org driver is absent.
func TestCheckCinderInTreeMigration(t *testing.T) {
	intreeSC := &storagev1.StorageClass{
		ObjectMeta:  metav1.ObjectMeta{Name: "legacy-cinder"},
		Provisioner: "kubernetes.io/cinder",
	}
	cinderDriver := &storagev1.CSIDriver{
		ObjectMeta: metav1.ObjectMeta{Name: "cinder.csi.openstack.org"},
	}

	tests := []struct {
		name       string
		objs       []runtime.Object
		wantStatus analyzer.Status
		wantCount  int
	}{
		{name: "no in-tree usage passes", objs: []runtime.Object{cinderDriver}, wantStatus: analyzer.StatusPass},
		{
			name: "in-tree usage with the CSI driver installed warns (translation shim carries it)",
			objs: []runtime.Object{intreeSC, cinderDriver}, wantStatus: analyzer.StatusWarn, wantCount: 1,
		},
		{
			name: "in-tree usage without the CSI driver is blocking",
			objs: []runtime.Object{intreeSC}, wantStatus: analyzer.StatusFail, wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := testCluster(tt.objs...)
			up := analyzer.Upgrade{
				From: analyzer.MustParseVersion("1.35.3"),
				To:   analyzer.MustParseVersion("1.36.0"),
			}

			got, err := checkCinderInTreeMigration(context.Background(), c, up)
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

// TestCinderVersionWordingDoesNotInventSupportClaims pins the verified rule:
// there is no published CPO compatibility matrix, so findings must report the
// observed drift and the absence of a guarantee - never an "unsupported"
// verdict upstream does not issue.
func TestCinderVersionWordingDoesNotInventSupportClaims(t *testing.T) {
	lagging := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "csi-cinder-controller", Namespace: "kube-system"},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{
				Name:  "cinder-csi-plugin",
				Image: "registry.k8s.io/provider-os/cinder-csi-plugin:v1.33.1",
			}}}},
		},
	}
	c := testCluster(lagging)
	up := analyzer.Upgrade{
		From: analyzer.MustParseVersion("1.35.3"),
		To:   analyzer.MustParseVersion("1.36.0"),
	}

	got, err := checkCinderCSIVersion(context.Background(), c, up)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Status != analyzer.StatusWarn {
		t.Fatalf("status = %v, want warn (message: %s)", got.Status, got.Message)
	}
	text := got.Message + " " + got.Remediation
	if strings.Contains(text, "unsupported") {
		t.Errorf("finding claims a support verdict upstream never published:\n%s", text)
	}
	for _, want := range []string{"go.mod", "no compatibility matrix"} {
		if !strings.Contains(got.Remediation, want) {
			t.Errorf("remediation should ground the pairing in %q; got:\n%s", want, got.Remediation)
		}
	}
}

package analyzer

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

// These tests pin the translation-shim distinction on the in-tree storage
// checks: a removed in-tree plugin is a blocker only when nothing can carry
// its volumes. Where CSI migration was on by default before the removal
// (cinder, aws-ebs, gce-pd, azure-*, vsphere, portworx) the translation layer
// keeps legacy objects working as long as the replacement driver is
// installed. rbd lost its migration support in the same release that removed
// the plugin, and cephfs never had any, so a registered ceph CSI driver does
// NOT soften those findings. Sources are cited on inTreeProvisioner.Translated.
func translationTestCluster(objs ...runtime.Object) *Cluster {
	return NewClusterForTest(fake.NewSimpleClientset(objs...), MustParseVersion("1.35.3"))
}

func TestInTreeProvisionerTranslationSplit(t *testing.T) {
	cinderSC := &storagev1.StorageClass{
		ObjectMeta:  metav1.ObjectMeta{Name: "legacy-cinder"},
		Provisioner: "kubernetes.io/cinder",
	}
	rbdSC := &storagev1.StorageClass{
		ObjectMeta:  metav1.ObjectMeta{Name: "legacy-rbd"},
		Provisioner: "kubernetes.io/rbd",
	}
	cinderDriver := &storagev1.CSIDriver{ObjectMeta: metav1.ObjectMeta{Name: "cinder.csi.openstack.org"}}
	rbdDriver := &storagev1.CSIDriver{ObjectMeta: metav1.ObjectMeta{Name: "rbd.csi.ceph.com"}}

	up := Upgrade{From: MustParseVersion("1.35.3"), To: MustParseVersion("1.36.0")}

	tests := []struct {
		name       string
		objs       []runtime.Object
		wantStatus Status
	}{
		{
			name:       "migrated plugin with driver installed is carried by the shim",
			objs:       []runtime.Object{cinderSC, cinderDriver},
			wantStatus: StatusWarn,
		},
		{
			name:       "migrated plugin without its driver is blocking",
			objs:       []runtime.Object{cinderSC},
			wantStatus: StatusFail,
		},
		{
			name: "rbd is blocking even with the ceph CSI driver registered: " +
				"1.31 removed its CSI migration support with the plugin",
			objs:       []runtime.Object{rbdSC, rbdDriver},
			wantStatus: StatusFail,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := checkInTreeProvisioners(context.Background(), translationTestCluster(tt.objs...), up)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Status != tt.wantStatus {
				t.Fatalf("status = %v, want %v (message: %s)", got.Status, tt.wantStatus, got.Message)
			}
			if got.Status == StatusWarn && !strings.Contains(got.Message, "translation shim") {
				t.Errorf("warn message should name the translation shim dependency; got: %s", got.Message)
			}
		})
	}
}

func TestInTreeVolumeSourceTranslationSplit(t *testing.T) {
	cinderPV := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-cinder"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				Cinder: &corev1.CinderPersistentVolumeSource{VolumeID: "vol-1"},
			},
		},
	}
	rbdPV := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-rbd"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				RBD: &corev1.RBDPersistentVolumeSource{RBDImage: "img"},
			},
		},
	}
	// FlexVolume is deprecated but not removed; it must not be reported here
	// as a removed plugin (flexvolume-in-use covers it).
	flexPV := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-flex"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				FlexVolume: &corev1.FlexPersistentVolumeSource{Driver: "vendor/driver"},
			},
		},
	}
	cinderDriver := &storagev1.CSIDriver{ObjectMeta: metav1.ObjectMeta{Name: "cinder.csi.openstack.org"}}

	up := Upgrade{From: MustParseVersion("1.35.3"), To: MustParseVersion("1.36.0")}

	tests := []struct {
		name       string
		objs       []runtime.Object
		wantStatus Status
	}{
		{
			name:       "cinder PV with driver installed is carried by the shim",
			objs:       []runtime.Object{cinderPV, cinderDriver},
			wantStatus: StatusWarn,
		},
		{
			name:       "cinder PV without the driver is blocking",
			objs:       []runtime.Object{cinderPV},
			wantStatus: StatusFail,
		},
		{
			name:       "rbd PV is blocking - migration support was removed with the plugin",
			objs:       []runtime.Object{rbdPV, cinderDriver},
			wantStatus: StatusFail,
		},
		{
			name:       "flexvolume PV alone is not reported as a removed plugin",
			objs:       []runtime.Object{flexPV},
			wantStatus: StatusPass,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := checkInTreeVolumeSources(context.Background(), translationTestCluster(tt.objs...), up)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Status != tt.wantStatus {
				t.Fatalf("status = %v, want %v (message: %s)", got.Status, tt.wantStatus, got.Message)
			}
		})
	}
}

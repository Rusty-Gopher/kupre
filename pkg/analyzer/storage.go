package analyzer

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// StorageChecks returns checks covering storage and CSI upgrade readiness.
func StorageChecks() []Check {
	return []Check{
		{
			Name:        "intree-storage-provisioner",
			Description: "StorageClasses still using removed in-tree volume provisioners",
			Category:    CategoryStorage,
			Severity:    SeverityError,
			Action:      ActionPlanAhead,
			Run:         checkInTreeProvisioners,
		},
		{
			Name:        "intree-volume-sources",
			Description: "PersistentVolumes still backed by removed in-tree volume plugins",
			Category:    CategoryStorage,
			Severity:    SeverityError,
			Action:      ActionPlanAhead,
			Run:         checkInTreeVolumeSources,
		},
		{
			Name:        "csi-driver-declared",
			Description: "Every CSI-backed StorageClass has a matching CSIDriver object",
			Evidence:    "Compares StorageClass provisioners against cluster-scoped CSIDriver objects.",
			Limits: "A CSIDriver object is a cluster-level declaration. It does not confirm the " +
				"driver is registered on any particular node - that lives in CSINode - nor that " +
				"the node plugin is running and healthy.",
			Category: CategoryStorage,
			Severity: SeverityError,
			Action:   ActionFixBeforeStart,
			Run:      checkCSIDriverRegistered,
		},
		{
			Name:        "default-storageclass",
			Description: "Exactly one default StorageClass is defined",
			Category:    CategoryStorage,
			Severity:    SeverityWarning,
			Action:      ActionFixBeforeStart,
			Run:         checkDefaultStorageClass,
		},
		{
			Name:        "unhealthy-pvs",
			Description: "PersistentVolumes in a Failed or Released state before the upgrade",
			Evidence:    "Reads the phase of every PersistentVolume.",
			Limits:      "Inspects PersistentVolumes only. Pending PersistentVolumeClaims are not evaluated.",
			Category:    CategoryStorage,
			Severity:    SeverityWarning,
			Action:      ActionResolveFirst,
			Run:         checkUnhealthyPVs,
		},
	}
}

// inTreeProvisioner maps a removed in-tree provisioner to its CSI replacement
// and the release in which the in-tree plugin stopped working.
type inTreeProvisioner struct {
	CSIDriver string
	RemovedIn string
}

// inTreeProvisioners lists in-tree provisioners whose plugins have been removed
// from kubelet and kube-controller-manager in favour of CSI drivers.
var inTreeProvisioners = map[string]inTreeProvisioner{
	"kubernetes.io/cinder":           {CSIDriver: "cinder.csi.openstack.org", RemovedIn: "1.26"},
	"kubernetes.io/aws-ebs":          {CSIDriver: "ebs.csi.aws.com", RemovedIn: "1.27"},
	"kubernetes.io/gce-pd":           {CSIDriver: "pd.csi.storage.gke.io", RemovedIn: "1.28"},
	"kubernetes.io/azure-disk":       {CSIDriver: "disk.csi.azure.com", RemovedIn: "1.30"},
	"kubernetes.io/azure-file":       {CSIDriver: "file.csi.azure.com", RemovedIn: "1.30"},
	"kubernetes.io/vsphere-volume":   {CSIDriver: "csi.vsphere.vmware.com", RemovedIn: "1.30"},
	"kubernetes.io/portworx-volume":  {CSIDriver: "pxd.portworx.com", RemovedIn: "1.36"},
	"kubernetes.io/glusterfs":        {CSIDriver: "", RemovedIn: "1.26"},
	"kubernetes.io/storageos":        {CSIDriver: "", RemovedIn: "1.25"},
	"kubernetes.io/quobyte":          {CSIDriver: "", RemovedIn: "1.25"},
	"kubernetes.io/flocker":          {CSIDriver: "", RemovedIn: "1.25"},
	"kubernetes.io/scaleio":          {CSIDriver: "", RemovedIn: "1.25"},
	"kubernetes.io/rbd":              {CSIDriver: "rbd.csi.ceph.com", RemovedIn: "1.31"},
	"kubernetes.io/cephfs":           {CSIDriver: "cephfs.csi.ceph.com", RemovedIn: "1.31"},
	"kubernetes.io/no-provisioner":   {},
	"kubernetes.io/host-path":        {},
	"kubernetes.io/aws-elastic-file": {},
}

// checkInTreeProvisioners finds StorageClasses using a removed in-tree
// provisioner. Volume provisioning silently stops working once the in-tree
// plugin is gone from the control plane.
func checkInTreeProvisioners(ctx context.Context, c *Cluster, up Upgrade) (*Result, error) {
	scs, err := c.StorageClasses(ctx)
	if err != nil {
		return nil, err
	}
	if len(scs) == 0 {
		return Skip("no StorageClasses defined"), nil
	}

	var bad []AffectedResource
	for _, sc := range scs {
		p, ok := inTreeProvisioners[sc.Provisioner]
		if !ok || p.RemovedIn == "" {
			continue
		}
		replacement := "no CSI replacement - this storage backend is no longer supported"
		if p.CSIDriver != "" {
			replacement = "migrate to CSI driver " + p.CSIDriver
		}
		bad = append(bad, AffectedResource{
			Kind: "StorageClass", APIVersion: "storage.k8s.io/v1", Name: sc.Name,
			Detail: fmt.Sprintf("in-tree provisioner %s removed in %s - %s",
				sc.Provisioner, p.RemovedIn, replacement),
		})
	}

	if len(bad) == 0 {
		return Pass("all %d StorageClass(es) use CSI or supported provisioners", len(scs)), nil
	}
	sortResources(bad)
	return Fail("%d StorageClass(es) use a removed in-tree provisioner", len(bad)).
		WithResources(bad...).
		WithRemediation("In-tree volume plugins have been removed from the control plane. Volumes " +
			"provisioned by these StorageClasses will fail to attach or provision after the " +
			"upgrade. Install the CSI driver, create a replacement StorageClass, and migrate " +
			"workloads before upgrading.").
		WithDocs("https://kubernetes.io/docs/concepts/storage/volumes/#csi-migration"), nil
}

// checkInTreeVolumeSources inspects PersistentVolumes for in-tree volume
// sources. A PV whose plugin has been removed cannot be mounted at all.
func checkInTreeVolumeSources(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	pvs, err := c.PersistentVolumes(ctx)
	if err != nil {
		return nil, err
	}
	if len(pvs) == 0 {
		return Skip("no PersistentVolumes found"), nil
	}

	var bad []AffectedResource
	for _, pv := range pvs {
		if src := inTreeVolumeSource(pv.Spec.PersistentVolumeSource); src != "" {
			bad = append(bad, AffectedResource{
				Kind: "PersistentVolume", APIVersion: "v1", Name: pv.Name,
				Detail: fmt.Sprintf("in-tree %s volume source; bound to %s", src, boundClaim(pv)),
			})
		}
	}

	if len(bad) == 0 {
		return Pass("all %d PersistentVolume(s) use CSI or supported volume sources", len(pvs)), nil
	}
	sortResources(bad)
	return Fail("%d PersistentVolume(s) still use a removed in-tree volume plugin", len(bad)).
		WithResources(bad...).
		WithRemediation("These PVs reference volume plugins that no longer exist in the kubelet. " +
			"Their pods will fail to mount after the upgrade. Migrate the data to CSI-backed " +
			"volumes first - CSI migration rewrites the in-tree source transparently only while " +
			"the in-tree plugin is still present.").
		WithDocs("https://kubernetes.io/docs/concepts/storage/volumes/#csi-migration"), nil
}

// inTreeVolumeSource returns the name of the removed in-tree plugin backing the
// volume source, or "" if the source is CSI or still supported.
func inTreeVolumeSource(s corev1.PersistentVolumeSource) string {
	switch {
	case s.Cinder != nil:
		return "Cinder"
	case s.AWSElasticBlockStore != nil:
		return "AWSElasticBlockStore"
	case s.GCEPersistentDisk != nil:
		return "GCEPersistentDisk"
	case s.AzureDisk != nil:
		return "AzureDisk"
	case s.AzureFile != nil:
		return "AzureFile"
	case s.VsphereVolume != nil:
		return "vSphereVolume"
	case s.PhotonPersistentDisk != nil:
		return "PhotonPersistentDisk"
	case s.PortworxVolume != nil:
		return "PortworxVolume"
	case s.ScaleIO != nil:
		return "ScaleIO"
	case s.StorageOS != nil:
		return "StorageOS"
	case s.Glusterfs != nil:
		return "GlusterFS"
	case s.RBD != nil:
		return "RBD"
	case s.CephFS != nil:
		return "CephFS"
	case s.FlexVolume != nil:
		return "FlexVolume"
	default:
		return ""
	}
}

// boundClaim renders the PVC a PV is bound to, or "<unbound>".
func boundClaim(pv corev1.PersistentVolume) string {
	if pv.Spec.ClaimRef == nil {
		return "<unbound>"
	}
	return pv.Spec.ClaimRef.Namespace + "/" + pv.Spec.ClaimRef.Name
}

// checkCSIDriverRegistered verifies that each CSI provisioner referenced by a
// StorageClass is actually registered as a CSIDriver object.
func checkCSIDriverRegistered(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	scs, err := c.StorageClasses(ctx)
	if err != nil {
		return nil, err
	}
	drivers, err := c.CSIDrivers(ctx)
	if err != nil {
		return nil, err
	}
	if len(scs) == 0 {
		return Skip("no StorageClasses defined"), nil
	}

	registered := map[string]bool{}
	for _, d := range drivers {
		registered[d.Name] = true
	}

	var missing []AffectedResource
	for _, sc := range scs {
		// Only CSI provisioners appear as CSIDriver objects; in-tree ones are
		// covered by the in-tree check.
		if _, isInTree := inTreeProvisioners[sc.Provisioner]; isInTree {
			continue
		}
		if sc.Provisioner == "kubernetes.io/no-provisioner" || registered[sc.Provisioner] {
			continue
		}
		missing = append(missing, AffectedResource{
			Kind: "StorageClass", APIVersion: "storage.k8s.io/v1", Name: sc.Name,
			Detail: fmt.Sprintf("provisioner %q has no CSIDriver object", sc.Provisioner),
		})
	}

	if len(missing) == 0 {
		return Pass("all CSI provisioners referenced by %d StorageClass(es) have a CSIDriver object "+
			"(per-node registration not checked)", len(scs)), nil
	}
	sortResources(missing)
	return Fail("%d StorageClass(es) reference an unregistered CSI driver", len(missing)).
		WithResources(missing...).
		WithRemediation("A StorageClass whose driver is not registered cannot provision volumes. " +
			"Either the driver's DaemonSet is not running, or the StorageClass is stale. Confirm " +
			"with: kubectl get csidrivers"), nil
}

// checkDefaultStorageClass verifies exactly one default StorageClass exists.
// Zero means dynamic provisioning without an explicit class fails; more than
// one means the API server rejects the ambiguity.
func checkDefaultStorageClass(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	scs, err := c.StorageClasses(ctx)
	if err != nil {
		return nil, err
	}
	if len(scs) == 0 {
		return Skip("no StorageClasses defined"), nil
	}

	const defaultAnnotation = "storageclass.kubernetes.io/is-default-class"
	var defaults []AffectedResource
	for _, sc := range scs {
		if sc.Annotations[defaultAnnotation] == "true" {
			defaults = append(defaults, AffectedResource{
				Kind: "StorageClass", APIVersion: "storage.k8s.io/v1", Name: sc.Name,
				Detail: "marked default, provisioner " + sc.Provisioner,
			})
		}
	}

	switch len(defaults) {
	case 1:
		return Pass("exactly one default StorageClass: %s", defaults[0].Name), nil
	case 0:
		return Warn("no default StorageClass among %d defined", len(scs)).
			WithRemediation("PersistentVolumeClaims that omit storageClassName will stay Pending. " +
				"If workloads rely on a default, set the " + defaultAnnotation + " annotation."), nil
	default:
		sortResources(defaults)
		return Warn("%d StorageClasses are marked default", len(defaults)).
			WithResources(defaults...).
			WithRemediation("With multiple defaults the API server picks the most recently created " +
				"one, which makes provisioning non-deterministic. Leave the annotation set on " +
				"exactly one."), nil
	}
}

// checkUnhealthyPVs finds PersistentVolumes in a terminal-but-unreclaimed state.
// These will still be broken after the upgrade, and resolving them first keeps
// post-upgrade storage errors attributable.
func checkUnhealthyPVs(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	pvs, err := c.PersistentVolumes(ctx)
	if err != nil {
		return nil, err
	}

	var released []AffectedResource
	for _, pv := range pvs {
		switch pv.Status.Phase {
		case corev1.VolumeFailed:
			released = append(released, AffectedResource{
				Kind: "PersistentVolume", APIVersion: "v1", Name: pv.Name,
				Detail: "phase=Failed: " + strings.TrimSpace(pv.Status.Message),
			})
		case corev1.VolumeReleased:
			released = append(released, AffectedResource{
				Kind: "PersistentVolume", APIVersion: "v1", Name: pv.Name,
				Detail: "phase=Released - claim deleted but volume not reclaimed",
			})
		}
	}

	if len(released) == 0 {
		return Pass("no failed or orphaned PersistentVolumes among %d", len(pvs)), nil
	}
	sortResources(released)
	return Warn("%d PersistentVolume(s) are failed or released", len(released)).
		WithResources(released...).
		WithRemediation("Resolve these before upgrading so that storage errors seen afterwards " +
			"can be attributed to the upgrade rather than to pre-existing state."), nil
}

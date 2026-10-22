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
				"the node plugin is running and healthy. Whether any PVC or pod actually uses " +
				"these StorageClasses is not evaluated, so a hit may be a stale class rather " +
				"than a live breakage - which is why this is a warning, not a blocker.",
			Category: CategoryStorage,
			Severity: SeverityWarning,
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

// inTreeProvisioner maps a removed in-tree provisioner to its CSI replacement,
// the release in which the in-tree plugin was removed, and whether the CSI
// migration translation layer still carries legacy objects after that removal.
type inTreeProvisioner struct {
	CSIDriver string
	RemovedIn string
	// Translated is true only where CSI migration was on by default before the
	// plugin's removal, so legacy StorageClasses and PV sources keep working
	// through the translation shim as long as the replacement driver is
	// installed. It is false for rbd and cephfs: Kubernetes 1.31 "will remove
	// the Ceph RBD volume plugin and its CSI migration support, making the rbd
	// volume type non-functional", and CephFS never had migration support at
	// all (https://kubernetes.io/blog/2024/07/19/kubernetes-1-31-upcoming-changes/).
	// Portworx migration (CSIMigrationPortworx) is enabled by default since
	// 1.31 (https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/);
	// the Cinder shim surviving the 1.26 removal is a verified fact recorded in
	// CLAUDE.md. Plugins with no CSIDriver were removed with no replacement.
	Translated bool
}

// inTreeProvisioners lists in-tree provisioners whose plugins have been removed
// from kubelet and kube-controller-manager in favour of CSI drivers.
var inTreeProvisioners = map[string]inTreeProvisioner{
	"kubernetes.io/cinder":           {CSIDriver: "cinder.csi.openstack.org", RemovedIn: "1.26", Translated: true},
	"kubernetes.io/aws-ebs":          {CSIDriver: "ebs.csi.aws.com", RemovedIn: "1.27", Translated: true},
	"kubernetes.io/gce-pd":           {CSIDriver: "pd.csi.storage.gke.io", RemovedIn: "1.28", Translated: true},
	"kubernetes.io/azure-disk":       {CSIDriver: "disk.csi.azure.com", RemovedIn: "1.30", Translated: true},
	"kubernetes.io/azure-file":       {CSIDriver: "file.csi.azure.com", RemovedIn: "1.30", Translated: true},
	"kubernetes.io/vsphere-volume":   {CSIDriver: "csi.vsphere.vmware.com", RemovedIn: "1.30", Translated: true},
	"kubernetes.io/portworx-volume":  {CSIDriver: "pxd.portworx.com", RemovedIn: "1.36", Translated: true},
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

// splitByTranslation partitions in-tree usages into those the CSI translation
// shim demonstrably carries (plugin migrated, replacement driver registered)
// and those that are broken outright.
func splitByTranslation(p inTreeProvisioner, registered map[string]bool) (shimmed bool, why string) {
	switch {
	case p.CSIDriver == "":
		return false, "removed in " + p.RemovedIn + " with no CSI replacement - this storage backend is no longer supported"
	case !p.Translated:
		return false, fmt.Sprintf("removed in %s together with its CSI migration support - volumes must be re-created on %s", p.RemovedIn, p.CSIDriver)
	case !registered[p.CSIDriver]:
		return false, fmt.Sprintf("removed in %s and its CSI replacement %s is not installed - translation has nothing to hand over to", p.RemovedIn, p.CSIDriver)
	default:
		return true, fmt.Sprintf("removed in %s - works only through CSI translation to %s (installed); migrate explicitly", p.RemovedIn, p.CSIDriver)
	}
}

// checkInTreeProvisioners finds StorageClasses using a removed in-tree
// provisioner. Where CSI migration reached on-by-default before the removal,
// the translation shim keeps legacy StorageClasses working as long as the
// replacement CSI driver is installed - so only usages without a working
// translation path are reported as blocking (see inTreeProvisioner.Translated
// for sources).
func checkInTreeProvisioners(ctx context.Context, c *Cluster, up Upgrade) (*Result, error) {
	scs, err := c.StorageClasses(ctx)
	if err != nil {
		return nil, err
	}
	if len(scs) == 0 {
		return Skip("no StorageClasses defined"), nil
	}
	drivers, err := c.CSIDrivers(ctx)
	if err != nil {
		return nil, err
	}
	registered := map[string]bool{}
	for _, d := range drivers {
		registered[d.Name] = true
	}

	var broken, shimmed []AffectedResource
	for _, sc := range scs {
		p, ok := inTreeProvisioners[sc.Provisioner]
		if !ok || p.RemovedIn == "" {
			continue
		}
		viaShim, why := splitByTranslation(p, registered)
		res := AffectedResource{
			Kind: "StorageClass", APIVersion: "storage.k8s.io/v1", Name: sc.Name,
			Detail: fmt.Sprintf("in-tree provisioner %s %s", sc.Provisioner, why),
		}
		if viaShim {
			shimmed = append(shimmed, res)
		} else {
			broken = append(broken, res)
		}
	}

	if len(broken) == 0 && len(shimmed) == 0 {
		return Pass("all %d StorageClass(es) use CSI or supported provisioners", len(scs)), nil
	}
	if len(broken) > 0 {
		all := append(broken, shimmed...)
		sortResources(all)
		return Fail("%d StorageClass(es) use a removed in-tree provisioner with no working CSI "+
			"translation", len(broken)).
			WithResources(all...).
			WithRemediation("From each plugin's removal release on, nothing serves volume " +
				"operations for these StorageClasses: either no CSI replacement exists, " +
				"migration support was removed with the plugin, or the replacement driver is " +
				"not installed here for the translation shim to hand over to. Install the CSI " +
				"driver where one exists, create a replacement StorageClass, and migrate " +
				"workloads before upgrading.").
			WithDocs("https://kubernetes.io/docs/concepts/storage/volumes/#csi-migration"), nil
	}
	sortResources(shimmed)
	return Warn("%d StorageClass(es) still use an in-tree provisioner, working only through the "+
		"CSI translation shim", len(shimmed)).
		WithResources(shimmed...).
		WithRemediation("These keep working because CSI migration translates them to the installed " +
			"CSI driver, a dependency invisible in the StorageClass itself. Recreate each with the " +
			"CSI provisioner named above so nothing rests on translation.").
		WithDocs("https://kubernetes.io/docs/concepts/storage/volumes/#csi-migration"), nil
}

// inTreeSourceProvisioners maps the volume-source names reported by
// inTreeVolumeSource to the provisioner table entry carrying the removal and
// translation data. Sources absent here have no CSI migration path at all.
var inTreeSourceProvisioners = map[string]string{
	"Cinder":               "kubernetes.io/cinder",
	"AWSElasticBlockStore": "kubernetes.io/aws-ebs",
	"GCEPersistentDisk":    "kubernetes.io/gce-pd",
	"AzureDisk":            "kubernetes.io/azure-disk",
	"AzureFile":            "kubernetes.io/azure-file",
	"vSphereVolume":        "kubernetes.io/vsphere-volume",
	"PortworxVolume":       "kubernetes.io/portworx-volume",
	"RBD":                  "kubernetes.io/rbd",
	"CephFS":               "kubernetes.io/cephfs",
	"GlusterFS":            "kubernetes.io/glusterfs",
	"StorageOS":            "kubernetes.io/storageos",
	"ScaleIO":              "kubernetes.io/scaleio",
}

// checkInTreeVolumeSources inspects PersistentVolumes for in-tree volume
// sources. As with StorageClasses, a PV whose plugin was under GA CSI
// migration keeps mounting through the translation shim while the replacement
// driver is installed; only PVs without that path are blocking.
func checkInTreeVolumeSources(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	pvs, err := c.PersistentVolumes(ctx)
	if err != nil {
		return nil, err
	}
	if len(pvs) == 0 {
		return Skip("no PersistentVolumes found"), nil
	}
	drivers, err := c.CSIDrivers(ctx)
	if err != nil {
		return nil, err
	}
	registered := map[string]bool{}
	for _, d := range drivers {
		registered[d.Name] = true
	}

	var broken, shimmed []AffectedResource
	for _, pv := range pvs {
		src := inTreeVolumeSource(pv.Spec.PersistentVolumeSource)
		if src == "" {
			continue
		}
		viaShim := false
		why := "no CSI migration path exists for this plugin"
		if p, ok := inTreeProvisioners[inTreeSourceProvisioners[src]]; ok && p.RemovedIn != "" {
			viaShim, why = splitByTranslation(p, registered)
		}
		res := AffectedResource{
			Kind: "PersistentVolume", APIVersion: "v1", Name: pv.Name,
			Detail: fmt.Sprintf("in-tree %s volume source %s; bound to %s", src, why, boundClaim(pv)),
		}
		if viaShim {
			shimmed = append(shimmed, res)
		} else {
			broken = append(broken, res)
		}
	}

	if len(broken) == 0 && len(shimmed) == 0 {
		return Pass("all %d PersistentVolume(s) use CSI or supported volume sources", len(pvs)), nil
	}
	if len(broken) > 0 {
		all := append(broken, shimmed...)
		sortResources(all)
		return Fail("%d PersistentVolume(s) use a removed in-tree volume plugin with no working "+
			"CSI translation", len(broken)).
			WithResources(all...).
			WithRemediation("From each plugin's removal release on, pods cannot mount these PVs: " +
				"either the plugin has no CSI migration path, migration support was removed with " +
				"it, or the replacement driver the shim would hand over to is not installed. " +
				"Migrate the data to CSI-backed volumes before upgrading.").
			WithDocs("https://kubernetes.io/docs/concepts/storage/volumes/#csi-migration"), nil
	}
	sortResources(shimmed)
	return Warn("%d PersistentVolume(s) still carry an in-tree volume source, mounted only through "+
		"the CSI translation shim", len(shimmed)).
		WithResources(shimmed...).
		WithRemediation("These PVs keep mounting because CSI migration translates them to the " +
			"installed CSI driver - a dependency invisible in the PV spec. Plan a deliberate " +
			"migration to CSI-native volumes so nothing rests on translation.").
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
	// FlexVolume is deliberately absent: it is deprecated but NOT removed, so
	// reporting it here as a removed plugin would be a false blocker. The
	// flexvolume-in-use check covers it (including the 1.36 kubeadm change).
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
		WithRemediation("A missing CSIDriver object usually means the driver is not installed: new " +
			"PVCs for these classes would sit Pending until a provisioner responds. Whether " +
			"anything currently uses them is not evaluated - check PVCs referencing each class, " +
			"then install the driver or delete the stale StorageClass. Confirm with: " +
			"kubectl get csidrivers"), nil
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

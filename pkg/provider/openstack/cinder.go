package openstack

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
	corev1 "k8s.io/api/core/v1"
)

// maxDriverLag is how many minor versions the cloud-provider-openstack
// components may trail the target Kubernetes release before kupre flags them.
//
// Zero, because upstream publishes no skew window at all. cloud-provider-openstack
// releases track Kubernetes minor versions one-for-one - the v1.36 line targets
// Kubernetes 1.36 - and the guidance is to run the matching release. There is no
// compatibility matrix (docs/compatibility-matrix.md 404s); the pairing is only
// evident from each release's go.mod pin on k8s.io/kubernetes.
//
// An earlier version tolerated one minor of lag, which invented a support
// guarantee upstream does not make.
const maxDriverLag = 0

// cinderChecks returns the Cinder CSI preflight checks.
func cinderChecks() []analyzer.Check {
	return []analyzer.Check{
		{
			Name:        "openstack-cinder-csi-version",
			Description: "cloud-provider-openstack components match the target Kubernetes release",
			Evidence:    "Parses the version tag from each cloud-provider-openstack container image.",
			Limits: "Compares minor versions only. Upstream publishes no supported-skew window, " +
				"so any mismatch is reported rather than judged. Images pinned by digest, or " +
				"tagged without a version, cannot be evaluated.",
			Category: analyzer.CategoryCloud,
			Severity: analyzer.SeverityWarning,
			Action:   analyzer.ActionPlanAhead,
			Run:      checkCinderCSIVersion,
		},
		{
			Name:        "openstack-cinder-csi-health",
			Description: "Cinder CSI controller and node plugins are running on every node",
			Category:    analyzer.CategoryCloud,
			Severity:    analyzer.SeverityError,
			Action:      analyzer.ActionFixBeforeStart,
			Run:         checkCinderCSIHealth,
		},
		{
			Name:        "openstack-cinder-intree-migration",
			Description: "No workloads remain on the removed in-tree Cinder volume plugin",
			Evidence: "Scans StorageClasses, PersistentVolumes and pod volumes for in-tree " +
				"kubernetes.io/cinder usage, and joins with CSIDriver registration to tell " +
				"whether the CSI translation shim can still carry what it finds.",
			Limits: "A CSIDriver object is a cluster-level declaration only; per-node health " +
				"of the driver is covered by openstack-cinder-csi-health.",
			Category: analyzer.CategoryCloud,
			Severity: analyzer.SeverityError,
			Run:      checkCinderInTreeMigration,
		},
		{
			Name:        "openstack-cinder-inline-ephemeral",
			Description: "Pods using inline CSI ephemeral Cinder volumes, removed in cloud-provider-openstack v1.31",
			Category:    analyzer.CategoryCloud,
			Severity:    analyzer.SeverityError,
			Action:      analyzer.ActionPlanAhead,
			Run:         checkCinderInlineEphemeral,
		},
	}
}

// imageTagRe extracts a semver-ish tag from a container image reference.
var imageTagRe = regexp.MustCompile(`:v?(\d+\.\d+(?:\.\d+)?)`)

// imageVersion parses the version from an image reference such as
// "registry.k8s.io/provider-os/cinder-csi-plugin:v1.33.1".
func imageVersion(image string) (analyzer.Version, bool) {
	// Strip any digest first so a digest's hex does not confuse the tag regexp.
	if i := strings.Index(image, "@"); i >= 0 {
		image = image[:i]
	}
	m := imageTagRe.FindStringSubmatch(image)
	if m == nil {
		return analyzer.Version{}, false
	}
	v, err := analyzer.ParseVersion(m[1])
	if err != nil {
		return analyzer.Version{}, false
	}
	return v, true
}

// openstackComponent describes a cloud-provider-openstack workload found in the
// cluster along with the version parsed from its image.
type openstackComponent struct {
	Kind      string
	Namespace string
	Name      string
	Container string
	Image     string
	Version   analyzer.Version
	Parsed    bool
}

// componentImages are the cloud-provider-openstack images kupre knows how to
// version-check, keyed by a substring of the image reference.
var componentImages = map[string]string{
	"cinder-csi-plugin":       "Cinder CSI driver",
	"manila-csi-plugin":       "Manila CSI driver",
	"openstack-cloud-control": "OpenStack cloud controller manager",
	"octavia-ingress-control": "Octavia ingress controller",
}

// findComponents scans workloads for cloud-provider-openstack images.
func findComponents(ctx context.Context, c *analyzer.Cluster) ([]openstackComponent, error) {
	var out []openstackComponent

	collect := func(kind, ns, name string, spec corev1.PodSpec) {
		containers := append(append([]corev1.Container{}, spec.InitContainers...), spec.Containers...)
		for _, ct := range containers {
			for frag := range componentImages {
				if !strings.Contains(ct.Image, frag) {
					continue
				}
				comp := openstackComponent{
					Kind: kind, Namespace: ns, Name: name,
					Container: ct.Name, Image: ct.Image,
				}
				comp.Version, comp.Parsed = imageVersion(ct.Image)
				out = append(out, comp)
			}
		}
	}

	dss, err := c.DaemonSets(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range dss {
		collect("DaemonSet", d.Namespace, d.Name, d.Spec.Template.Spec)
	}

	deps, err := c.Deployments(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range deps {
		collect("Deployment", d.Namespace, d.Name, d.Spec.Template.Spec)
	}

	stss, err := c.StatefulSets(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range stss {
		collect("StatefulSet", s.Namespace, s.Name, s.Spec.Template.Spec)
	}
	return out, nil
}

// componentLabel returns the friendly name for a component image.
func componentLabel(image string) string {
	for frag, label := range componentImages {
		if strings.Contains(image, frag) {
			return label
		}
	}
	return "cloud-provider-openstack component"
}

// checkCinderCSIVersion compares the deployed cloud-provider-openstack
// component versions against the target Kubernetes release.
//
// The CPO <-> Kubernetes pairing is convention, not published compatibility:
// each CPO vX.Y release pins k8s.io/kubernetes vX.Y in its go.mod, and there
// is no compatibility matrix or supported skew window anywhere upstream
// (docs/compatibility-matrix.md 404s). kupre therefore reports the observed
// version drift and the absence of any guarantee, and does not invent an
// "unsupported" verdict upstream never issued.
func checkCinderCSIVersion(ctx context.Context, c *analyzer.Cluster, up analyzer.Upgrade) (*analyzer.Result, error) {
	comps, err := findComponents(ctx, c)
	if err != nil {
		return nil, err
	}
	if len(comps) == 0 {
		return analyzer.Skip("no cloud-provider-openstack components found in the cluster"), nil
	}

	var lagging, unknown []analyzer.AffectedResource
	for _, comp := range comps {
		res := analyzer.AffectedResource{
			Kind: comp.Kind, Namespace: comp.Namespace, Name: comp.Name,
		}
		if !comp.Parsed {
			res.Detail = fmt.Sprintf("%s: cannot parse version from image %s",
				componentLabel(comp.Image), comp.Image)
			unknown = append(unknown, res)
			continue
		}

		lag := comp.Version.MinorDistance(up.To)
		if lag <= maxDriverLag {
			continue
		}
		res.Detail = fmt.Sprintf("%s %s does not match target Kubernetes %s (%d minor version(s) behind)",
			componentLabel(comp.Image), comp.Version.MinorString(), up.To.MinorString(), lag)
		lagging = append(lagging, res)
	}

	if len(lagging) == 0 && len(unknown) == 0 {
		return analyzer.Pass("all %d cloud-provider-openstack component(s) match Kubernetes %s",
			len(comps), up.To.MinorString()), nil
	}
	if len(lagging) == 0 {
		return analyzer.Warn("could not determine the version of %d cloud-provider-openstack component(s)", len(unknown)).
			WithResources(unknown...).
			WithRemediation("Confirm manually that these components support Kubernetes %s.", up.To.MinorString()), nil
	}

	return analyzer.Warn("%d cloud-provider-openstack component(s) lag the target Kubernetes release", len(lagging)).
		WithResources(append(lagging, unknown...)...).
		WithRemediation(
			"cloud-provider-openstack releases track Kubernetes minor versions one-for-one: the "+
				"v%s line targets Kubernetes %s. That pairing is inferred from each release's "+
				"go.mod pin - upstream publishes no compatibility matrix and guarantees no skew "+
				"window - so nothing vouches for a mismatched pairing either way. Upgrade these "+
				"components to the v%s line before or alongside the control plane. A CSI driver "+
				"behind the kubelet risks volume attach and mount failures that surface only "+
				"once nodes are being replaced.",
			up.To.MinorString(), up.To.MinorString(), up.To.MinorString()).
		WithDocs("https://github.com/kubernetes/cloud-provider-openstack/blob/master/docs/cinder-csi-plugin/using-cinder-csi-plugin.md"), nil
}

// checkCinderCSIHealth verifies the Cinder CSI node plugin is scheduled and
// ready on every node that could host a volume-consuming pod.
func checkCinderCSIHealth(ctx context.Context, c *analyzer.Cluster, _ analyzer.Upgrade) (*analyzer.Result, error) {
	drivers, err := c.CSIDrivers(ctx)
	if err != nil {
		return nil, err
	}
	found := false
	for _, d := range drivers {
		if d.Name == "cinder.csi.openstack.org" {
			found = true
			break
		}
	}
	if !found {
		return analyzer.Skip("Cinder CSI driver is not registered on this cluster"), nil
	}

	dss, err := c.DaemonSets(ctx)
	if err != nil {
		return nil, err
	}

	var issues []analyzer.AffectedResource
	sawNodePlugin := false
	for _, d := range dss {
		if !strings.Contains(d.Name, "cinder") {
			continue
		}
		sawNodePlugin = true
		if d.Status.NumberUnavailable > 0 || d.Status.NumberReady < d.Status.DesiredNumberScheduled {
			issues = append(issues, analyzer.AffectedResource{
				Kind: "DaemonSet", APIVersion: "apps/v1",
				Namespace: d.Namespace, Name: d.Name,
				Detail: fmt.Sprintf("%d/%d pods ready", d.Status.NumberReady, d.Status.DesiredNumberScheduled),
			})
		}
	}

	if !sawNodePlugin {
		return analyzer.Warn("Cinder CSI driver is registered but no Cinder DaemonSet was found").
			WithRemediation("The CSIDriver object exists without a node plugin DaemonSet backing " +
				"it. Volumes will fail to mount. Confirm the driver is actually deployed."), nil
	}
	if len(issues) == 0 {
		return analyzer.Pass("Cinder CSI node plugin is ready on all scheduled nodes"), nil
	}
	return analyzer.Fail("Cinder CSI node plugin is not ready everywhere").
		WithResources(issues...).
		WithRemediation("Nodes without a ready Cinder CSI node plugin cannot mount Cinder " +
			"volumes. Pods rescheduled onto them during the upgrade drain will stay Pending. " +
			"Fix this before starting the upgrade."), nil
}

// checkCinderInTreeMigration verifies nothing still depends on the in-tree
// Cinder volume plugin, which was removed from Kubernetes in 1.26.
//
// The removal did NOT take the CSI translation shim with it: legacy
// kubernetes.io/cinder StorageClasses and Cinder PV sources still translate to
// cinder.csi.openstack.org, provided that CSI driver is installed (verified
// 2026-07-21, see CLAUDE.md "OpenStack / cloud-provider-openstack"). So the
// evidenced breakage is conditional: with the driver registered these objects
// keep working through translation (warn - migrate deliberately); without it
// they cannot provision or mount at all (fail).
func checkCinderInTreeMigration(ctx context.Context, c *analyzer.Cluster, _ analyzer.Upgrade) (*analyzer.Result, error) {
	var affected []analyzer.AffectedResource

	scs, err := c.StorageClasses(ctx)
	if err != nil {
		return nil, err
	}
	for _, sc := range scs {
		if sc.Provisioner == "kubernetes.io/cinder" {
			affected = append(affected, analyzer.AffectedResource{
				Kind: "StorageClass", APIVersion: "storage.k8s.io/v1", Name: sc.Name,
				Detail: "uses the in-tree kubernetes.io/cinder provisioner, removed in 1.26",
			})
		}
	}

	pvs, err := c.PersistentVolumes(ctx)
	if err != nil {
		return nil, err
	}
	for _, pv := range pvs {
		if pv.Spec.Cinder != nil {
			affected = append(affected, analyzer.AffectedResource{
				Kind: "PersistentVolume", APIVersion: "v1", Name: pv.Name,
				Detail: "in-tree Cinder volume source, removed in 1.26",
			})
		}
	}

	pods, err := c.Pods(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range pods {
		for _, vol := range p.Spec.Volumes {
			if vol.Cinder != nil {
				affected = append(affected, analyzer.AffectedResource{
					Kind: "Pod", APIVersion: "v1", Namespace: p.Namespace, Name: p.Name,
					Detail: "inline in-tree Cinder volume " + vol.Name,
				})
			}
		}
	}

	if len(affected) == 0 {
		return analyzer.Pass("no in-tree Cinder volume usage; fully migrated to the CSI driver"), nil
	}

	drivers, err := c.CSIDrivers(ctx)
	if err != nil {
		return nil, err
	}
	driverInstalled := false
	for _, d := range drivers {
		if d.Name == "cinder.csi.openstack.org" {
			driverInstalled = true
			break
		}
	}

	if driverInstalled {
		return analyzer.Warn("%d object(s) still reference the in-tree Cinder plugin - they work "+
			"only through the CSI translation shim", len(affected)).
			WithResources(affected...).
			WithRemediation("Kubernetes removed the in-tree Cinder plugin in 1.26; these objects " +
				"keep working only because the CSI translation shim rewrites them to " +
				"cinder.csi.openstack.org, which is installed here. That dependency is invisible " +
				"in the objects themselves. Recreate the StorageClass with provisioner " +
				"cinder.csi.openstack.org and migrate the volumes so nothing rests on translation.").
			WithDocs("https://github.com/kubernetes/cloud-provider-openstack/blob/master/docs/cinder-csi-plugin/using-cinder-csi-plugin.md"), nil
	}
	return analyzer.Fail("%d object(s) use the in-tree Cinder plugin and the Cinder CSI driver "+
		"is not installed", len(affected)).
		WithResources(affected...).
		WithRemediation("The in-tree Cinder plugin was removed in Kubernetes 1.26, and translating " +
			"the legacy objects to CSI requires the cinder.csi.openstack.org driver, which is not " +
			"registered on this cluster. These objects cannot provision or mount volumes. Install " +
			"the Cinder CSI driver, recreate the StorageClass with provisioner " +
			"cinder.csi.openstack.org, and migrate the affected volumes.").
		WithDocs("https://github.com/kubernetes/cloud-provider-openstack/blob/master/docs/cinder-csi-plugin/using-cinder-csi-plugin.md"), nil
}

// checkCinderInlineEphemeral finds pods using inline CSI ephemeral volumes
// backed by the Cinder driver.
//
// cloud-provider-openstack removed CSI inline ephemeral volume support from
// cinder-csi in its v1.31 release. Pods declaring such a volume fail to start
// once the driver is upgraded - and the driver must be upgraded to track a
// newer Kubernetes. This is the most likely way an OpenStack cluster breaks
// during an otherwise routine upgrade.
func checkCinderInlineEphemeral(ctx context.Context, c *analyzer.Cluster, _ analyzer.Upgrade) (*analyzer.Result, error) {
	pods, err := c.Pods(ctx)
	if err != nil {
		return nil, err
	}

	var affected []analyzer.AffectedResource
	for _, p := range pods {
		for _, v := range p.Spec.Volumes {
			if v.CSI == nil || v.CSI.Driver != "cinder.csi.openstack.org" {
				continue
			}
			affected = append(affected, analyzer.AffectedResource{
				Kind: "Pod", APIVersion: "v1", Namespace: p.Namespace, Name: p.Name,
				Detail: "inline CSI ephemeral volume " + v.Name,
			})
		}
	}

	if len(affected) == 0 {
		return analyzer.Pass("no pods use inline CSI ephemeral Cinder volumes"), nil
	}
	return analyzer.Fail("%d pod(s) use inline CSI ephemeral Cinder volumes", len(affected)).
		WithResources(affected...).
		WithRemediation("cloud-provider-openstack removed inline CSI ephemeral volume support " +
			"from cinder-csi in v1.31. These pods will fail to start once the driver is upgraded, " +
			"which it must be to track a newer Kubernetes release. Convert each to a generic " +
			"ephemeral volume (spec.volumes[].ephemeral.volumeClaimTemplate) before upgrading.").
		WithDocs("https://github.com/kubernetes/cloud-provider-openstack/blob/master/docs/cinder-csi-plugin/using-cinder-csi-plugin.md"), nil
}

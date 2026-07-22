package analyzer

import (
	"context"
	"fmt"
	"strings"

	"github.com/Rusty-Gopher/kupre/pkg/deprecation"
)

// ReleaseChecks returns checks for non-API breaking changes: removed volume
// plugins, changed defaults, and deprecated component modes that do not show up
// as an API version disappearing.
func ReleaseChecks() []Check {
	return []Check{
		{
			Name:        "gitrepo-volumes",
			Description: "Pods using the gitRepo volume plugin, disabled without recourse in 1.36",
			Category:    CategoryWorkload,
			Severity:    SeverityError,
			Action:      ActionPlanAhead,
			Run:         checkGitRepoVolumes,
		},
		{
			Name:        "flexvolume-in-use",
			Description: "Workloads still using FlexVolume, which kubeadm stops supporting in 1.36",
			Category:    CategoryStorage,
			Severity:    SeverityWarning,
			Action:      ActionPlanAhead,
			Run:         checkFlexVolume,
		},
		{
			Name:        "service-external-ips",
			Description: "Services using the deprecated spec.externalIPs field",
			Category:    CategoryWorkload,
			Severity:    SeverityInfo,
			Action:      ActionReviewLater,
			Run:         checkServiceExternalIPs,
		},
		{
			Name:        "kube-proxy-mode",
			Description: "kube-proxy running in the deprecated ipvs mode",
			Category:    CategoryNode,
			Severity:    SeverityWarning,
			Action:      ActionPlanAhead,
			Run:         checkKubeProxyMode,
		},
		{
			Name:        "legacy-endpoints",
			Description: "Manually managed Endpoints objects, deprecated in favour of EndpointSlice",
			Category:    CategoryWorkload,
			Severity:    SeverityInfo,
			Action:      ActionReviewLater,
			Run:         checkLegacyEndpoints,
		},
		{
			Name:        "release-advisories",
			Description: "Breaking changes on the upgrade path that cannot be detected from the API",
			Category:    CategoryNode,
			Severity:    SeverityWarning,
			Action:      ActionVerifyManually,
			Run:         checkReleaseAdvisories,
		},
	}
}

// checkGitRepoVolumes finds pods using the gitRepo volume type.
//
// 1.36 disables the plugin with no feature gate to re-enable it, so affected
// pods fail to start outright. This is one of the few genuinely unrecoverable
// changes in the release.
func checkGitRepoVolumes(ctx context.Context, c *Cluster, up Upgrade) (*Result, error) {
	target := MustParseVersion("1.36")
	if !up.Crosses(target) {
		return Skip("upgrade does not cross 1.36, where gitRepo volumes are disabled"), nil
	}

	pods, err := c.Pods(ctx)
	if err != nil {
		return nil, err
	}

	var affected []AffectedResource
	for _, p := range pods {
		for _, v := range p.Spec.Volumes {
			if v.GitRepo != nil {
				affected = append(affected, AffectedResource{
					Kind: "Pod", APIVersion: "v1", Namespace: p.Namespace, Name: p.Name,
					Detail: fmt.Sprintf("gitRepo volume %q → %s", v.Name, v.GitRepo.Repository),
				})
			}
		}
	}

	if len(affected) == 0 {
		return Pass("no pods use the gitRepo volume plugin"), nil
	}
	sortResources(affected)
	return Fail("%d pod(s) use the gitRepo volume plugin, disabled in 1.36", len(affected)).
		WithResources(affected...).
		WithRemediation("1.36 disables gitRepo with no feature gate to turn it back on, so these " +
			"pods will fail to start after the upgrade. Replace each with an init container that " +
			"clones the repository into an emptyDir, or bake the content into the image.").
		WithDocs("https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.36.md"), nil
}

// checkFlexVolume finds FlexVolume usage across pods and persistent volumes.
func checkFlexVolume(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	pods, err := c.Pods(ctx)
	if err != nil {
		return nil, err
	}
	pvs, err := c.PersistentVolumes(ctx)
	if err != nil {
		return nil, err
	}

	var affected []AffectedResource
	for _, p := range pods {
		for _, v := range p.Spec.Volumes {
			if v.FlexVolume != nil {
				affected = append(affected, AffectedResource{
					Kind: "Pod", APIVersion: "v1", Namespace: p.Namespace, Name: p.Name,
					Detail: fmt.Sprintf("FlexVolume %q, driver %s", v.Name, v.FlexVolume.Driver),
				})
			}
		}
	}
	for _, pv := range pvs {
		if pv.Spec.FlexVolume != nil {
			affected = append(affected, AffectedResource{
				Kind: "PersistentVolume", APIVersion: "v1", Name: pv.Name,
				Detail: "FlexVolume driver " + pv.Spec.FlexVolume.Driver,
			})
		}
	}

	if len(affected) == 0 {
		return Pass("no FlexVolume usage found"), nil
	}
	sortResources(affected)
	return Warn("%d object(s) still use FlexVolume", len(affected)).
		WithResources(affected...).
		WithRemediation("FlexVolume is superseded by CSI, and from 1.36 kubeadm no longer " +
			"configures the plugin directory. Keeping FlexVolume working past that point needs a " +
			"custom non-distroless controller-manager image plus explicit --flex-volume-plugin-dir " +
			"and extraVolumes settings. Migrating these drivers to CSI is the durable fix.").
		WithDocs("https://kubernetes.io/docs/concepts/storage/volumes/#flexvolume-deprecated"), nil
}

// checkServiceExternalIPs finds Services using the deprecated externalIPs field.
func checkServiceExternalIPs(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	svcs, err := c.Services(ctx)
	if err != nil {
		return nil, err
	}

	var affected []AffectedResource
	for _, s := range svcs {
		if len(s.Spec.ExternalIPs) > 0 {
			affected = append(affected, AffectedResource{
				Kind: "Service", APIVersion: "v1", Namespace: s.Namespace, Name: s.Name,
				Detail: "externalIPs=" + strings.Join(s.Spec.ExternalIPs, ","),
			})
		}
	}

	if len(affected) == 0 {
		return Pass("no Services use the deprecated spec.externalIPs field"), nil
	}
	sortResources(affected)
	return Warn("%d Service(s) use the deprecated spec.externalIPs field", len(affected)).
		WithResources(affected...).
		WithRemediation("externalIPs is deprecated as of 1.36 and emits a warning. Nothing breaks " +
			"yet. Plan a migration to LoadBalancer or Ingress."), nil
}

// checkKubeProxyMode reads the kube-proxy ConfigMap to determine its proxy mode.
// ipvs was deprecated in 1.35 in favour of nftables.
func checkKubeProxyMode(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	cm, err := c.GetConfigMap(ctx, "kube-system", "kube-proxy")
	if err != nil {
		// Many distributions do not deploy kube-proxy this way, or at all.
		return Skip("kube-proxy ConfigMap not readable in kube-system; mode could not be determined"), nil
	}

	var mode string
	for _, v := range cm.Data {
		for _, line := range strings.Split(v, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "mode:") {
				mode = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "mode:")), `"'`)
			}
		}
	}

	switch mode {
	case "ipvs":
		return Warn("kube-proxy is running in the deprecated ipvs mode").
			WithResources(AffectedResource{
				Kind: "ConfigMap", APIVersion: "v1", Namespace: "kube-system", Name: "kube-proxy",
				Detail: "mode: ipvs",
			}).
			WithRemediation("ipvs mode was deprecated in 1.35 in favour of nftables. It still " +
				"works, but is on a removal path. Plan the migration; test it in a non-production " +
				"cluster first, since nftables changes how Service traffic is matched.").
			WithDocs("https://kubernetes.io/docs/reference/networking/virtual-ips/"), nil
	case "":
		return Skip("kube-proxy mode not set in the ConfigMap (using the platform default)"), nil
	default:
		return Pass("kube-proxy is running in %s mode", mode), nil
	}
}

// checkLegacyEndpoints finds Endpoints objects with no owning Service-managed
// EndpointSlice, i.e. manually maintained ones. The Endpoints API is deprecated
// as of 1.33 though upstream has committed to never removing it.
func checkLegacyEndpoints(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	epItems, err := c.Endpoints(ctx)
	if err != nil {
		return Skip("could not list Endpoints: %v", err), nil
	}

	// The endpoints controller creates and maintains an Endpoints object for
	// every Service that has a selector. Those are not "manually managed" and
	// flagging them would bury the real finding in noise. Only an Endpoints
	// whose Service has no selector - or which has no Service at all - was
	// written by hand or by an operator.
	svcs, err := c.Services(ctx)
	if err != nil {
		return nil, err
	}
	selectorManaged := make(map[string]bool, len(svcs))
	for _, s := range svcs {
		if len(s.Spec.Selector) > 0 {
			selectorManaged[s.Namespace+"/"+s.Name] = true
		}
	}

	var manual []AffectedResource
	for _, e := range epItems {
		if selectorManaged[e.Namespace+"/"+e.Name] || len(e.Subsets) == 0 {
			continue
		}
		addrs := 0
		for _, s := range e.Subsets {
			addrs += len(s.Addresses)
		}
		manual = append(manual, AffectedResource{
			Kind: "Endpoints", APIVersion: "v1", Namespace: e.Namespace, Name: e.Name,
			Detail: fmt.Sprintf("%d address(es) across %d subset(s), no Service selector",
				addrs, len(e.Subsets)),
		})
	}

	if len(manual) == 0 {
		return Pass("no manually managed Endpoints objects found"), nil
	}
	sortResources(manual)
	return Warn("%d Endpoints object(s) are manually managed", len(manual)).
		WithResources(manual...).
		WithRemediation("The Endpoints API was deprecated in 1.33 in favour of EndpointSlice. " +
			"Upstream has committed to never removing it, so this is not an upgrade blocker - but " +
			"new features land only on EndpointSlice, and Endpoints truncates at 1000 addresses.").
		WithDocs("https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/"), nil
}

// checkReleaseAdvisories surfaces breaking changes on the upgrade path that
// cannot be detected from the Kubernetes API - removed kubelet flags, changed
// component defaults, and metric renames. It always reports, because the whole
// point is that kupre cannot verify these for the operator.
func checkReleaseAdvisories(_ context.Context, _ *Cluster, up Upgrade) (*Result, error) {
	changes := deprecation.BreakingChangesBetween(up.From.MinorString(), up.To.MinorString())

	var advisories []AffectedResource
	for _, bc := range changes {
		if bc.Detectable {
			continue
		}
		advisories = append(advisories, AffectedResource{
			Kind:   "ReleaseNote",
			Name:   bc.ID,
			Detail: fmt.Sprintf("[%s] %s - %s", bc.ReleaseMinor, bc.Title, bc.Remediation),
		})
	}

	if len(advisories) == 0 {
		return Pass("no manual-review advisories between %s and %s",
			up.From.MinorString(), up.To.MinorString()), nil
	}
	return Warn("%d breaking change(s) on this upgrade path need manual verification", len(advisories)).
		WithResources(advisories...).
		WithRemediation("These changes affect node and control-plane configuration that is not " +
			"visible through the Kubernetes API, so kupre cannot check them for you. Each one has " +
			"caused real upgrade failures - review them against your node configuration and " +
			"component flags before proceeding.").
		WithDocs("https://kubernetes.io/releases/"), nil
}

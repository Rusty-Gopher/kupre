package analyzer

import (
	"context"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

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
			Name:        "ingress-nginx-retired",
			Description: "Use of the ingress-nginx controller, retired upstream in March 2026 with no further releases of any kind",
			Category:    CategoryWorkload,
			Severity:    SeverityWarning,
			Action:      ActionPlanAhead,
			Evidence: "Lists pods labelled app.kubernetes.io/name=ingress-nginx (the detection " +
				"signal the retirement statement itself uses), IngressClasses whose " +
				"spec.controller is k8s.io/ingress-nginx, and the Ingress objects served by " +
				"those classes or carrying the deprecated kubernetes.io/ingress.class: nginx " +
				"annotation.",
			Limits: "Cannot tell whether the deployed ingress-nginx build has known CVEs, and " +
				"cannot detect a renamed or unlabelled deployment - absence of the label is " +
				"not proof of absence. The Ingress list is blast radius (routes a migration " +
				"must cover), not a measurement of traffic.",
			Run: checkIngressNginxRetired,
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

// ingressNginxStatementURL is the joint Kubernetes Steering and Security
// Response Committee statement announcing the retirement.
const ingressNginxStatementURL = "https://kubernetes.io/blog/2026/01/29/ingress-nginx-statement/"

// checkIngressNginxRetired detects use of the ingress-nginx controller, which
// the Kubernetes project retired in March 2026. Not version-gated: the
// retirement is in the past, so this is about running retired software today.
//
// Evidence strongest first: controller pods carrying the label the statement's
// own detection command selects on, then IngressClasses bound to the
// k8s.io/ingress-nginx controller, then the Ingress objects those serve - the
// blast radius a migration has to cover.
func checkIngressNginxRetired(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	// A Forbidden list degrades that signal to "unknown", never to "absent".
	// Anything found in the remaining readable lists is still reported.
	var unreadable []string

	pods, err := c.Pods(ctx)
	switch {
	case err == nil:
	case apierrors.IsForbidden(err):
		unreadable = append(unreadable, "pods")
	default:
		return nil, err
	}

	classes, err := c.IngressClasses(ctx)
	switch {
	case err == nil:
	case apierrors.IsForbidden(err):
		unreadable = append(unreadable, "ingressclasses")
	default:
		return nil, err
	}

	ingresses, err := c.Ingresses(ctx)
	switch {
	case err == nil:
	case apierrors.IsForbidden(err):
		unreadable = append(unreadable, "ingresses")
	default:
		return nil, err
	}

	var controllers []AffectedResource
	for _, p := range pods {
		if p.Labels["app.kubernetes.io/name"] == "ingress-nginx" {
			controllers = append(controllers, AffectedResource{
				Kind: "Pod", APIVersion: "v1", Namespace: p.Namespace, Name: p.Name,
				Detail: "labelled app.kubernetes.io/name=ingress-nginx",
			})
		}
	}

	nginxClasses := map[string]bool{}
	var classResources []AffectedResource
	for _, ic := range classes {
		if ic.Spec.Controller == "k8s.io/ingress-nginx" {
			nginxClasses[ic.Name] = true
			classResources = append(classResources, AffectedResource{
				Kind: "IngressClass", APIVersion: "networking.k8s.io/v1", Name: ic.Name,
				Detail: "spec.controller=k8s.io/ingress-nginx",
			})
		}
	}

	var served []AffectedResource
	for _, ing := range ingresses {
		switch {
		case ing.Spec.IngressClassName != nil && nginxClasses[*ing.Spec.IngressClassName]:
			served = append(served, AffectedResource{
				Kind: "Ingress", APIVersion: "networking.k8s.io/v1",
				Namespace: ing.Namespace, Name: ing.Name,
				Detail: "spec.ingressClassName=" + *ing.Spec.IngressClassName,
			})
		case ing.Annotations["kubernetes.io/ingress.class"] == "nginx":
			served = append(served, AffectedResource{
				Kind: "Ingress", APIVersion: "networking.k8s.io/v1",
				Namespace: ing.Namespace, Name: ing.Name,
				Detail: "deprecated annotation kubernetes.io/ingress.class: nginx",
			})
		}
	}

	if len(controllers)+len(classResources)+len(served) == 0 {
		if len(unreadable) > 0 {
			return Skip("no ingress-nginx found in the readable lists, but no permission to list %s "+
				"- grant list on %s (see deploy/rbac.yaml) for a conclusive answer",
				strings.Join(unreadable, ", "), strings.Join(unreadable, ", ")), nil
		}
		return Pass("no ingress-nginx controller pods, IngressClasses, or served Ingresses found"), nil
	}

	sortResources(controllers)
	sortResources(classResources)
	sortResources(served)
	affected := append(append(controllers, classResources...), served...)

	return Warn("ingress-nginx is in use (%d controller pod(s), %d IngressClass(es), %d Ingress(es) served) - the project was retired in March 2026",
		len(controllers), len(classResources), len(served)).
		WithResources(affected...).
		WithRemediation("The Kubernetes project retired ingress-nginx in March 2026: \"There will " +
			"be no more releases for bug fixes, security patches, or any updates of any kind after " +
			"the project is retired.\" Existing deployments keep working, which is the trap - " +
			"\"unless you proactively check, you may not know you are affected until you are " +
			"compromised\" - and per the statement, \"choosing to remain with Ingress NGINX after " +
			"its retirement leaves you and your users vulnerable to attack.\" Migrate to a Gateway " +
			"API implementation or another actively maintained Ingress controller; the Ingress " +
			"objects listed above are the routes that migration has to cover.").
		WithCommands("kubectl get pods --all-namespaces --selector app.kubernetes.io/name=ingress-nginx").
		WithDocs(ingressNginxStatementURL), nil
}

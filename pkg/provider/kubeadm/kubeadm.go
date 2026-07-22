// Package kubeadm implements preflight checks for kubeadm-managed clusters.
//
// Detection and evidence both come from the kube-system/kubeadm-config
// ConfigMap, which holds the ClusterConfiguration that `kubeadm upgrade apply`
// itself reads - so validating it means validating the upgrade's actual input.
// Managed platforms (EKS, GKE, MetaKube, …) have no such ConfigMap and every
// check here skips cleanly.
package kubeadm

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
	"github.com/Rusty-Gopher/kupre/pkg/deprecation"
	"github.com/Rusty-Gopher/kupre/pkg/provider"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/yaml"
)

// Provider implements provider.Provider for kubeadm clusters.
type Provider struct{}

func init() { provider.Register(Provider{}) }

// Name returns the provider identifier.
func (Provider) Name() string { return "kubeadm" }

// clusterConfiguration is the subset of kubeadm's ClusterConfiguration kupre
// validates. extraArgs changed shape between config versions (v1beta3 map,
// v1beta4 list of name/value pairs); both are handled at extraction time.
type clusterConfiguration struct {
	KubernetesVersion string          `json:"kubernetesVersion"`
	FeatureGates      map[string]bool `json:"featureGates"`
	APIServer         componentConfig `json:"apiServer"`
	ControllerManager componentConfig `json:"controllerManager"`
	Scheduler         componentConfig `json:"scheduler"`
	DNS               struct {
		ImageTag string `json:"imageTag"`
	} `json:"dns"`
	Etcd struct {
		Local *struct {
			ImageTag string `json:"imageTag"`
		} `json:"local"`
		External *struct {
			Endpoints []string `json:"endpoints"`
		} `json:"external"`
	} `json:"etcd"`
}

// componentConfig carries a control-plane component's extra arguments in
// either config-version shape.
type componentConfig struct {
	ExtraArgs extraArgs `json:"extraArgs"`
}

// extraArgs unmarshals both the v1beta3 map form and the v1beta4 list form.
type extraArgs map[string]string

// UnmarshalJSON accepts {"k":"v"} and [{"name":"k","value":"v"}].
func (e *extraArgs) UnmarshalJSON(data []byte) error {
	*e = extraArgs{}
	var asMap map[string]string
	if err := yaml.Unmarshal(data, &asMap); err == nil {
		*e = asMap
		return nil
	}
	var asList []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	if err := yaml.Unmarshal(data, &asList); err != nil {
		return err
	}
	for _, a := range asList {
		(*e)[a.Name] = a.Value
	}
	return nil
}

// loadClusterConfiguration fetches and parses the kubeadm-config ConfigMap.
// The bool reports whether the cluster is a kubeadm cluster at all.
func loadClusterConfiguration(ctx context.Context, c *analyzer.Cluster) (*clusterConfiguration, bool, error) {
	cm, err := c.GetConfigMap(ctx, "kube-system", "kubeadm-config")
	if err != nil {
		if apierrors.IsNotFound(err) || apierrors.IsForbidden(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read kubeadm-config: %w", err)
	}
	raw, ok := cm.Data["ClusterConfiguration"]
	if !ok {
		return nil, false, nil
	}
	var cc clusterConfiguration
	if err := yaml.Unmarshal([]byte(raw), &cc); err != nil {
		return nil, true, fmt.Errorf("parse ClusterConfiguration: %w", err)
	}
	return &cc, true, nil
}

// Detect reports whether the cluster is kubeadm-managed.
func (Provider) Detect(ctx context.Context, c *analyzer.Cluster) (bool, error) {
	_, isKubeadm, err := loadClusterConfiguration(ctx, c)
	return isKubeadm, err
}

// Checks returns the kubeadm-specific checks.
func (Provider) Checks() []analyzer.Check {
	return []analyzer.Check{
		{
			Name:        "kubeadm-removed-feature-gates",
			Description: "ClusterConfiguration sets feature gates the target release removes",
			Category:    analyzer.CategoryNode,
			Severity:    analyzer.SeverityError,
			Action:      analyzer.ActionFixBeforeStart,
			Evidence: "Parses featureGates and per-component extraArgs feature-gates from the " +
				"kubeadm-config ConfigMap - the same input `kubeadm upgrade apply` consumes.",
			Limits: "Covers the gates recorded in kupre's release database for the upgrade " +
				"path, currently 1.35–1.36. Gates set only in node-local files (kubelet " +
				"flags, drop-ins) are invisible to the API.",
			Run: checkRemovedFeatureGates,
		},
		{
			Name:        "kubeadm-pinned-component-versions",
			Description: "Pinned CoreDNS or etcd image tags that will fight the target release",
			Category:    analyzer.CategoryNode,
			Severity:    analyzer.SeverityWarning,
			Action:      analyzer.ActionPlanAhead,
			Evidence: "Compares dns.imageTag and etcd.local.imageTag pins in ClusterConfiguration " +
				"against the versions the target kubeadm release expects (from kubeadm's own " +
				"pinned constants).",
			Limits: "Unpinned components are managed by kubeadm itself and are not judged. " +
				"External etcd version cannot be probed read-only; only its configuration is " +
				"visible. Expected-version data is a snapshot covering 1.35–1.36.",
			Run: checkPinnedComponentVersions,
		},
	}
}

// checkRemovedFeatureGates validates the config's feature gates against the
// gates removed on the upgrade path.
func checkRemovedFeatureGates(ctx context.Context, c *analyzer.Cluster, up analyzer.Upgrade) (*analyzer.Result, error) {
	cc, isKubeadm, err := loadClusterConfiguration(ctx, c)
	if err != nil {
		return nil, err
	}
	if !isKubeadm {
		return analyzer.Skip("not a kubeadm cluster (no kubeadm-config ConfigMap)"), nil
	}

	removed := deprecation.FeatureGatesRemovedBetween(up.From.MinorString(), up.To.MinorString())
	if len(removed) == 0 {
		if deprecation.BeyondHorizon(up.To.MinorString()) {
			return analyzer.Warn("no feature-gate removal data for Kubernetes %s - could not draw a conclusion",
				up.To.MinorString()).
				WithRemediation("%s", deprecation.HorizonNote(up.To.MinorString())), nil
		}
		return analyzer.Pass("no feature gates are removed between %s and %s",
			up.From.MinorString(), up.To.MinorString()), nil
	}
	removedByName := map[string]deprecation.RemovedFeatureGate{}
	for _, g := range removed {
		removedByName[g.Name] = g
	}

	var hits []analyzer.AffectedResource
	report := func(where, gate string, g deprecation.RemovedFeatureGate) {
		hits = append(hits, analyzer.AffectedResource{
			Kind: "ConfigMap", APIVersion: "v1", Namespace: "kube-system", Name: "kubeadm-config",
			Detail: fmt.Sprintf("%s sets %s, removed in %s - the component will refuse to start",
				where, gate, g.RemovedIn),
		})
	}
	for gate := range cc.FeatureGates {
		if g, hit := removedByName[gate]; hit {
			report("featureGates", gate, g)
		}
	}
	components := map[string]componentConfig{
		"apiServer": cc.APIServer, "controllerManager": cc.ControllerManager, "scheduler": cc.Scheduler,
	}
	for name, comp := range components {
		for _, gate := range parseFeatureGatesArg(comp.ExtraArgs["feature-gates"]) {
			if g, hit := removedByName[gate]; hit {
				report(name+".extraArgs.feature-gates", gate, g)
			}
		}
	}

	if len(hits) == 0 {
		return analyzer.Pass("ClusterConfiguration sets none of the %d feature gate(s) removed by %s",
			len(removed), up.To.MinorString()), nil
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Detail < hits[j].Detail })
	return analyzer.Fail("ClusterConfiguration sets %d feature gate(s) that %s removes", len(hits), up.To.MinorString()).
		WithResources(hits...).
		WithRemediation("A component started with a removed feature gate exits immediately, and " +
			"during `kubeadm upgrade apply` that means a control-plane component that never " +
			"comes back. Remove these gates from the kubeadm-config ConfigMap (kubectl edit is " +
			"outside kupre's remit - it never writes) and from any node-local drop-ins before " +
			"upgrading."), nil
}

// parseFeatureGatesArg splits a --feature-gates=A=true,B=false value into gate names.
func parseFeatureGatesArg(v string) []string {
	if v == "" {
		return nil
	}
	var out []string
	for _, pair := range strings.Split(v, ",") {
		name, _, _ := strings.Cut(strings.TrimSpace(pair), "=")
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

// checkPinnedComponentVersions compares explicit CoreDNS/etcd pins against the
// target release's expectations.
func checkPinnedComponentVersions(ctx context.Context, c *analyzer.Cluster, up analyzer.Upgrade) (*analyzer.Result, error) {
	cc, isKubeadm, err := loadClusterConfiguration(ctx, c)
	if err != nil {
		return nil, err
	}
	if !isKubeadm {
		return analyzer.Skip("not a kubeadm cluster (no kubeadm-config ConfigMap)"), nil
	}

	expected, known := deprecation.ComponentsFor(up.To.MinorString())
	if !known {
		return analyzer.Warn("no component-version data for Kubernetes %s - pinned versions could not be judged",
			up.To.MinorString()).
			WithRemediation("%s", deprecation.HorizonNote(up.To.MinorString())), nil
	}

	var findings []analyzer.AffectedResource
	if tag := cc.DNS.ImageTag; tag != "" && tag != expected.CoreDNSVersion {
		findings = append(findings, analyzer.AffectedResource{
			Kind: "ConfigMap", APIVersion: "v1", Namespace: "kube-system", Name: "kubeadm-config",
			Detail: fmt.Sprintf("dns.imageTag pins CoreDNS %s; kubeadm %s expects %s and its "+
				"Corefile migration targets that version", tag, up.To.MinorString(), expected.CoreDNSVersion),
		})
	}
	if cc.Etcd.Local != nil {
		if tag := cc.Etcd.Local.ImageTag; tag != "" && tag != expected.EtcdVersion {
			findings = append(findings, analyzer.AffectedResource{
				Kind: "ConfigMap", APIVersion: "v1", Namespace: "kube-system", Name: "kubeadm-config",
				Detail: fmt.Sprintf("etcd.local.imageTag pins %s; kubeadm %s defaults to %s",
					tag, up.To.MinorString(), expected.EtcdVersion),
			})
		}
	}
	if cc.Etcd.External != nil {
		findings = append(findings, analyzer.AffectedResource{
			Kind: "ConfigMap", APIVersion: "v1", Namespace: "kube-system", Name: "kubeadm-config",
			Detail: fmt.Sprintf("external etcd at %s - kubeadm %s requires etcd ≥ %s, which kupre "+
				"cannot verify read-only; confirm before upgrading",
				strings.Join(cc.Etcd.External.Endpoints, ", "), up.To.MinorString(), expected.MinExternalEtcdVersion),
		})
	}

	if len(findings) == 0 {
		return analyzer.Pass("no component pins conflict with kubeadm %s (CoreDNS %s, etcd %s)",
			up.To.MinorString(), expected.CoreDNSVersion, expected.EtcdVersion), nil
	}
	return analyzer.Warn("%d component pin(s) need review before upgrading to %s",
		len(findings), up.To.MinorString()).
		WithResources(findings...).
		WithRemediation("An explicit imageTag freezes a component kubeadm would otherwise upgrade " +
			"and migrate. Either remove the pin so kubeadm manages the version, or verify the " +
			"pinned version is compatible with the target release and its config migration."), nil
}

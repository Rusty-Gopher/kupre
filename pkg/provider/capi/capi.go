// Package capi implements upgrade preflight checks for clusters whose nodes
// are managed by Cluster API-style machine controllers: upstream Cluster API
// (cluster.x-k8s.io) and the Kubermatic/MetaKube machine-controller
// (cluster.k8s.io).
//
// On these clusters a Kubernetes upgrade is a rolling machine replacement, so
// the questions that matter are about the rollout machinery itself: how many
// spare machines the strategy needs, and whether a blocked eviction stalls the
// rollout or hangs it forever.
package capi

import (
	"context"
	"fmt"
	"strings"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
	"github.com/Rusty-Gopher/kupre/pkg/provider"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Provider implements provider.Provider for CAPI-family clusters.
type Provider struct{}

func init() { provider.Register(Provider{}) }

// Name returns the provider identifier.
func (Provider) Name() string { return "cluster-api" }

// machineDeploymentGVRs lists the group/versions machine deployments live
// under, newest first. Only the first one the cluster serves is used.
var machineDeploymentGVRs = []schema.GroupVersionResource{
	{Group: "cluster.x-k8s.io", Version: "v1beta2", Resource: "machinedeployments"},
	{Group: "cluster.x-k8s.io", Version: "v1beta1", Resource: "machinedeployments"},
	{Group: "cluster.k8s.io", Version: "v1alpha1", Resource: "machinedeployments"},
}

// machineGVRs mirrors machineDeploymentGVRs for Machine objects.
var machineGVRs = []schema.GroupVersionResource{
	{Group: "cluster.x-k8s.io", Version: "v1beta2", Resource: "machines"},
	{Group: "cluster.x-k8s.io", Version: "v1beta1", Resource: "machines"},
	{Group: "cluster.k8s.io", Version: "v1alpha1", Resource: "machines"},
}

// Detect reports whether the cluster serves a machine API.
func (Provider) Detect(ctx context.Context, c *analyzer.Cluster) (bool, error) {
	for _, gvr := range machineDeploymentGVRs {
		ok, err := c.Serves(ctx, gvr)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// Checks returns the machine-rollout checks.
func (Provider) Checks() []analyzer.Check {
	return []analyzer.Check{
		{
			Name:        "capi-rollout-strategy",
			Description: "Machine rollout strategy and the spare capacity it requires",
			Category:    analyzer.CategoryCloud,
			Severity:    analyzer.SeverityInfo,
			Action:      analyzer.ActionVerifyManually,
			Evidence:    "Reads maxSurge/maxUnavailable from every MachineDeployment's rollout strategy.",
			Limits: "States what the strategy will demand; it cannot verify the infrastructure " +
				"can supply it - cloud quota and capacity are outside a read-only Kubernetes " +
				"client. Control-plane machines on managed platforms are not visible.",
			Run: checkRolloutStrategy,
		},
		{
			Name:        "capi-drain-hang",
			Description: "Blocked evictions hang machine replacement forever when no drain timeout is set",
			Category:    analyzer.CategoryCloud,
			Severity:    analyzer.SeverityError,
			Action:      analyzer.ActionFixBeforeStart,
			Evidence: "Joins the machine API's nodeDrainTimeout configuration with the live " +
				"PodDisruptionBudget state. Cluster API retries a blocked eviction every 20s " +
				"with no deadline unless nodeDrainTimeout is set.",
			Limits: "The cluster.k8s.io (Kubermatic machine-controller) API does not expose a " +
				"drain timeout field, so on those clusters only the PDB half of the join is " +
				"evidence; the controller's own drain behavior is not visible.",
			Run: checkDrainHang,
		},
		{
			Name:        "capi-machines-consistent",
			Description: "Every machine is phase-healthy and bound to a node",
			Category:    analyzer.CategoryCloud,
			Severity:    analyzer.SeverityWarning,
			Action:      analyzer.ActionResolveFirst,
			Evidence:    "Compares Machine objects (phase, nodeRef) against the cluster's nodes.",
			Limits: "A machine controller mid-reconcile shows transient mismatches; findings " +
				"here are a snapshot, worth re-checking before acting.",
			Run: checkMachinesConsistent,
		},
	}
}

// listFirstServed returns the items of the first GVR the cluster serves.
func listFirstServed(ctx context.Context, c *analyzer.Cluster, gvrs []schema.GroupVersionResource) ([]unstructured.Unstructured, schema.GroupVersionResource, error) {
	for _, gvr := range gvrs {
		ok, err := c.Serves(ctx, gvr)
		if err != nil || !ok {
			continue
		}
		items, err := c.ListGVR(ctx, gvr)
		if err != nil {
			return nil, gvr, err
		}
		return items, gvr, nil
	}
	return nil, schema.GroupVersionResource{}, nil
}

// rolloutStrategy is the strategy shape shared by all the machine APIs.
type rolloutStrategy struct {
	Type           string
	MaxSurge       string
	MaxUnavailable string
	// DrainTimeoutSeconds is nil when the field is absent from the API group,
	// which is different from being set to zero.
	DrainTimeoutSeconds *int64
}

// strategyOf extracts the rollout strategy from a MachineDeployment of any of
// the supported API shapes: cluster.x-k8s.io/v1beta2 nests it under
// spec.rollout.strategy, the older groups under spec.strategy.
func strategyOf(md unstructured.Unstructured) rolloutStrategy {
	s := rolloutStrategy{Type: "RollingUpdate", MaxSurge: "1", MaxUnavailable: "0"}

	paths := [][]string{
		{"spec", "rollout", "strategy"},
		{"spec", "strategy"},
	}
	for _, p := range paths {
		raw, found, _ := unstructured.NestedMap(md.Object, p...)
		if !found {
			continue
		}
		if t, ok := raw["type"].(string); ok {
			s.Type = t
		}
		if ru, ok := raw["rollingUpdate"].(map[string]any); ok {
			s.MaxSurge = intOrString(ru["maxSurge"], s.MaxSurge)
			s.MaxUnavailable = intOrString(ru["maxUnavailable"], s.MaxUnavailable)
		}
		break
	}

	// Drain timeout moved around between versions; nil means not exposed.
	for _, p := range [][]string{
		{"spec", "template", "spec", "deletion", "nodeDrainTimeoutSeconds"}, // v1beta2
		{"spec", "template", "spec", "nodeDrainTimeoutSeconds"},
		{"spec", "template", "spec", "nodeDrainTimeout"}, // v1beta1 metav1.Duration (seconds as int when set via JSON? handled as int64 only)
	} {
		if v, found, _ := unstructured.NestedInt64(md.Object, p...); found {
			s.DrainTimeoutSeconds = &v
			break
		}
	}
	return s
}

// intOrString renders Kubernetes intstr values from unstructured data.
func intOrString(v any, fallback string) string {
	switch t := v.(type) {
	case int64:
		return fmt.Sprintf("%d", t)
	case float64:
		return fmt.Sprintf("%d", int64(t))
	case string:
		return t
	default:
		return fallback
	}
}

// checkRolloutStrategy states what the machine rollout will demand of the
// infrastructure, per MachineDeployment.
func checkRolloutStrategy(ctx context.Context, c *analyzer.Cluster, _ analyzer.Upgrade) (*analyzer.Result, error) {
	mds, gvr, err := listFirstServed(ctx, c, machineDeploymentGVRs)
	if err != nil {
		return nil, err
	}
	if len(mds) == 0 {
		return analyzer.Skip("no MachineDeployments found"), nil
	}

	var notes []analyzer.AffectedResource
	surging := 0
	for _, md := range mds {
		s := strategyOf(md)
		replicas, _, _ := unstructured.NestedInt64(md.Object, "spec", "replicas")
		detail := fmt.Sprintf("replicas=%d %s maxSurge=%s maxUnavailable=%s",
			replicas, s.Type, s.MaxSurge, s.MaxUnavailable)
		if s.MaxSurge != "0" && s.MaxSurge != "0%" {
			surging++
			detail += fmt.Sprintf(" - rollout creates up to %s extra machine(s); the cloud "+
				"project needs quota and capacity for them", s.MaxSurge)
		} else if s.MaxUnavailable != "0" && s.MaxUnavailable != "0%" {
			detail += fmt.Sprintf(" - scale-down-first: capacity dips by up to %s machine(s) "+
				"during rollout", s.MaxUnavailable)
		}
		notes = append(notes, analyzer.AffectedResource{
			Kind: "MachineDeployment", APIVersion: gvr.GroupVersion().String(),
			Namespace: md.GetNamespace(), Name: md.GetName(),
			Detail: detail,
		})
	}

	if surging == 0 {
		return analyzer.Pass("machine rollout needs no extra capacity (no surge configured)").
			WithResources(notes...), nil
	}
	return analyzer.Warn("%d MachineDeployment(s) surge during rollout - verify cloud quota headroom",
		surging).
		WithResources(notes...).
		WithRemediation("kupre cannot read cloud quotas. Before the window, confirm the project " +
			"has instance, CPU, RAM, volume and floating-IP headroom for the surge machines " +
			"listed above; a quota rejection mid-rollout strands the upgrade half-done."), nil
}

// checkDrainHang joins drain-timeout configuration with live PDB state.
func checkDrainHang(ctx context.Context, c *analyzer.Cluster, _ analyzer.Upgrade) (*analyzer.Result, error) {
	mds, gvr, err := listFirstServed(ctx, c, machineDeploymentGVRs)
	if err != nil {
		return nil, err
	}
	if len(mds) == 0 {
		return analyzer.Skip("no MachineDeployments found"), nil
	}

	pdbs, err := c.PodDisruptionBudgets(ctx)
	if err != nil {
		return nil, err
	}
	blockedPDBs := 0
	for _, p := range pdbs {
		if p.Status.ExpectedPods > 0 && p.Status.DisruptionsAllowed == 0 {
			blockedPDBs++
		}
	}

	legacyGroup := gvr.Group == "cluster.k8s.io"
	var unbounded []analyzer.AffectedResource
	for _, md := range mds {
		s := strategyOf(md)
		if s.DrainTimeoutSeconds == nil || *s.DrainTimeoutSeconds == 0 {
			detail := "no nodeDrainTimeout - a blocked eviction is retried forever"
			if legacyGroup {
				detail = "drain timeout not exposed by cluster.k8s.io; assume evictions are retried indefinitely"
			}
			unbounded = append(unbounded, analyzer.AffectedResource{
				Kind: "MachineDeployment", APIVersion: gvr.GroupVersion().String(),
				Namespace: md.GetNamespace(), Name: md.GetName(),
				Detail: detail,
			})
		}
	}

	switch {
	case len(unbounded) > 0 && blockedPDBs > 0:
		sortCapi(unbounded)
		return analyzer.Fail("%d PDB(s) permit zero evictions and %d MachineDeployment(s) have no "+
			"drain deadline - machine replacement will hang indefinitely, not just stall",
			blockedPDBs, len(unbounded)).
			WithResources(unbounded...).
			WithRemediation("The machine controller retries blocked evictions forever without a " +
				"drain timeout, so the first affected node parks the whole rollout. Fix the " +
				"blocking PDBs (see pdb-blocks-drain for the exact commands), or set a " +
				"nodeDrainTimeout as a backstop - noting that a timeout means pods are killed " +
				"rather than evicted when it fires.").
			WithDocs("https://cluster-api.sigs.k8s.io/tasks/automated-machine-management/machine_deletions"), nil
	case len(unbounded) > 0:
		sortCapi(unbounded)
		return analyzer.Warn("%d MachineDeployment(s) have no drain deadline (no PDB currently blocks, "+
			"but any that starts blocking mid-rollout hangs it)", len(unbounded)).
			WithResources(unbounded...).
			WithRemediation("Consider a nodeDrainTimeout as a backstop against PDBs that tighten " +
				"during the rollout - e.g. a single-replica workload whose pod lands on the next " +
				"node to drain."), nil
	default:
		return analyzer.Pass("every MachineDeployment bounds its node drain with a timeout"), nil
	}
}

// checkMachinesConsistent verifies machine/node bookkeeping.
func checkMachinesConsistent(ctx context.Context, c *analyzer.Cluster, _ analyzer.Upgrade) (*analyzer.Result, error) {
	machines, gvr, err := listFirstServed(ctx, c, machineGVRs)
	if err != nil {
		return nil, err
	}
	if len(machines) == 0 {
		return analyzer.Skip("no Machine objects found"), nil
	}

	var issues []analyzer.AffectedResource
	for _, m := range machines {
		phase, _, _ := unstructured.NestedString(m.Object, "status", "phase")
		nodeRef, refFound, _ := unstructured.NestedString(m.Object, "status", "nodeRef", "name")

		var problems []string
		if phase != "" && phase != "Running" && phase != "Provisioned" {
			problems = append(problems, "phase="+phase)
		}
		if !refFound || nodeRef == "" {
			problems = append(problems, "no nodeRef - machine exists but is not backing a node")
		}
		if m.GetDeletionTimestamp() != nil {
			problems = append(problems, "deleting")
		}
		if len(problems) > 0 {
			issues = append(issues, analyzer.AffectedResource{
				Kind: "Machine", APIVersion: gvr.GroupVersion().String(),
				Namespace: m.GetNamespace(), Name: m.GetName(),
				Detail: strings.Join(problems, "; "),
			})
		}
	}

	if len(issues) == 0 {
		return analyzer.Pass("all %d machine(s) are running and bound to nodes", len(machines)), nil
	}
	sortCapi(issues)
	return analyzer.Warn("%d of %d machine(s) are unhealthy or unbound", len(issues), len(machines)).
		WithResources(issues...).
		WithRemediation("A rolling upgrade waits on the machine controller to replace machines " +
			"cleanly. Machines already stuck provisioning, failed, or half-deleted will confuse " +
			"that process and are much easier to diagnose before the rollout than during it."), nil
}

// sortCapi orders resources by namespace/name for stable output.
func sortCapi(rs []analyzer.AffectedResource) {
	for i := 1; i < len(rs); i++ {
		for j := i; j > 0; j-- {
			a, b := rs[j-1], rs[j]
			if a.Namespace < b.Namespace || (a.Namespace == b.Namespace && a.Name <= b.Name) {
				break
			}
			rs[j-1], rs[j] = b, a
		}
	}
}

package analyzer

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// maxKubeletSkew is the number of minor versions a kubelet may lag behind the
// control plane. Kubernetes has supported n-3 since 1.28.
const maxKubeletSkew = 3

// NodeChecks returns checks covering node-level upgrade readiness.
func NodeChecks() []Check {
	return []Check{
		{
			Name:        "node-ready",
			Description: "All nodes are Ready and schedulable",
			Category:    CategoryNode,
			Severity:    SeverityError,
			Action:      ActionFixBeforeStart,
			Run:         checkNodesReady,
		},
		{
			Name:        "kubelet-version-skew",
			Description: "Kubelet versions stay within the supported skew of the target control plane",
			Category:    CategoryNode,
			Severity:    SeverityError,
			Action:      ActionPlanAhead,
			Run:         checkKubeletSkew,
		},
		{
			Name:        "node-pressure",
			Description: "Nodes are free of memory, disk, and PID pressure",
			Category:    CategoryNode,
			Severity:    SeverityWarning,
			Action:      ActionResolveFirst,
			Run:         checkNodePressure,
		},
		{
			Name:        "container-runtime",
			Description: "Container runtimes are checked against the few versions known to be unusable",
			Evidence:    "Parses each node's reported containerRuntimeVersion.",
			Limits: "Only recognises dockershim-era Docker and containerd older than 1.6. " +
				"CRI-O is not evaluated at all, and no runtime is verified against the target " +
				"release's actual CRI requirements. Passing means nothing known-bad was found, " +
				"not that the runtime is confirmed supported.",
			Category: CategoryNode,
			Severity: SeverityWarning,
			Action:   ActionPlanAhead,
			Run:      checkContainerRuntime,
		},
		mixedRuntimeCheck(),
		{
			Name:        "schedulable-node-count",
			Description: "More than one node is schedulable, so a drain has somewhere to move pods",
			Evidence:    "Counts nodes that are Ready, uncordoned and free of NoSchedule/NoExecute taints.",
			Limits: "A node count is not a capacity model. This does not evaluate allocatable " +
				"CPU or memory, pod resource requests, affinity or topology constraints, " +
				"local volumes, or whether any specific pod can actually be rescheduled. " +
				"Passing means a drain has somewhere to try, not that it will succeed.",
			Category: CategoryNode,
			Severity: SeverityWarning,
			Action:   ActionResolveFirst,
			Run:      checkSchedulableNodeCount,
		},
	}
}

// checkNodesReady verifies every node is Ready and not cordoned.
func checkNodesReady(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	nodes, err := c.Nodes(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("cluster reports zero nodes")
	}

	var bad []AffectedResource
	for _, n := range nodes {
		var problems []string
		if !isNodeReady(n) {
			problems = append(problems, "not Ready")
		}
		if n.Spec.Unschedulable {
			problems = append(problems, "cordoned")
		}
		if len(problems) > 0 {
			bad = append(bad, AffectedResource{
				Kind: "Node", APIVersion: "v1", Name: n.Name,
				Detail: strings.Join(problems, ", "),
			})
		}
	}

	if len(bad) == 0 {
		return Pass("all %d node(s) are Ready and schedulable", len(nodes)), nil
	}
	sortResources(bad)
	return Fail("%d of %d node(s) are not ready for upgrade", len(bad), len(nodes)).
		WithResources(bad...).
		WithRemediation("A rolling upgrade replaces nodes one at a time and waits for each to " +
			"become Ready. Starting with an unhealthy or cordoned node will stall the rollout. " +
			"Restore these nodes, or remove them from the cluster."), nil
}

// isNodeReady reports whether the node's Ready condition is True.
func isNodeReady(n corev1.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// checkKubeletSkew verifies that after the control plane moves to the target
// version, every kubelet remains within the supported version skew.
//
// Kubernetes supports kubelets up to three minor versions older than the API
// server. A kubelet outside that window is unsupported and may fail to register
// or misbehave, so the nodes must be upgraded first or alongside.
func checkKubeletSkew(ctx context.Context, c *Cluster, up Upgrade) (*Result, error) {
	nodes, err := c.Nodes(ctx)
	if err != nil {
		return nil, err
	}

	var (
		tooOld  []AffectedResource
		tooNew  []AffectedResource
		unknown []AffectedResource
	)
	for _, n := range nodes {
		kv, err := ParseVersion(n.Status.NodeInfo.KubeletVersion)
		if err != nil {
			unknown = append(unknown, AffectedResource{
				Kind: "Node", APIVersion: "v1", Name: n.Name,
				Detail: "unparseable kubelet version " + n.Status.NodeInfo.KubeletVersion,
			})
			continue
		}
		skew := kv.MinorDistance(up.To)
		switch {
		case skew > maxKubeletSkew:
			tooOld = append(tooOld, AffectedResource{
				Kind: "Node", APIVersion: "v1", Name: n.Name,
				Detail: fmt.Sprintf("kubelet %s is %d minor versions behind target %s (max %d)",
					kv.String(), skew, up.To.MinorString(), maxKubeletSkew),
			})
		case skew < 0:
			tooNew = append(tooNew, AffectedResource{
				Kind: "Node", APIVersion: "v1", Name: n.Name,
				Detail: fmt.Sprintf("kubelet %s is newer than target control plane %s",
					kv.String(), up.To.MinorString()),
			})
		}
	}

	if bad := append(append(tooOld, tooNew...), unknown...); len(bad) > 0 {
		sortResources(bad)
		res := Fail("%d of %d node(s) violate the kubelet version skew policy for %s",
			len(bad), len(nodes), up.To.MinorString()).WithResources(bad...)
		return res.WithRemediation(
			"Kubernetes supports kubelets at most %d minor versions older than the API server, "+
				"and never newer. Upgrade these nodes' kubelets before, or as part of, moving the "+
				"control plane to %s.", maxKubeletSkew, up.To.MinorString()).
			WithDocs("https://kubernetes.io/releases/version-skew-policy/"), nil
	}

	return Pass("all %d kubelet(s) remain within the supported %d-minor skew of %s",
		len(nodes), maxKubeletSkew, up.To.MinorString()), nil
}

// checkNodePressure looks for nodes reporting resource pressure. Draining moves
// pods onto the remaining nodes, so pre-existing pressure tends to become
// eviction storms mid-upgrade.
func checkNodePressure(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	nodes, err := c.Nodes(ctx)
	if err != nil {
		return nil, err
	}

	pressureTypes := []corev1.NodeConditionType{
		corev1.NodeMemoryPressure,
		corev1.NodeDiskPressure,
		corev1.NodePIDPressure,
		corev1.NodeNetworkUnavailable,
	}

	var bad []AffectedResource
	for _, n := range nodes {
		var active []string
		for _, cond := range n.Status.Conditions {
			for _, pt := range pressureTypes {
				if cond.Type == pt && cond.Status == corev1.ConditionTrue {
					active = append(active, string(pt))
				}
			}
		}
		if len(active) > 0 {
			bad = append(bad, AffectedResource{
				Kind: "Node", APIVersion: "v1", Name: n.Name,
				Detail: strings.Join(active, ", "),
			})
		}
	}

	if len(bad) == 0 {
		return Pass("no pressure conditions on any of %d node(s)", len(nodes)), nil
	}
	sortResources(bad)
	return Warn("%d of %d node(s) report resource pressure", len(bad), len(nodes)).
		WithResources(bad...).
		WithRemediation("Draining concentrates pods onto the remaining nodes. Nodes already " +
			"under pressure are likely to start evicting once more pods land on them. Free resources or " +
			"add capacity first."), nil
}

// checkContainerRuntime reports the container runtimes in use. Very old
// containerd and any remaining dockershim-era runtime are worth flagging.
func checkContainerRuntime(ctx context.Context, c *Cluster, up Upgrade) (*Result, error) {
	nodes, err := c.Nodes(ctx)
	if err != nil {
		return nil, err
	}

	runtimes := map[string][]string{}
	for _, n := range nodes {
		runtimes[n.Status.NodeInfo.ContainerRuntimeVersion] = append(
			runtimes[n.Status.NodeInfo.ContainerRuntimeVersion], n.Name)
	}

	var flagged []AffectedResource
	for rt, names := range runtimes {
		reason := runtimeConcern(rt)
		if reason == "" {
			continue
		}
		for _, name := range names {
			flagged = append(flagged, AffectedResource{
				Kind: "Node", APIVersion: "v1", Name: name,
				Detail: fmt.Sprintf("%s - %s", rt, reason),
			})
		}
	}

	if len(flagged) == 0 {
		var seen []string
		for rt := range runtimes {
			seen = append(seen, rt)
		}
		return Pass("no known-unusable container runtime found (checked for dockershim and "+
			"containerd <1.6 only): %s", strings.Join(seen, ", ")), nil
	}
	sortResources(flagged)
	return Warn("%d node(s) run a container runtime worth reviewing before upgrading", len(flagged)).
		WithResources(flagged...).
		WithRemediation("Confirm the runtime version is supported by the target Kubernetes " +
			"release and supports the CRI features it requires."), nil
}

// runtimeConcern returns a reason string if the runtime version warrants
// attention, or "" if it looks fine.
func runtimeConcern(rt string) string {
	name, ver, ok := strings.Cut(rt, "://")
	if !ok {
		return "unrecognized runtime string"
	}
	switch name {
	case "docker":
		return "dockershim was removed in Kubernetes 1.24; migrate to containerd or CRI-O"
	case "containerd":
		v, err := ParseVersion(ver)
		if err != nil {
			return ""
		}
		// containerd 1.x before 1.6 lacks the CRI features modern kubelets use.
		if v.Major == 1 && v.Minor < 6 {
			return "containerd < 1.6 is end-of-life and lacks required CRI features"
		}
	case "cri-o":
		// CRI-O tracks Kubernetes minor versions; a very old one is a concern,
		// but the correct pairing is release-specific, so stay quiet here.
		return ""
	}
	return ""
}

// checkSchedulableNodeCount verifies more than one node is schedulable, so a
// drain has somewhere to move pods to.
//
// This is deliberately a node count and nothing more. Modelling whether a given
// pod can actually reschedule would require evaluating allocatable resources,
// requests, affinity, topology spread, taints and local volumes - the result
// message and Limits say so rather than implying the work was done.
func checkSchedulableNodeCount(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	nodes, err := c.Nodes(ctx)
	if err != nil {
		return nil, err
	}

	schedulable := 0
	for _, n := range nodes {
		if isNodeReady(n) && !n.Spec.Unschedulable && !hasNoScheduleTaint(n) {
			schedulable++
		}
	}

	if schedulable < 2 {
		return Warn("only %d schedulable node(s); draining one leaves nowhere to move its pods", schedulable).
			WithRemediation("A rolling upgrade needs at least one other schedulable node to take " +
				"the pods from the node being drained. With fewer than two the upgrade will " +
				"cause downtime. Add capacity, or plan for an outage window."), nil
	}
	return Pass("%d node(s) are schedulable (node count only - capacity and constraints not evaluated)",
		schedulable), nil
}

// hasNoScheduleTaint reports whether the node carries a NoSchedule or
// NoExecute taint, which keeps ordinary workloads off it.
func hasNoScheduleTaint(n corev1.Node) bool {
	for _, t := range n.Spec.Taints {
		if t.Effect == corev1.TaintEffectNoSchedule || t.Effect == corev1.TaintEffectNoExecute {
			return true
		}
	}
	return false
}

// mixedRuntimeCheck returns the runtime-consistency check declaration.
func mixedRuntimeCheck() Check {
	return Check{
		Name:        "mixed-container-runtimes",
		Description: "All nodes run the same container runtime and version",
		Category:    CategoryNode,
		Severity:    SeverityWarning,
		Action:      ActionResolveFirst,
		Evidence:    "Compares the reported containerRuntimeVersion string across all nodes.",
		Limits: "String equality only. Cannot tell an in-progress, intentional runtime " +
			"migration from configuration drift - that distinction belongs to the operator.",
		Run: checkMixedRuntimes,
	}
}

// checkMixedRuntimes flags node pools running divergent runtimes. A rolling
// upgrade replaces nodes from a template; drift means some nodes were built
// differently, and the upgrade will silently converge them - or fail on the
// odd ones out.
func checkMixedRuntimes(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	nodes, err := c.Nodes(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodes) < 2 {
		return Skip("fewer than two nodes; runtime consistency does not apply"), nil
	}

	byRuntime := map[string][]string{}
	for _, n := range nodes {
		rt := n.Status.NodeInfo.ContainerRuntimeVersion
		byRuntime[rt] = append(byRuntime[rt], n.Name)
	}
	if len(byRuntime) == 1 {
		for rt := range byRuntime {
			return Pass("all %d node(s) run %s", len(nodes), rt), nil
		}
	}

	var mixed []AffectedResource
	for rt, names := range byRuntime {
		mixed = append(mixed, AffectedResource{
			Kind: "Node", APIVersion: "v1", Name: strings.Join(names, ", "),
			Detail: rt,
		})
	}
	sortResources(mixed)
	return Warn("nodes run %d different container runtime versions", len(byRuntime)).
		WithResources(mixed...).
		WithRemediation("A rolling upgrade rebuilds nodes from one template, so divergent " +
			"runtimes mean either drift that the upgrade will change out from under workloads, " +
			"or an unfinished migration worth completing first. Confirm which before starting."), nil
}

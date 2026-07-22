package openstack

import (
	"context"
	"strings"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
	corev1 "k8s.io/api/core/v1"
)

// ccmChecks returns the OpenStack cloud-controller-manager preflight checks.
func ccmChecks() []analyzer.Check {
	return []analyzer.Check{
		{
			Name:        "openstack-external-ccm",
			Description: "Cluster uses the external OpenStack cloud controller manager",
			Category:    analyzer.CategoryCloud,
			Severity:    analyzer.SeverityError,
			Action:      analyzer.ActionPlanAhead,
			Run:         checkExternalCCM,
		},
		{
			Name:        "openstack-node-provider-id",
			Description: "Every node has an OpenStack provider ID assigned by the CCM",
			Category:    analyzer.CategoryCloud,
			Severity:    analyzer.SeverityWarning,
			Action:      analyzer.ActionResolveFirst,
			Run:         checkNodeProviderIDs,
		},
	}
}

// checkExternalCCM verifies the cluster is not relying on the in-tree OpenStack
// cloud provider, which was removed from kube-controller-manager in 1.26.
//
// The reliable in-cluster signal is the node.cloudprovider.kubernetes.io/uninitialized
// taint lifecycle: nodes initialized by an external CCM carry a provider ID and
// topology labels. A node stuck with the uninitialized taint means no CCM is
// running at all.
func checkExternalCCM(ctx context.Context, c *analyzer.Cluster, _ analyzer.Upgrade) (*analyzer.Result, error) {
	nodes, err := c.Nodes(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return analyzer.Skip("no nodes to inspect"), nil
	}

	const uninitializedTaint = "node.cloudprovider.kubernetes.io/uninitialized"

	var stuck []analyzer.AffectedResource
	for _, n := range nodes {
		for _, t := range n.Spec.Taints {
			if t.Key == uninitializedTaint {
				stuck = append(stuck, analyzer.AffectedResource{
					Kind: "Node", APIVersion: "v1", Name: n.Name,
					Detail: "still carries the " + uninitializedTaint + " taint",
				})
			}
		}
	}

	if len(stuck) > 0 {
		return analyzer.Fail("%d node(s) have not been initialized by a cloud controller manager", len(stuck)).
			WithResources(stuck...).
			WithRemediation("Nodes keep the uninitialized taint until a cloud controller manager " +
				"claims them, and no ordinary workload will schedule there. The in-tree OpenStack " +
				"provider was removed in Kubernetes 1.26, so an external " +
				"openstack-cloud-controller-manager must be running. Deploy it before upgrading.").
			WithDocs("https://github.com/kubernetes/cloud-provider-openstack/blob/master/docs/openstack-cloud-controller-manager/using-openstack-cloud-controller-manager.md"), nil
	}

	// A managed control plane runs the CCM outside the workload cluster, so its
	// absence from the pod list is expected and not a failure.
	comps, err := findComponents(ctx, c)
	if err != nil {
		return nil, err
	}
	for _, comp := range comps {
		if strings.Contains(comp.Image, "openstack-cloud-control") {
			return analyzer.Pass("external OpenStack cloud controller manager running in-cluster (%s/%s)",
				comp.Namespace, comp.Name), nil
		}
	}

	return analyzer.Pass("all %d node(s) are cloud-initialized; the CCM runs outside this cluster "+
		"(typical for a managed control plane)", len(nodes)), nil
}

// checkNodeProviderIDs verifies each node carries an OpenStack provider ID and
// the topology labels the CSI driver relies on for volume scheduling.
func checkNodeProviderIDs(ctx context.Context, c *analyzer.Cluster, _ analyzer.Upgrade) (*analyzer.Result, error) {
	nodes, err := c.Nodes(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return analyzer.Skip("no nodes to inspect"), nil
	}

	var issues []analyzer.AffectedResource
	for _, n := range nodes {
		var problems []string
		switch {
		case n.Spec.ProviderID == "":
			problems = append(problems, "no providerID set")
		case !strings.HasPrefix(n.Spec.ProviderID, "openstack://"):
			problems = append(problems, "providerID is not an openstack:// URI: "+n.Spec.ProviderID)
		}
		if n.Labels[corev1.LabelTopologyZone] == "" {
			problems = append(problems, "missing "+corev1.LabelTopologyZone+" label")
		}
		if len(problems) > 0 {
			issues = append(issues, analyzer.AffectedResource{
				Kind: "Node", APIVersion: "v1", Name: n.Name,
				Detail: strings.Join(problems, "; "),
			})
		}
	}

	if len(issues) == 0 {
		return analyzer.Pass("all %d node(s) have an OpenStack provider ID and topology zone label", len(nodes)), nil
	}
	return analyzer.Warn("%d of %d node(s) are missing cloud provider metadata", len(issues), len(nodes)).
		WithResources(issues...).
		WithRemediation("The Cinder CSI driver uses the provider ID to map a node to its Nova " +
			"instance, and the topology zone label to place volumes in the right availability " +
			"zone. Missing either causes volume attach failures when pods reschedule during the " +
			"upgrade drain."), nil
}

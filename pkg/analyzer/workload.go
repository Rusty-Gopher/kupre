package analyzer

import (
	"context"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// WorkloadChecks returns checks covering workload-level upgrade readiness:
// whether nodes can actually be drained and rescheduled during a rolling
// upgrade. These are the failures that make an upgrade hang rather than break.
func WorkloadChecks() []Check {
	return []Check{
		{
			Name:        "pdb-blocks-drain",
			Description: "PodDisruptionBudgets that currently permit zero voluntary evictions",
			Category:    CategoryWorkload,
			Severity:    SeverityError,
			Action:      ActionFixBeforeStart,
			Run:         checkPDBBlocksDrain,
		},
		{
			Name:        "pdb-unhealthy",
			Description: "PodDisruptionBudgets whose selector matches no pods or that are unsatisfied",
			Category:    CategoryWorkload,
			Severity:    SeverityWarning,
			Action:      ActionResolveFirst,
			Run:         checkPDBHealth,
		},
		{
			Name:        "single-replica-workloads",
			Description: "Single-replica workloads that will incur downtime when their node is drained",
			Category:    CategoryWorkload,
			Severity:    SeverityWarning,
			Action:      ActionReviewLater,
			Run:         checkSingleReplica,
		},
		{
			Name:        "pods-not-ready",
			Description: "Pods that are not running or not ready before the upgrade starts",
			Category:    CategoryWorkload,
			Severity:    SeverityWarning,
			Action:      ActionResolveFirst,
			Run:         checkPodsNotReady,
		},
	}
}

// checkPDBBlocksDrain finds PDBs that allow zero disruptions right now.
//
// A node drain evicts pods via the eviction API, which honours PDBs. A PDB
// reporting DisruptionsAllowed=0 will reject every eviction of its pods, so the
// drain blocks indefinitely and the rolling upgrade stalls on that node. This is
// the single most common cause of a stuck Kubernetes upgrade.
func checkPDBBlocksDrain(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	pdbs, err := c.PodDisruptionBudgets(ctx)
	if err != nil {
		return nil, err
	}
	if len(pdbs) == 0 {
		return Skip("no PodDisruptionBudgets defined"), nil
	}

	var blocked []AffectedResource
	var blockedPDBs []policyv1.PodDisruptionBudget
	for _, p := range pdbs {
		// A PDB that has never been processed has no useful status; the
		// pdb-unhealthy check reports those separately.
		if p.Status.ObservedGeneration == 0 && p.Status.ExpectedPods == 0 {
			continue
		}
		if p.Status.DisruptionsAllowed > 0 {
			continue
		}
		// Zero expected pods means the PDB matches nothing, which cannot block
		// a drain. That case is a hygiene problem, not a drain blocker.
		if p.Status.ExpectedPods == 0 {
			continue
		}
		blocked = append(blocked, AffectedResource{
			Kind:       "PodDisruptionBudget",
			APIVersion: "policy/v1",
			Namespace:  p.Namespace,
			Name:       p.Name,
			Detail: fmt.Sprintf("%s, healthy %d/%d, disruptionsAllowed=0",
				pdbConstraint(p), p.Status.CurrentHealthy, p.Status.ExpectedPods),
		})
		blockedPDBs = append(blockedPDBs, p)
	}

	if len(blocked) == 0 {
		return Pass("all %d PodDisruptionBudget(s) currently permit at least one eviction", len(pdbs)), nil
	}

	sortResources(blocked)
	res := Fail("%d PodDisruptionBudget(s) allow zero disruptions and will block node drain", len(blocked)).
		WithResources(blocked...).
		WithRemediation(
			"Node drain evicts pods through the eviction API, which these PDBs will reject, " +
				"so the rolling upgrade will hang on the first affected node. Give each guarded " +
				"workload one more replica than its budget requires, so at least one eviction " +
				"is permitted.").
		WithDocs("https://kubernetes.io/docs/tasks/run-application/configure-pdb/")

	// Turn each blocking PDB into the exact command that unblocks it. Emitted
	// only where the owning workload was resolved from the PDB's selector.
	if cmds := scaleCommandsFor(ctx, c, blockedPDBs); len(cmds) > 0 {
		res = res.WithCommands(cmds...)
	} else {
		res = res.WithCommands("kubectl get pdb -A -o wide")
	}
	return res, nil
}

// scaleCommandsFor resolves each PDB to the Deployments and StatefulSets its
// selector matches, and returns a scale command taking each one replica above
// the budget's requirement.
//
// A PDB's name frequently matches its workload's name, but that is convention,
// not guarantee. Matching on the selector is the only correct way to do this,
// and anything that cannot be resolved is omitted rather than guessed - an
// operator will paste whatever command we print.
func scaleCommandsFor(ctx context.Context, c *Cluster, pdbs []policyv1.PodDisruptionBudget) []string {
	deploys, err := c.Deployments(ctx)
	if err != nil {
		return nil
	}
	stss, err := c.StatefulSets(ctx)
	if err != nil {
		return nil
	}

	var cmds []string
	for _, p := range pdbs {
		sel, err := metav1.LabelSelectorAsSelector(p.Spec.Selector)
		if err != nil || sel.Empty() {
			continue
		}
		want := p.Status.DesiredHealthy + 1

		// A budget can sit at zero for two different reasons, and they need
		// opposite fixes. If every matched pod is healthy, the workload simply
		// does not have enough replicas and scaling up helps. If some pods are
		// unhealthy, the replica count is already sufficient and scaling is a
		// no-op - the pods themselves have to be repaired. Emitting a scale
		// command in that second case would be confidently wrong.
		if p.Status.CurrentHealthy < p.Status.ExpectedPods {
			cmds = append(cmds, fmt.Sprintf(
				"kubectl get pods -n %s -l %s   # %d/%d healthy - repair these, do not scale",
				p.Namespace, sel.String(), p.Status.CurrentHealthy, p.Status.ExpectedPods))
			continue
		}

		for _, d := range deploys {
			if d.Namespace != p.Namespace || !sel.Matches(labels.Set(d.Spec.Template.Labels)) {
				continue
			}
			if d.Spec.Replicas != nil && *d.Spec.Replicas >= want {
				continue // already large enough; scaling would change nothing
			}
			cmds = append(cmds, fmt.Sprintf(
				"kubectl scale deployment/%s -n %s --replicas=%d", d.Name, d.Namespace, want))
		}
		for _, st := range stss {
			if st.Namespace != p.Namespace || !sel.Matches(labels.Set(st.Spec.Template.Labels)) {
				continue
			}
			if st.Spec.Replicas != nil && *st.Spec.Replicas >= want {
				continue
			}
			cmds = append(cmds, fmt.Sprintf(
				"kubectl scale statefulset/%s -n %s --replicas=%d", st.Name, st.Namespace, want))
		}
	}
	sort.Strings(cmds)
	return dedupeStrings(cmds)
}

// dedupeStrings removes duplicates from a sorted slice.
func dedupeStrings(in []string) []string {
	out := in[:0]
	var last string
	for i, s := range in {
		if i == 0 || s != last {
			out = append(out, s)
		}
		last = s
	}
	return out
}

// pdbConstraint renders a PDB's configured constraint for display.
func pdbConstraint(p policyv1.PodDisruptionBudget) string {
	switch {
	case p.Spec.MinAvailable != nil:
		return "minAvailable=" + p.Spec.MinAvailable.String()
	case p.Spec.MaxUnavailable != nil:
		return "maxUnavailable=" + p.Spec.MaxUnavailable.String()
	default:
		return "no constraint set"
	}
}

// checkPDBHealth finds PDBs that are misconfigured rather than merely tight:
// ones matching no pods at all, or whose healthy count is below the requirement.
func checkPDBHealth(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	pdbs, err := c.PodDisruptionBudgets(ctx)
	if err != nil {
		return nil, err
	}
	if len(pdbs) == 0 {
		return Skip("no PodDisruptionBudgets defined"), nil
	}

	var issues []AffectedResource
	for _, p := range pdbs {
		var detail string
		switch {
		case p.Status.ExpectedPods == 0:
			detail = "selector matches no pods - stale PDB"
		case p.Status.CurrentHealthy < p.Status.DesiredHealthy:
			detail = fmt.Sprintf("only %d/%d pods healthy, below desired %d",
				p.Status.CurrentHealthy, p.Status.ExpectedPods, p.Status.DesiredHealthy)
		default:
			continue
		}
		issues = append(issues, AffectedResource{
			Kind:       "PodDisruptionBudget",
			APIVersion: "policy/v1",
			Namespace:  p.Namespace,
			Name:       p.Name,
			Detail:     detail,
		})
	}

	if len(issues) == 0 {
		return Pass("all %d PodDisruptionBudget(s) are satisfied and match live pods", len(pdbs)), nil
	}
	sortResources(issues)
	return Warn("%d PodDisruptionBudget(s) are stale or unsatisfied", len(issues)).
		WithResources(issues...).
		WithRemediation("A PDB matching no pods is usually left over from a removed workload and " +
			"can be deleted. An unsatisfied PDB means the workload is already degraded - resolve " +
			"that before adding upgrade churn."), nil
}

// checkSingleReplica finds replicated workloads running exactly one replica.
// Draining their node means downtime for that service, since there is no second
// replica to serve traffic while the pod reschedules.
func checkSingleReplica(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	deploys, err := c.Deployments(ctx)
	if err != nil {
		return nil, err
	}
	stss, err := c.StatefulSets(ctx)
	if err != nil {
		return nil, err
	}

	var single []AffectedResource
	for _, d := range deploys {
		if d.Spec.Replicas != nil && *d.Spec.Replicas == 1 {
			single = append(single, AffectedResource{
				Kind: "Deployment", APIVersion: "apps/v1",
				Namespace: d.Namespace, Name: d.Name,
				Detail: "replicas=1",
			})
		}
	}
	for _, s := range stss {
		if s.Spec.Replicas != nil && *s.Spec.Replicas == 1 {
			single = append(single, AffectedResource{
				Kind: "StatefulSet", APIVersion: "apps/v1",
				Namespace: s.Namespace, Name: s.Name,
				Detail: "replicas=1",
			})
		}
	}

	total := len(deploys) + len(stss)
	if len(single) == 0 {
		return Pass("no single-replica Deployments or StatefulSets among %d workload(s)", total), nil
	}
	sortResources(single)
	return Warn("%d of %d workload(s) run a single replica and will have downtime during drain", len(single), total).
		WithResources(single...).
		WithRemediation("Each of these becomes unavailable while its node drains and the pod " +
			"reschedules. Scale to 2+ replicas with anti-affinity for the duration of the upgrade, " +
			"or accept and schedule the downtime."), nil
}

// checkPodsNotReady finds pods that are already unhealthy. Starting an upgrade
// on a cluster with pre-existing failures makes it very hard to tell whether a
// later failure was caused by the upgrade.
func checkPodsNotReady(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	pods, err := c.Pods(ctx)
	if err != nil {
		return nil, err
	}
	if len(pods) == 0 {
		return Skip("no pods found"), nil
	}

	var bad []AffectedResource
	for _, p := range pods {
		// Completed pods from Jobs and CronJobs are expected terminal states.
		if p.Status.Phase == corev1.PodSucceeded {
			continue
		}
		if reason := unhealthyReason(p); reason != "" {
			bad = append(bad, AffectedResource{
				Kind: "Pod", APIVersion: "v1",
				Namespace: p.Namespace, Name: p.Name,
				Detail: reason,
			})
		}
	}

	if len(bad) == 0 {
		return Pass("all %d pod(s) are running and ready", len(pods)), nil
	}
	sortResources(bad)
	return Warn("%d of %d pod(s) are not ready before the upgrade", len(bad), len(pods)).
		WithResources(bad...).
		WithRemediation("Resolve pre-existing pod failures first. Upgrading a cluster that is " +
			"already degraded makes it ambiguous whether later failures were caused by the upgrade."), nil
}

// unhealthyReason returns a short description of why a pod is unhealthy, or ""
// if it is healthy.
func unhealthyReason(p corev1.Pod) string {
	if p.Status.Phase == corev1.PodFailed {
		return "phase=Failed"
	}
	if p.DeletionTimestamp != nil {
		return "terminating"
	}

	// Surface container-level wait reasons first: they name the actual problem
	// (ImagePullBackOff, CrashLoopBackOff) rather than just "not ready".
	for _, cs := range p.Status.ContainerStatuses {
		if w := cs.State.Waiting; w != nil && w.Reason != "" && w.Reason != "ContainerCreating" {
			return fmt.Sprintf("container %s: %s", cs.Name, w.Reason)
		}
		if cs.RestartCount > 20 {
			return fmt.Sprintf("container %s: %d restarts", cs.Name, cs.RestartCount)
		}
	}

	if p.Status.Phase == corev1.PodPending {
		return "phase=Pending"
	}
	for _, cond := range p.Status.Conditions {
		if cond.Type == corev1.PodReady && cond.Status != corev1.ConditionTrue {
			if cond.Reason != "" {
				return "not ready: " + cond.Reason
			}
			return "not ready"
		}
	}
	return ""
}

// sortResources orders affected resources by namespace then name for stable
// report output.
func sortResources(rs []AffectedResource) {
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].Namespace != rs[j].Namespace {
			return rs[i].Namespace < rs[j].Namespace
		}
		return rs[i].Name < rs[j].Name
	})
}

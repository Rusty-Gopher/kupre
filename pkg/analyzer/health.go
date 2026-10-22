package analyzer

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// HealthChecks returns the health mission's suite: what is wrong with the
// cluster right now, and why. Roughly half is reused from the upgrade suite
// (a broken cluster is broken in both contexts); the health-specific checks
// focus on naming causes rather than listing symptoms.
func HealthChecks() []Check {
	out := []Check{
		{
			Name:        "pod-failure-causes",
			Description: "Unhealthy pods, with the reason the cluster itself gives for each",
			Category:    CategoryWorkload,
			Severity:    SeverityError,
			Action:      ActionFixBeforeStart,
			Evidence: "Joins every not-ready pod to its container states and to the warning " +
				"events the kubelet and controllers emitted for it, and reports the most " +
				"specific cause found: missing secret or configmap, image pull failure, " +
				"failed mount, OOM kill, crash loop.",
			Limits: "Events expire (typically after 1h), so long-broken pods may have lost " +
				"their explanatory event; those fall back to container state. Causes are " +
				"as reported by the cluster, not re-diagnosed.",
			Run: checkPodFailureCauses,
		},
		{
			Name:        "pending-pods-explained",
			Description: "Pods stuck Pending, with the scheduler's own explanation",
			Category:    CategoryWorkload,
			Severity:    SeverityError,
			Action:      ActionFixBeforeStart,
			Evidence: "Reads the PodScheduled condition the scheduler writes onto every pod " +
				"it cannot place - its literal reasoning, e.g. \"0/3 nodes are available: " +
				"3 Insufficient memory\".",
			Limits: "Explains scheduling failures only. A Pending pod that was never seen " +
				"by a scheduler (e.g. no matching scheduler name) has no condition to read.",
			Run: checkPendingPodsExplained,
		},
		{
			Name:        "oom-killed-containers",
			Description: "Containers the kernel recently killed for exceeding memory limits",
			Category:    CategoryWorkload,
			Severity:    SeverityWarning,
			Action:      ActionResolveFirst,
			Evidence: "Reads each container's lastState for a terminated/OOMKilled record, " +
				"which the kubelet retains from the previous restart.",
			Limits: "Only the most recent restart is retained, so a container that was " +
				"OOM-killed twice ago shows clean. Frequency requires metrics history " +
				"kupre does not have.",
			Run: checkOOMKilled,
		},
		{
			Name:        "rollouts-stuck",
			Description: "Deployments and StatefulSets that are not at their desired state",
			Category:    CategoryWorkload,
			Severity:    SeverityWarning,
			Action:      ActionResolveFirst,
			Evidence: "Compares desired vs ready replicas and reads the Progressing condition, " +
				"including ProgressDeadlineExceeded.",
			Limits: "A rollout mid-flight looks identical to a stuck one for its first " +
				"minutes; findings here are a snapshot.",
			Run: checkRolloutsStuck,
		},
		{
			Name:        "node-utilization",
			Description: "Nodes running hot on memory or CPU right now",
			Category:    CategoryNode,
			Severity:    SeverityWarning,
			Action:      ActionResolveFirst,
			Evidence: "Reads live usage from the metrics API (metrics-server) and compares " +
				"it against each node's allocatable resources.",
			Limits: "A single point-in-time sample: spikes and troughs are invisible, and " +
				"absence of metrics-server skips the check. This is a smoke alarm, not " +
				"capacity planning.",
			Run: checkNodeUtilization,
		},
		{
			Name:        "missing-resource-requests",
			Description: "Containers with no CPU or memory requests",
			Category:    CategoryWorkload,
			Severity:    SeverityWarning,
			Action:      ActionReviewLater,
			Evidence:    "Reads resource requests from every Deployment, StatefulSet and DaemonSet pod template.",
			Limits: "Absence of requests is the finding; what the right values would be " +
				"requires usage history kupre does not keep.",
			Run: checkMissingRequests,
		},
		{
			Name:        "failed-jobs",
			Description: "Jobs that exhausted their retries and failed",
			Category:    CategoryWorkload,
			Severity:    SeverityWarning,
			Action:      ActionResolveFirst,
			Evidence:    "Reads the Failed condition and failure counts from every Job.",
			Limits:      "CronJob-owned Jobs are aged out by history limits; only retained Jobs are visible.",
			Run:         checkFailedJobs,
		},
	}

	// Shared with the upgrade suite: a broken cluster is broken in any mission.
	reused := map[string]bool{
		"node-ready": true, "node-pressure": true, "mixed-container-runtimes": true,
		"schedulable-node-count": true, "pdb-unhealthy": true, "unhealthy-pvs": true,
		"apiservice-availability": true, "webhook-backend-fragility": true,
		"trust-bundle-expiry": true, "apiserver-cert-expiry": true,
		// Retired software is a present-tense security exposure, not just an
		// upgrade concern: no more security patches of any kind ship for it.
		"ingress-nginx-retired": true,
		// Running an unpatched release is a present-tense exposure too.
		"kubernetes-version-support": true,
		"cert-manager-compatibility": true,
	}
	for _, c := range AllChecks() {
		if reused[c.Name] {
			out = append(out, c)
		}
	}
	return out
}

// podEventIndex groups warning events by involved object namespace/name.
func podEventIndex(events []corev1.Event) map[string][]corev1.Event {
	idx := map[string][]corev1.Event{}
	for _, e := range events {
		if e.Type != corev1.EventTypeWarning || e.InvolvedObject.Kind != "Pod" {
			continue
		}
		key := e.InvolvedObject.Namespace + "/" + e.InvolvedObject.Name
		idx[key] = append(idx[key], e)
	}
	return idx
}

// bestCause picks the most specific cause available for an unhealthy pod:
// a warning event message beats a container wait reason beats the bare phase.
func bestCause(p corev1.Pod, events []corev1.Event) string {
	// Prefer the newest event with a concrete message.
	var newest *corev1.Event
	for i := range events {
		e := &events[i]
		if newest == nil || e.LastTimestamp.After(newest.LastTimestamp.Time) {
			newest = e
		}
	}
	if newest != nil && newest.Message != "" {
		return fmt.Sprintf("%s: %s", newest.Reason, strings.TrimSpace(newest.Message))
	}
	if reason := unhealthyReason(p); reason != "" {
		return reason
	}
	return "phase=" + string(p.Status.Phase)
}

// checkPodFailureCauses reports each unhealthy pod with its cause.
func checkPodFailureCauses(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	pods, err := c.Pods(ctx)
	if err != nil {
		return nil, err
	}
	events, err := c.Events(ctx)
	if err != nil {
		// The join degrades to container-state causes; say so rather than fail.
		events = nil
	}
	idx := podEventIndex(events)

	var causes []AffectedResource
	for _, p := range pods {
		if p.Status.Phase == corev1.PodSucceeded {
			continue
		}
		if unhealthyReason(p) == "" {
			continue
		}
		causes = append(causes, AffectedResource{
			Kind: "Pod", APIVersion: "v1", Namespace: p.Namespace, Name: p.Name,
			Detail: truncateDetail(bestCause(p, idx[p.Namespace+"/"+p.Name]), 160),
		})
	}

	if len(causes) == 0 {
		return Pass("every pod is running and ready (%d checked)", len(pods)), nil
	}
	sortResources(causes)
	return Fail("%d pod(s) are unhealthy - causes as reported by the cluster", len(causes)).
		WithResources(causes...).
		WithRemediation("Each line is the cluster's own explanation, not a guess: missing " +
			"secrets and service accounts need creating, image errors need registry or tag " +
			"fixes, OOM kills need higher limits or smaller workloads. Fix the cause, then " +
			"delete the pod if its controller does not recover it."), nil
}

// checkPendingPodsExplained surfaces the scheduler's own message per Pending pod.
func checkPendingPodsExplained(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	pods, err := c.Pods(ctx)
	if err != nil {
		return nil, err
	}

	var pending []AffectedResource
	for _, p := range pods {
		if p.Status.Phase != corev1.PodPending {
			continue
		}
		msg := ""
		for _, cond := range p.Status.Conditions {
			if cond.Type == corev1.PodScheduled && cond.Status != corev1.ConditionTrue {
				msg = cond.Message
			}
		}
		if msg == "" {
			continue // pending for a non-scheduling reason; pod-failure-causes covers it
		}
		pending = append(pending, AffectedResource{
			Kind: "Pod", APIVersion: "v1", Namespace: p.Namespace, Name: p.Name,
			Detail: truncateDetail(msg, 180),
		})
	}

	if len(pending) == 0 {
		return Pass("no pods are stuck waiting for the scheduler"), nil
	}
	sortResources(pending)
	return Fail("%d pod(s) cannot be scheduled - the scheduler's reasons attached", len(pending)).
		WithResources(pending...).
		WithRemediation("The message is the scheduler's literal verdict. \"Insufficient " +
			"cpu/memory\" means add capacity or lower requests; taint messages mean add a " +
			"toleration or remove the taint; affinity messages mean the placement rules " +
			"cannot be satisfied with the current nodes."), nil
}

// checkOOMKilled reports containers whose previous termination was an OOM kill.
func checkOOMKilled(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	pods, err := c.Pods(ctx)
	if err != nil {
		return nil, err
	}

	var oom []AffectedResource
	for _, p := range pods {
		for _, cs := range p.Status.ContainerStatuses {
			t := cs.LastTerminationState.Terminated
			if t == nil || t.Reason != "OOMKilled" {
				continue
			}
			oom = append(oom, AffectedResource{
				Kind: "Pod", APIVersion: "v1", Namespace: p.Namespace, Name: p.Name,
				Detail: fmt.Sprintf("container %s OOM-killed at %s (restart #%d)",
					cs.Name, t.FinishedAt.Format("2006-01-02 15:04"), cs.RestartCount),
			})
		}
	}

	if len(oom) == 0 {
		return Pass("no container's most recent restart was an OOM kill"), nil
	}
	sortResources(oom)
	return Warn("%d container(s) were OOM-killed on their last restart", len(oom)).
		WithResources(oom...).
		WithRemediation("The kernel killed these for exceeding their memory limit. Raise the " +
			"limit if the usage is legitimate, or find the leak if it is not - repeated OOM " +
			"kills usually oscillate between crash loop and degraded service."), nil
}

// checkRolloutsStuck reports workloads below their desired replica state.
func checkRolloutsStuck(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	deploys, err := c.Deployments(ctx)
	if err != nil {
		return nil, err
	}
	stss, err := c.StatefulSets(ctx)
	if err != nil {
		return nil, err
	}

	var stuck []AffectedResource
	for _, d := range deploys {
		want := int32(1)
		if d.Spec.Replicas != nil {
			want = *d.Spec.Replicas
		}
		deadline := false
		for _, cond := range d.Status.Conditions {
			if cond.Type == "Progressing" && cond.Reason == "ProgressDeadlineExceeded" {
				deadline = true
			}
		}
		if d.Status.ReadyReplicas < want || deadline {
			detail := fmt.Sprintf("%d/%d replicas ready", d.Status.ReadyReplicas, want)
			if deadline {
				detail += " - progress deadline exceeded"
			}
			stuck = append(stuck, AffectedResource{
				Kind: "Deployment", APIVersion: "apps/v1",
				Namespace: d.Namespace, Name: d.Name, Detail: detail,
			})
		}
	}
	for _, s := range stss {
		want := int32(1)
		if s.Spec.Replicas != nil {
			want = *s.Spec.Replicas
		}
		if s.Status.ReadyReplicas < want {
			stuck = append(stuck, AffectedResource{
				Kind: "StatefulSet", APIVersion: "apps/v1",
				Namespace: s.Namespace, Name: s.Name,
				Detail: fmt.Sprintf("%d/%d replicas ready", s.Status.ReadyReplicas, want),
			})
		}
	}

	if len(stuck) == 0 {
		return Pass("all %d Deployment(s)/StatefulSet(s) are at their desired state",
			len(deploys)+len(stss)), nil
	}
	sortResources(stuck)
	return Warn("%d workload(s) are below their desired state", len(stuck)).
		WithResources(stuck...).
		WithRemediation("Cross-reference with pod-failure-causes: a workload below desired " +
			"state almost always has its reason listed there, per pod."), nil
}

// checkNodeUtilization flags nodes hot on memory or CPU using metrics-server.
func checkNodeUtilization(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	metrics, err := c.NodeMetrics(ctx)
	if err != nil || len(metrics) == 0 {
		return Skip("no metrics API available (metrics-server not installed or not readable)"), nil
	}
	nodes, err := c.Nodes(ctx)
	if err != nil {
		return nil, err
	}
	allocatable := map[string]corev1.ResourceList{}
	for _, n := range nodes {
		allocatable[n.Name] = n.Status.Allocatable
	}

	const memWarn, cpuWarn = 85, 90
	var hot []AffectedResource
	for _, m := range metrics {
		name := m.GetName()
		usage, ok, _ := unstructured.NestedStringMap(m.Object, "usage")
		if !ok {
			continue
		}
		alloc, ok := allocatable[name]
		if !ok {
			continue
		}
		memAlloc := alloc[corev1.ResourceMemory]
		cpuAlloc := alloc[corev1.ResourceCPU]
		memPct := resourcePercent(usage["memory"], memAlloc.String())
		cpuPct := resourcePercent(usage["cpu"], cpuAlloc.String())
		var over []string
		if memPct >= memWarn {
			over = append(over, fmt.Sprintf("memory %d%%", memPct))
		}
		if cpuPct >= cpuWarn {
			over = append(over, fmt.Sprintf("cpu %d%%", cpuPct))
		}
		if len(over) > 0 {
			hot = append(hot, AffectedResource{
				Kind: "Node", APIVersion: "v1", Name: name,
				Detail: strings.Join(over, ", ") + " of allocatable in use right now",
			})
		}
	}

	if len(hot) == 0 {
		return Pass("no node above %d%% memory or %d%% CPU at scan time (%d node(s) sampled)",
			memWarn, cpuWarn, len(metrics)), nil
	}
	sortResources(hot)
	return Warn("%d node(s) are running hot right now", len(hot)).
		WithResources(hot...).
		WithRemediation("A hot node is one eviction storm away from cascading: pods killed " +
			"there reschedule onto the remaining nodes and heat those too. Add capacity or " +
			"move load before it tips."), nil
}

// resourcePercent computes used/total as a percentage from quantity strings.
func resourcePercent(used, total string) int {
	u, errU := resource.ParseQuantity(used)
	t, errT := resource.ParseQuantity(total)
	if errU != nil || errT != nil || t.IsZero() {
		return 0
	}
	return int(u.MilliValue() * 100 / t.MilliValue())
}

// checkMissingRequests reports containers without resource requests.
func checkMissingRequests(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	type workload struct {
		kind, ns, name string
		spec           corev1.PodSpec
	}
	var workloads []workload

	deploys, err := c.Deployments(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range deploys {
		workloads = append(workloads, workload{"Deployment", d.Namespace, d.Name, d.Spec.Template.Spec})
	}
	stss, err := c.StatefulSets(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range stss {
		workloads = append(workloads, workload{"StatefulSet", s.Namespace, s.Name, s.Spec.Template.Spec})
	}
	dss, err := c.DaemonSets(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range dss {
		workloads = append(workloads, workload{"DaemonSet", d.Namespace, d.Name, d.Spec.Template.Spec})
	}

	var missing []AffectedResource
	for _, w := range workloads {
		var bare []string
		for _, ct := range w.spec.Containers {
			if ct.Resources.Requests.Cpu().IsZero() && ct.Resources.Requests.Memory().IsZero() {
				bare = append(bare, ct.Name)
			}
		}
		if len(bare) > 0 {
			missing = append(missing, AffectedResource{
				Kind: w.kind, APIVersion: "apps/v1", Namespace: w.ns, Name: w.name,
				Detail: "no requests on container(s): " + strings.Join(bare, ", "),
			})
		}
	}

	if len(missing) == 0 {
		return Pass("every container in %d workload(s) declares resource requests", len(workloads)), nil
	}
	sortResources(missing)
	return Warn("%d of %d workload(s) have containers with no resource requests",
		len(missing), len(workloads)).
		WithResources(missing...).
		WithRemediation("Requestless containers schedule blind and are first against the wall " +
			"under node pressure (BestEffort QoS). Set requests from observed usage; even " +
			"rough values beat none."), nil
}

// checkFailedJobs reports Jobs that exhausted retries.
func checkFailedJobs(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	jobs, err := c.Jobs(ctx)
	if err != nil {
		return nil, err
	}
	if len(jobs) == 0 {
		return Skip("no Jobs in the cluster"), nil
	}

	var failed []AffectedResource
	for _, j := range jobs {
		for _, cond := range j.Status.Conditions {
			if cond.Type == "Failed" && cond.Status == corev1.ConditionTrue {
				failed = append(failed, AffectedResource{
					Kind: "Job", APIVersion: "batch/v1", Namespace: j.Namespace, Name: j.Name,
					Detail: truncateDetail(fmt.Sprintf("%s: %s", cond.Reason, cond.Message), 140),
				})
			}
		}
	}

	if len(failed) == 0 {
		return Pass("no failed Jobs among %d", len(jobs)), nil
	}
	sortResources(failed)
	return Warn("%d Job(s) failed and gave up", len(failed)).
		WithResources(failed...).
		WithRemediation("A failed Job stays failed until recreated; whatever it was supposed " +
			"to do has not happened. Check the pod logs it left behind, fix, and re-run."), nil
}

// truncateDetail keeps resource details scannable.
func truncateDetail(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

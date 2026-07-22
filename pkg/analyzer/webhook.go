package analyzer

import (
	"context"
	"fmt"
	"strings"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WebhookChecks returns checks covering admission webhook compatibility.
//
// Admission webhooks are a classic upgrade hazard: a webhook with
// failurePolicy=Fail whose backing pod is unschedulable during a node drain
// will reject every matching API write, which can deadlock the upgrade itself.
func WebhookChecks() []Check {
	return []Check{
		{
			Name:        "webhook-failure-policy",
			Description: "Fail-closed webhooks that could block cluster operations during upgrade",
			Category:    CategoryWebhook,
			Severity:    SeverityWarning,
			Action:      ActionReviewLater,
			Run:         checkWebhookFailurePolicy,
		},
		{
			Name:        "webhook-admission-versions",
			Description: "Webhooks still advertising the removed admission.k8s.io/v1beta1 review version",
			Category:    CategoryWebhook,
			Severity:    SeverityError,
			Action:      ActionPlanAhead,
			Run:         checkWebhookAdmissionVersions,
		},
		{
			Name:        "webhook-scope",
			Description: "Webhooks intercepting cluster-critical resources without namespace exclusions",
			Category:    CategoryWebhook,
			Severity:    SeverityWarning,
			Action:      ActionReviewLater,
			Run:         checkWebhookScope,
		},
		webhookBackendFragilityCheck(),
		{
			Name:        "webhook-timeout",
			Description: "Webhook timeouts long enough to stall API requests during upgrade churn",
			Category:    CategoryWebhook,
			Severity:    SeverityInfo,
			Action:      ActionReviewLater,
			Run:         checkWebhookTimeout,
		},
	}
}

// webhookRef is a flattened view of one webhook from either configuration kind.
type webhookRef struct {
	ConfigKind    string
	ConfigName    string
	WebhookName   string
	FailurePolicy *admissionv1.FailurePolicyType
	TimeoutSecs   *int32
	AdmissionVers []string
	Rules         []admissionv1.RuleWithOperations
	NSSelectorSet bool
	ServiceNS     string
	ServiceName   string
}

// resource renders the webhook as an AffectedResource with the given detail.
func (w webhookRef) resource(detail string) AffectedResource {
	return AffectedResource{
		Kind:       w.ConfigKind,
		APIVersion: "admissionregistration.k8s.io/v1",
		Name:       w.ConfigName,
		Detail:     fmt.Sprintf("webhook %q: %s", w.WebhookName, detail),
	}
}

// allWebhooks flattens both webhook configuration kinds into one slice.
func allWebhooks(ctx context.Context, c *Cluster) ([]webhookRef, error) {
	vals, err := c.ValidatingWebhooks(ctx)
	if err != nil {
		return nil, err
	}
	muts, err := c.MutatingWebhooks(ctx)
	if err != nil {
		return nil, err
	}

	var out []webhookRef
	for _, cfg := range vals {
		for _, w := range cfg.Webhooks {
			ref := webhookRef{
				ConfigKind: "ValidatingWebhookConfiguration", ConfigName: cfg.Name,
				WebhookName: w.Name, FailurePolicy: w.FailurePolicy, TimeoutSecs: w.TimeoutSeconds,
				AdmissionVers: w.AdmissionReviewVersions, Rules: w.Rules,
				NSSelectorSet: hasNamespaceExclusion(w.NamespaceSelector),
			}
			if s := w.ClientConfig.Service; s != nil {
				ref.ServiceNS, ref.ServiceName = s.Namespace, s.Name
			}
			out = append(out, ref)
		}
	}
	for _, cfg := range muts {
		for _, w := range cfg.Webhooks {
			ref := webhookRef{
				ConfigKind: "MutatingWebhookConfiguration", ConfigName: cfg.Name,
				WebhookName: w.Name, FailurePolicy: w.FailurePolicy, TimeoutSecs: w.TimeoutSeconds,
				AdmissionVers: w.AdmissionReviewVersions, Rules: w.Rules,
				NSSelectorSet: hasNamespaceExclusion(w.NamespaceSelector),
			}
			if s := w.ClientConfig.Service; s != nil {
				ref.ServiceNS, ref.ServiceName = s.Namespace, s.Name
			}
			out = append(out, ref)
		}
	}
	return out, nil
}

// hasNamespaceExclusion reports whether the selector meaningfully narrows the
// webhook's scope, which is what keeps it away from kube-system during drains.
func hasNamespaceExclusion(sel *metav1.LabelSelector) bool {
	if sel == nil {
		return false
	}
	return len(sel.MatchLabels) > 0 || len(sel.MatchExpressions) > 0
}

// checkWebhookFailurePolicy flags fail-closed webhooks, and escalates when the
// webhook's own backing service runs in the cluster it gates.
func checkWebhookFailurePolicy(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	whs, err := allWebhooks(ctx, c)
	if err != nil {
		return nil, err
	}
	if len(whs) == 0 {
		return Skip("no admission webhooks configured"), nil
	}

	var risky []AffectedResource
	for _, w := range whs {
		if w.FailurePolicy == nil || *w.FailurePolicy != admissionv1.Fail {
			continue
		}
		detail := "failurePolicy=Fail"
		if w.ServiceName != "" {
			detail += fmt.Sprintf(", backed by in-cluster service %s/%s", w.ServiceNS, w.ServiceName)
		}
		risky = append(risky, w.resource(detail))
	}

	if len(risky) == 0 {
		return Pass("none of %d webhook(s) are fail-closed", len(whs)), nil
	}
	sortResources(risky)
	return Warn("%d of %d webhook(s) are fail-closed and can block API writes during the upgrade",
		len(risky), len(whs)).
		WithResources(risky...).
		WithRemediation("A webhook with failurePolicy=Fail rejects every matching API request " +
			"while its backing pods are unavailable. During a rolling upgrade those pods are " +
			"themselves drained and rescheduled, so the webhook can block the very operations " +
			"the upgrade depends on. Ensure each has multiple replicas spread across nodes, a PDB " +
			"that still permits eviction, and a namespaceSelector excluding kube-system.").
		WithDocs("https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#failure-policy"), nil
}

// checkWebhookAdmissionVersions finds webhooks that only speak the long-removed
// admission.k8s.io/v1beta1 AdmissionReview version.
func checkWebhookAdmissionVersions(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	whs, err := allWebhooks(ctx, c)
	if err != nil {
		return nil, err
	}
	if len(whs) == 0 {
		return Skip("no admission webhooks configured"), nil
	}

	var broken, legacy []AffectedResource
	for _, w := range whs {
		supportsV1 := false
		hasV1beta1 := false
		for _, v := range w.AdmissionVers {
			switch v {
			case "v1":
				supportsV1 = true
			case "v1beta1":
				hasV1beta1 = true
			}
		}
		switch {
		case !supportsV1:
			broken = append(broken, w.resource(fmt.Sprintf(
				"admissionReviewVersions=%v does not include v1", w.AdmissionVers)))
		case hasV1beta1:
			legacy = append(legacy, w.resource(
				"still lists the removed v1beta1 alongside v1 (harmless, but stale)"))
		}
	}

	if len(broken) > 0 {
		sortResources(broken)
		return Fail("%d webhook(s) do not support AdmissionReview v1", len(broken)).
			WithResources(broken...).
			WithRemediation("admission.k8s.io/v1beta1 was removed in Kubernetes 1.22. A webhook " +
				"that does not list v1 in admissionReviewVersions cannot be called at all - the " +
				"API server fails the request according to its failurePolicy. Upgrade the webhook " +
				"component and set admissionReviewVersions: [\"v1\"].").
			WithDocs("https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/"), nil
	}
	if len(legacy) > 0 {
		sortResources(legacy)
		return Warn("%d webhook(s) still advertise the removed v1beta1 review version", len(legacy)).
			WithResources(legacy...).
			WithRemediation("These webhooks negotiate v1 correctly, so nothing breaks. Removing " +
				"\"v1beta1\" from admissionReviewVersions is cleanup, not a blocker.").
			WithAction(ActionReviewLater), nil
	}
	return Pass("all %d webhook(s) support AdmissionReview v1", len(whs)), nil
}

// criticalResources are resources whose interception during an upgrade is most
// likely to deadlock node replacement.
var criticalResources = map[string]bool{
	"pods": true, "nodes": true, "persistentvolumeclaims": true,
	"persistentvolumes": true, "*": true,
}

// checkWebhookScope flags fail-closed webhooks that intercept upgrade-critical
// resources without excluding any namespace.
func checkWebhookScope(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	whs, err := allWebhooks(ctx, c)
	if err != nil {
		return nil, err
	}
	if len(whs) == 0 {
		return Skip("no admission webhooks configured"), nil
	}

	var risky []AffectedResource
	for _, w := range whs {
		if w.FailurePolicy == nil || *w.FailurePolicy != admissionv1.Fail || w.NSSelectorSet {
			continue
		}
		var hit []string
		for _, r := range w.Rules {
			for _, res := range r.Resources {
				if criticalResources[res] {
					hit = append(hit, res)
				}
			}
		}
		if len(hit) > 0 {
			risky = append(risky, w.resource(fmt.Sprintf(
				"fail-closed on %s cluster-wide, no namespaceSelector", strings.Join(dedupe(hit), ", "))))
		}
	}

	if len(risky) == 0 {
		return Pass("no fail-closed webhook intercepts upgrade-critical resources cluster-wide"), nil
	}
	sortResources(risky)
	return Warn("%d webhook(s) intercept upgrade-critical resources cluster-wide while fail-closed", len(risky)).
		WithResources(risky...).
		WithRemediation("These webhooks gate pod and volume operations in every namespace, " +
			"including kube-system. If they become unavailable mid-upgrade, node drain and " +
			"pod rescheduling both stop. Add a namespaceSelector that excludes kube-system."), nil
}

// checkWebhookTimeout reports webhooks with long timeouts, which compound API
// latency when the cluster is busy rescheduling.
func checkWebhookTimeout(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	whs, err := allWebhooks(ctx, c)
	if err != nil {
		return nil, err
	}
	if len(whs) == 0 {
		return Skip("no admission webhooks configured"), nil
	}

	const longTimeout = 15
	var slow []AffectedResource
	for _, w := range whs {
		if w.TimeoutSecs != nil && *w.TimeoutSecs > longTimeout {
			slow = append(slow, w.resource(fmt.Sprintf("timeoutSeconds=%d", *w.TimeoutSecs)))
		}
	}

	if len(slow) == 0 {
		return Pass("all %d webhook(s) use timeouts of %ds or less", len(whs), longTimeout), nil
	}
	sortResources(slow)
	return Warn("%d webhook(s) use timeouts above %ds", len(slow), longTimeout).
		WithResources(slow...).
		WithRemediation("Long webhook timeouts multiply during upgrade churn, when many pods are " +
			"created and deleted at once. Timeouts of 5-10s are typical for healthy webhooks."), nil
}

// dedupe removes duplicates while preserving order.
func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// webhookBackendFragilityCheck returns the join check declaration; wired into
// WebhookChecks via checks.go registration.
func webhookBackendFragilityCheck() Check {
	return Check{
		Name:        "webhook-backend-fragility",
		Description: "Fail-closed webhooks whose backing workload cannot survive a node drain",
		Category:    CategoryWebhook,
		Severity:    SeverityError,
		Action:      ActionFixBeforeStart,
		Evidence: "Joins each fail-closed webhook to its backing Service by name, then to " +
			"the Deployments whose pod template matches that Service's selector, and reads " +
			"their replica counts and PodDisruptionBudgets.",
		Limits: "Backends reachable via URL instead of a Service cannot be resolved. " +
			"Replica count is the signal, not pod placement: two replicas on the same " +
			"node still go down together, which this cannot see without scheduling data.",
		Run: checkWebhookBackendFragility,
	}
}

// checkWebhookBackendFragility finds the admission-webhook deadlock setup: a
// webhook that rejects requests when unavailable, backed by a workload that a
// single node drain makes unavailable.
//
// The individual facts are visible in other checks; the join is what makes the
// finding concrete. A fail-closed webhook is a design choice; a fail-closed
// webhook with one replica is a scheduled outage for every resource it gates,
// timed to whenever the upgrade drains that node.
func checkWebhookBackendFragility(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	whs, err := allWebhooks(ctx, c)
	if err != nil {
		return nil, err
	}
	if len(whs) == 0 {
		return Skip("no admission webhooks configured"), nil
	}

	svcs, err := c.Services(ctx)
	if err != nil {
		return nil, err
	}
	deploys, err := c.Deployments(ctx)
	if err != nil {
		return nil, err
	}
	pdbs, err := c.PodDisruptionBudgets(ctx)
	if err != nil {
		return nil, err
	}

	svcByKey := map[string]corev1.Service{}
	for _, s := range svcs {
		svcByKey[s.Namespace+"/"+s.Name] = s
	}

	var broken, fragile []AffectedResource
	seen := map[string]bool{}
	for _, w := range whs {
		if w.FailurePolicy == nil || *w.FailurePolicy != admissionv1.Fail || w.ServiceName == "" {
			continue
		}
		key := w.ServiceNS + "/" + w.ServiceName
		if seen[key] {
			continue // one finding per backend, not per webhook entry
		}
		seen[key] = true

		svc, ok := svcByKey[key]
		if !ok {
			broken = append(broken, AffectedResource{
				Kind: w.ConfigKind, Name: w.ConfigName,
				Detail: fmt.Sprintf("fail-closed webhook %q points at Service %s, which does not exist",
					w.WebhookName, key),
			})
			continue
		}

		sel := svc.Spec.Selector
		if len(sel) == 0 {
			continue // selectorless service: endpoints are managed externally
		}
		for _, d := range deploys {
			if d.Namespace != svc.Namespace || !labelsMatch(sel, d.Spec.Template.Labels) {
				continue
			}
			replicas := int32(1)
			if d.Spec.Replicas != nil {
				replicas = *d.Spec.Replicas
			}
			pdbState := pdbStateFor(pdbs, d.Namespace, d.Spec.Template.Labels)
			switch {
			case replicas <= 1:
				fragile = append(fragile, AffectedResource{
					Kind: "Deployment", APIVersion: "apps/v1",
					Namespace: d.Namespace, Name: d.Name,
					Detail: fmt.Sprintf("backs fail-closed webhook %q with replicas=%d - its node's "+
						"drain rejects every request this webhook gates", w.WebhookName, replicas),
				})
			case pdbState == "blocked":
				fragile = append(fragile, AffectedResource{
					Kind: "Deployment", APIVersion: "apps/v1",
					Namespace: d.Namespace, Name: d.Name,
					Detail: fmt.Sprintf("backs fail-closed webhook %q and its PDB currently permits "+
						"zero evictions - drain of its nodes hangs AND admission fails", w.WebhookName),
				})
			}
		}
	}

	if len(broken) == 0 && len(fragile) == 0 {
		return Pass("every fail-closed webhook backend resolved and can survive a single node drain"), nil
	}
	all := append(broken, fragile...)
	sortResources(all)
	res := Fail("%d fail-closed webhook backend(s) cannot survive a node drain", len(all)).
		WithResources(all...).
		WithRemediation("Scale each backing workload to 2+ replicas spread across nodes (a " +
			"podAntiAffinity or topologySpreadConstraint), give it a PDB that still permits " +
			"one eviction, and recreate any missing Service. Alternatively set the webhook's " +
			"failurePolicy to Ignore for the upgrade window, accepting unvalidated admissions " +
			"while it is unavailable.").
		WithDocs("https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#failure-policy")
	return res, nil
}

// labelsMatch reports whether every selector pair appears in the labels.
func labelsMatch(selector, labels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// pdbStateFor reports "blocked" when a PDB matching the pod labels currently
// permits zero disruptions, "" otherwise.
func pdbStateFor(pdbs []policyv1.PodDisruptionBudget, namespace string, podLabels map[string]string) string {
	for _, p := range pdbs {
		if p.Namespace != namespace || p.Spec.Selector == nil {
			continue
		}
		if !labelsMatch(p.Spec.Selector.MatchLabels, podLabels) {
			continue
		}
		if p.Status.ExpectedPods > 0 && p.Status.DisruptionsAllowed == 0 {
			return "blocked"
		}
	}
	return ""
}

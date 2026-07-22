package analyzer

import (
	"context"
	"strings"

	"github.com/Rusty-Gopher/kupre/pkg/deprecation"
	"github.com/coredns/corefile-migration/migration"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// CoreDNSChecks returns the CoreDNS configuration-migration check.
//
// kubeadm runs exactly this trial-migration as an upgrade preflight, but only
// with root on a control-plane node. The corefile-migration library it uses is
// importable, and the Corefile plus the running CoreDNS version are both
// API-visible - so the same evidence is available read-only, on any cluster
// that runs CoreDNS, kubeadm or not.
func CoreDNSChecks() []Check {
	return []Check{
		{
			Name:        "coredns-corefile-migration",
			Description: "The live Corefile survives migration to the target release's CoreDNS",
			Category:    CategoryNode,
			Severity:    SeverityWarning,
			Action:      ActionPlanAhead,
			Evidence: "Trial-migrates the live Corefile (kube-system/coredns ConfigMap) from the " +
				"running CoreDNS version (from the deployment's image tag) to the version the " +
				"target Kubernetes release pins, using the same corefile-migration library " +
				"kubeadm's own upgrade preflight uses. Nothing is applied.",
			Limits: "Judges configuration migration only, not CoreDNS behavior. Platforms that " +
				"manage CoreDNS themselves may upgrade it on their own schedule to a different " +
				"version than kubeadm's pin. Expected-version data covers 1.35–1.36; unknown " +
				"CoreDNS versions or a missing ConfigMap skip rather than guess.",
			Run: checkCoreDNSCorefileMigration,
		},
	}
}

// corednsVersionFromImages extracts the CoreDNS version from the coredns
// deployment's container images, without the leading v.
func corednsVersionFromImages(images []string) string {
	for _, img := range images {
		if !strings.Contains(img, "coredns") {
			continue
		}
		if v, ok := imageTag(img); ok {
			return strings.TrimPrefix(v, "v")
		}
	}
	return ""
}

// imageTag extracts the tag portion of an image reference, tolerating digests.
func imageTag(image string) (string, bool) {
	if i := strings.Index(image, "@"); i >= 0 {
		image = image[:i]
	}
	i := strings.LastIndex(image, ":")
	if i < 0 || strings.Contains(image[i:], "/") {
		return "", false
	}
	return image[i+1:], true
}

// checkCoreDNSCorefileMigration trial-migrates the live Corefile.
func checkCoreDNSCorefileMigration(ctx context.Context, c *Cluster, up Upgrade) (*Result, error) {
	cm, err := c.GetConfigMap(ctx, "kube-system", "coredns")
	if err != nil {
		if apierrors.IsNotFound(err) || apierrors.IsForbidden(err) {
			return Skip("no readable kube-system/coredns ConfigMap; cluster DNS is managed elsewhere"), nil
		}
		return nil, err
	}
	corefile, ok := cm.Data["Corefile"]
	if !ok || strings.TrimSpace(corefile) == "" {
		return Skip("coredns ConfigMap has no Corefile key"), nil
	}

	deploys, err := c.Deployments(ctx)
	if err != nil {
		return nil, err
	}
	current := ""
	for _, d := range deploys {
		if d.Namespace != "kube-system" || !strings.Contains(d.Name, "coredns") {
			continue
		}
		var images []string
		for _, ct := range d.Spec.Template.Spec.Containers {
			images = append(images, ct.Image)
		}
		current = corednsVersionFromImages(images)
	}
	if current == "" {
		return Skip("could not determine the running CoreDNS version from the deployment image"), nil
	}

	expected, known := deprecation.ComponentsFor(up.To.MinorString())
	if !known {
		return Warn("no CoreDNS pin data for Kubernetes %s - Corefile compatibility could not be judged",
			up.To.MinorString()).
			WithRemediation("%s", deprecation.HorizonNote(up.To.MinorString())), nil
	}
	target := strings.TrimPrefix(expected.CoreDNSVersion, "v")

	if verAtLeast(current, target) {
		return Pass("CoreDNS %s already meets or exceeds the %s the target release pins - no migration needed",
			current, target), nil
	}
	if err := migration.ValidUpMigration(current, target); err != nil {
		return Skip("the migration library cannot evaluate CoreDNS %s → %s (%v); verify the "+
			"Corefile manually against the CoreDNS release notes", current, target, err), nil
	}

	unsupported, err := migration.Unsupported(current, target, corefile)
	if err != nil {
		return Warn("the live Corefile could not be parsed for migration to CoreDNS %s: %v", target, err).
			WithRemediation("kubeadm's upgrade runs this same migration and will hit the same " +
				"parse failure. Fix the Corefile syntax, or plan to hand-migrate it."), nil
	}
	if _, err := migration.Migrate(current, target, corefile, true); err != nil {
		return Warn("the live Corefile does not migrate cleanly from CoreDNS %s to %s: %v",
			current, target, err).
			WithRemediation("The upgrade's automatic Corefile migration will fail the same way, " +
				"leaving DNS on the old config or the upgrade blocked. Migrate the Corefile by " +
				"hand first.").
			WithDocs("https://github.com/coredns/corefile-migration"), nil
	}

	if len(unsupported) > 0 {
		var res []AffectedResource
		for _, n := range unsupported {
			res = append(res, AffectedResource{
				Kind: "ConfigMap", APIVersion: "v1", Namespace: "kube-system", Name: "coredns",
				Detail: n.ToString(),
			})
		}
		return Warn("the Corefile uses %d plugin option(s) the target CoreDNS %s does not support",
			len(unsupported), target).
			WithResources(res...).
			WithRemediation("These survive automatic migration by being dropped or ignored - DNS " +
				"behavior changes silently. Review each and adjust the Corefile deliberately " +
				"before the upgrade migrates it for you."), nil
	}

	return Pass("the live Corefile migrates cleanly from CoreDNS %s to %s", current, target), nil
}

// verAtLeast compares dotted versions numerically, returning true when a >= b.
func verAtLeast(a, b string) bool {
	av, errA := ParseVersion(a)
	bv, errB := ParseVersion(b)
	if errA != nil || errB != nil {
		return false
	}
	return av.AtLeast(bv)
}

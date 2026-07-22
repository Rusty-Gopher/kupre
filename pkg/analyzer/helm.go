package analyzer

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Rusty-Gopher/kupre/pkg/deprecation"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/yaml"
)

// HelmChecks returns checks built on Helm's release storage.
//
// This is the strongest API-usage evidence available to a read-only client:
// Helm stores the rendered manifest verbatim at install/upgrade time, so the
// apiVersions in it are exactly what the chart emitted - they never pass
// through the API server's version conversion. Where the live-object check can
// only say "authorship unknown", this says "this release will re-apply that
// apiVersion on its next upgrade".
func HelmChecks() []Check {
	return []Check{
		{
			Name:        "helm-release-removed-apis",
			Description: "Helm releases whose stored manifests use API versions the target release removes",
			Category:    CategoryAPI,
			Severity:    SeverityError,
			Action:      ActionPlanAhead,
			Evidence: "Decodes every sh.helm.release.v1 Secret (and configmap-backend release) " +
				"and scans the stored rendered manifest, which preserves apiVersions exactly " +
				"as the chart emitted them - this data never passes through API conversion.",
			Limits: "Covers Helm-managed resources only; kubectl-applied and operator-managed " +
				"objects are invisible here. Reads only the manifest and chart metadata - " +
				"release values are never read or reported. Requires list access on Secrets; " +
				"without it the check is skipped, not passed.",
			Run: checkHelmReleaseRemovedAPIs,
		},
	}
}

// helmRelease is the subset of Helm's release payload kupre needs. The values
// (config) field is deliberately absent: release values can embed credentials,
// and kupre must never load them into memory, let alone report them.
type helmRelease struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Version   int    `json:"version"`
	Manifest  string `json:"manifest"`
	Info      struct {
		Status string `json:"status"`
	} `json:"info"`
	Chart struct {
		Metadata struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"metadata"`
	} `json:"chart"`
}

// helmMagicGzip is the gzip magic Helm checks before decompressing; releases
// written by very old Helm 3 builds may be uncompressed.
var helmMagicGzip = []byte{0x1f, 0x8b, 0x08}

// decodeHelmRelease reverses Helm's storage encoding: base64 (Helm's own
// layer; the Kubernetes Secret layer is already handled by client-go), then
// gzip when the magic matches, then JSON.
func decodeHelmRelease(data []byte) (*helmRelease, error) {
	raw, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("helm base64 layer: %w", err)
	}
	if bytes.HasPrefix(raw, helmMagicGzip) {
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("helm gzip layer: %w", err)
		}
		defer zr.Close()
		if raw, err = io.ReadAll(zr); err != nil {
			return nil, fmt.Errorf("helm gzip layer: %w", err)
		}
	}
	var rel helmRelease
	if err := json.Unmarshal(raw, &rel); err != nil {
		return nil, fmt.Errorf("helm release json: %w", err)
	}
	return &rel, nil
}

// manifestDoc is the identifying header of one document in a rendered manifest.
type manifestDoc struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name string `json:"name"`
	} `json:"metadata"`
}

// manifestDocs splits a rendered manifest into documents and parses each one's
// identity. Documents that fail to parse are skipped: a chart can emit
// commentary or partial documents, and one bad doc must not hide the rest.
func manifestDocs(manifest string) []manifestDoc {
	var out []manifestDoc
	for _, doc := range strings.Split(manifest, "\n---") {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}
		var d manifestDoc
		if err := yaml.Unmarshal([]byte(doc), &d); err != nil {
			continue
		}
		if d.APIVersion != "" && d.Kind != "" {
			out = append(out, d)
		}
	}
	return out
}

// helmReleases loads and decodes every current Helm release, from both storage
// backends. Only the latest revision per release is considered: superseded
// revisions describe history, not what the next `helm upgrade` will re-apply.
func helmReleases(ctx context.Context, c *Cluster) (releases []*helmRelease, undecodable int, cmBackendErr error, err error) {
	secrets, err := c.HelmReleaseSecrets(ctx)
	if err != nil {
		return nil, 0, nil, err
	}
	cms, cmBackendErr := c.HelmReleaseConfigMaps(ctx)
	if cmBackendErr != nil {
		// The secret backend is the default; a configmap-backend failure must
		// not discard what the secret backend produced - but it must be said.
		cms = nil
	}

	type payload struct {
		data []byte
	}
	var payloads []payload
	for _, s := range secrets {
		if d, ok := s.Data["release"]; ok {
			payloads = append(payloads, payload{data: d})
		}
	}
	for _, cm := range cms {
		if d, ok := cm.Data["release"]; ok {
			payloads = append(payloads, payload{data: []byte(d)})
		}
	}

	latest := map[string]*helmRelease{}
	for _, p := range payloads {
		rel, err := decodeHelmRelease(p.data)
		if err != nil {
			undecodable++
			continue
		}
		key := rel.Namespace + "/" + rel.Name
		if cur, ok := latest[key]; !ok || rel.Version > cur.Version {
			latest[key] = rel
		}
	}
	for _, rel := range latest {
		releases = append(releases, rel)
	}
	sort.Slice(releases, func(i, j int) bool {
		if releases[i].Namespace != releases[j].Namespace {
			return releases[i].Namespace < releases[j].Namespace
		}
		return releases[i].Name < releases[j].Name
	})
	return releases, undecodable, cmBackendErr, nil
}

// checkHelmReleaseRemovedAPIs scans every release's stored manifest for
// apiVersions removed on the upgrade path.
func checkHelmReleaseRemovedAPIs(ctx context.Context, c *Cluster, up Upgrade) (*Result, error) {
	releases, undecodable, cmBackendErr, err := helmReleases(ctx, c)
	if err != nil {
		if apierrors.IsForbidden(err) {
			return Skip("no permission to list Helm release secrets; grant list on secrets " +
				"(see deploy/rbac.yaml) or scan manifests with Pluto/kubent instead"), nil
		}
		return nil, err
	}
	if len(releases) == 0 {
		return Skip("no Helm v3 releases found in the cluster"), nil
	}

	scheduled := deprecation.RemovedBetween(up.From.MinorString(), up.To.MinorString())
	if len(scheduled) == 0 {
		if deprecation.BeyondHorizon(up.To.MinorString()) {
			return beyondHorizon(up)
		}
		return Pass("no API removals scheduled between %s and %s (%d Helm release(s) present)",
			up.From.MinorString(), up.To.MinorString(), len(releases)), nil
	}
	removed := map[string]deprecation.APIRemoval{}
	for _, r := range scheduled {
		removed[r.GroupVersion()+"/"+r.Kind] = r
	}

	var affected []AffectedResource
	for _, rel := range releases {
		for _, doc := range manifestDocs(rel.Manifest) {
			r, hit := removed[doc.APIVersion+"/"+doc.Kind]
			if !hit {
				continue
			}
			affected = append(affected, AffectedResource{
				Kind:       doc.Kind,
				APIVersion: doc.APIVersion,
				Namespace:  rel.Namespace,
				Name:       doc.Metadata.Name,
				Detail: fmt.Sprintf("in Helm release %s (chart %s %s) - removed in %s → %s",
					rel.Name, rel.Chart.Metadata.Name, rel.Chart.Metadata.Version,
					r.RemovedIn, r.Replacement()),
			})
		}
	}

	if len(affected) == 0 {
		res := Pass("none of %d Helm release(s) render an API version removed by %s",
			len(releases), up.To.MinorString())
		if cmBackendErr != nil && apierrors.IsForbidden(cmBackendErr) {
			res = Warn("%d secret-backend Helm release(s) are clean for %s, but configmap-backend "+
				"releases could not be read", len(releases), up.To.MinorString()).
				WithRemediation("Grant list on ConfigMaps labeled owner=helm, or confirm no " +
					"release uses the configmap storage backend.")
		}
		if undecodable > 0 {
			res = Warn("%d Helm release payload(s) could not be decoded; the other %d are clean for %s",
				undecodable, len(releases), up.To.MinorString()).
				WithRemediation("Undecodable payloads were counted, not ignored - verify those " +
					"releases by hand (helm get manifest) before trusting this result.")
		}
		return res, nil
	}
	sortResources(affected)
	return Fail("%d resource(s) across Helm releases use an API version removed by %s",
		len(affected), up.To.MinorString()).
		WithResources(affected...).
		WithRemediation("These come from Helm's own stored manifests, so unlike a live-object "+
			"scan this is confirmed authorship: the next `helm upgrade` of each release will "+
			"re-apply the removed apiVersion and fail after the cluster reaches %s. Upgrade "+
			"each chart to a version that renders the replacement apiVersion first.",
			up.To.MinorString()).
		WithDocs("https://kubernetes.io/docs/reference/using-api/deprecation-guide/"), nil
}

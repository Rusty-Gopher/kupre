package analyzer

import (
	"context"
	"errors"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// apiServicesGVR is the aggregated-API registration resource.
var apiServicesGVR = schema.GroupVersionResource{
	Group: "apiregistration.k8s.io", Version: "v1", Resource: "apiservices",
}

// PlatformChecks returns checks on the API machinery itself: aggregated API
// availability and CRD storage-version hygiene.
func PlatformChecks() []Check {
	return []Check{
		{
			Name:        "apiservice-availability",
			Description: "Aggregated API services are available",
			Category:    CategoryAPI,
			Severity:    SeverityError,
			Action:      ActionResolveFirst,
			Evidence:    "Reads the Available condition of every APIService backed by an in-cluster Service.",
			Limits: "Availability is as reported by the aggregator at scan time; a backend " +
				"that flaps between scrapes can show healthy here. Local (non-aggregated) " +
				"API groups have no backend and are not evaluated.",
			Run: checkAPIServiceAvailability,
		},
		{
			Name:        "crd-stored-versions",
			Description: "CRDs whose stored objects lag the current storage version",
			Category:    CategoryAPI,
			Severity:    SeverityWarning,
			Action:      ActionPlanAhead,
			Evidence:    "Compares each CRD's status.storedVersions against its spec storage version.",
			Limits: "Detects that objects were written under an older version at some point, " +
				"not how many exist now - counting would require reading every object of " +
				"every affected CRD. Migration state inside operators is invisible.",
			Run: checkCRDStoredVersions,
		},
	}
}

// checkAPIServiceAvailability finds aggregated APIs whose backend is down.
//
// An unavailable APIService is worse than one broken feature: it degrades API
// discovery and can stall garbage collection and namespace deletion, which are
// exactly the operations an upgrade leans on.
func checkAPIServiceAvailability(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	svcs, err := c.ListGVR(ctx, apiServicesGVR)
	switch {
	case err == nil:
	case apierrors.IsForbidden(err):
		return Skip("no permission to read APIServices; aggregated API health is unknown"), nil
	case apierrors.IsNotFound(err) || errors.Is(err, ErrNoDynamicClient):
		return Skip("apiregistration API not readable; aggregated API health unknown"), nil
	default:
		return nil, err
	}
	if len(svcs) == 0 {
		return Skip("no APIService objects found; aggregated API health unknown"), nil
	}

	aggregated := 0
	var down []AffectedResource
	for _, s := range svcs {
		// Local API groups have no spec.service and cannot be unavailable.
		if _, found, _ := unstructuredString(s.Object, "spec", "service", "name"); !found {
			continue
		}
		aggregated++

		available := ""
		msg := ""
		if conds, ok, _ := nestedSlice(s.Object, "status", "conditions"); ok {
			for _, cd := range conds {
				m, ok := cd.(map[string]any)
				if !ok {
					continue
				}
				if m["type"] == "Available" {
					available, _ = m["status"].(string)
					msg, _ = m["message"].(string)
				}
			}
		}
		if available != "True" {
			ns, _, _ := unstructuredString(s.Object, "spec", "service", "namespace")
			name, _, _ := unstructuredString(s.Object, "spec", "service", "name")
			down = append(down, AffectedResource{
				Kind: "APIService", Name: s.GetName(),
				Detail: fmt.Sprintf("backend %s/%s unavailable: %s", ns, name, msg),
			})
		}
	}

	if len(down) == 0 {
		return Pass("all %d aggregated API service(s) report Available", aggregated), nil
	}
	sortResources(down)
	return Fail("%d aggregated API service(s) are unavailable", len(down)).
		WithResources(down...).
		WithRemediation("An unavailable aggregated API degrades discovery and can stall garbage " +
			"collection and namespace deletion - machinery the upgrade depends on. Restore the " +
			"backing service, or delete the stale APIService registration."), nil
}

// checkCRDStoredVersions finds CRDs still carrying objects stored under a
// version that is no longer the storage version.
func checkCRDStoredVersions(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	crds, err := c.CustomResourceDefinitions(ctx)
	if err != nil {
		return nil, err
	}
	if len(crds) == 0 {
		return Skip("no CustomResourceDefinitions found"), nil
	}

	var stale []AffectedResource
	for _, crd := range crds {
		storage := ""
		for _, v := range crd.Spec.Versions {
			if v.Storage {
				storage = v.Name
			}
		}
		var old []string
		for _, sv := range crd.Status.StoredVersions {
			if sv != storage {
				old = append(old, sv)
			}
		}
		if len(old) > 0 {
			stale = append(stale, AffectedResource{
				Kind: "CustomResourceDefinition", APIVersion: "apiextensions.k8s.io/v1",
				Name: crd.Name,
				Detail: fmt.Sprintf("storedVersions still include %s; storage version is %s",
					strings.Join(old, ", "), storage),
			})
		}
	}

	if len(stale) == 0 {
		return Pass("all %d CRD(s) have every stored object at their current storage version", len(crds)), nil
	}
	sortResources(stale)
	return Warn("%d CRD(s) carry objects stored under a superseded version", len(stale)).
		WithResources(stale...).
		WithRemediation("The Kubernetes upgrade itself does not read these, but the owning " +
			"operator cannot drop the old version from its CRD until every stored object is " +
			"rewritten and the version removed from status.storedVersions - and operator " +
			"upgrades are usually part of the same maintenance window. Migrate with the " +
			"operator's storage-migration procedure, or kube-storage-version-migrator.").
		WithDocs("https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definition-versioning/#upgrade-existing-objects-to-a-new-stored-version"), nil
}

// nestedSlice reads a nested []any from an unstructured object.
func nestedSlice(obj map[string]any, fields ...string) ([]any, bool, error) {
	cur := any(obj)
	for _, f := range fields {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false, nil
		}
		cur, ok = m[f]
		if !ok {
			return nil, false, nil
		}
	}
	s, ok := cur.([]any)
	return s, ok, nil
}

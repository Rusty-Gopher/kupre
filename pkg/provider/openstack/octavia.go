package openstack

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
	corev1 "k8s.io/api/core/v1"
)

// octaviaChecks returns the Octavia load balancer preflight checks.
func octaviaChecks() []analyzer.Check {
	return []analyzer.Check{
		{
			Name:        "openstack-octavia-annotations",
			Description: "LoadBalancer Services use current Octavia annotations",
			Category:    analyzer.CategoryCloud,
			Severity:    analyzer.SeverityWarning,
			Action:      analyzer.ActionReviewLater,
			Run:         checkOctaviaAnnotations,
		},
		{
			Name:        "openstack-loadbalancer-health",
			Description: "LoadBalancer Services have an assigned external address",
			Category:    analyzer.CategoryCloud,
			Severity:    analyzer.SeverityWarning,
			Action:      analyzer.ActionResolveFirst,
			Run:         checkLoadBalancerHealth,
		},
	}
}

// deprecatedAnnotation records an Octavia Service annotation that has been
// renamed or removed in cloud-provider-openstack.
type deprecatedAnnotation struct {
	Replacement string
	Note        string
}

// deprecatedOctaviaAnnotations maps superseded loadbalancer annotations to
// their current equivalents.
//
// cloud-provider-openstack renamed several annotations when the Octavia
// provider was split out of the legacy Neutron LBaaS implementation. The old
// names are silently ignored, so a Service keeps working with the wrong
// settings rather than failing loudly - which makes this worth flagging.
var deprecatedOctaviaAnnotations = map[string]deprecatedAnnotation{
	"loadbalancer.openstack.org/floating-network-id": {
		Replacement: "loadbalancer.openstack.org/floating-network-id",
		Note:        "still supported; verify it matches the CCM's configured floating network",
	},
	"service.beta.kubernetes.io/openstack-internal-load-balancer": {
		Replacement: "loadbalancer.openstack.org/internal",
		Note:        "the service.beta.kubernetes.io form is legacy",
	},
	"loadbalancer.openstack.org/cascade-delete": {
		Replacement: "",
		Note:        "cascade delete is the default behaviour and the annotation is ignored",
	},
}

// checkOctaviaAnnotations inspects LoadBalancer Services for legacy annotations.
func checkOctaviaAnnotations(ctx context.Context, c *analyzer.Cluster, _ analyzer.Upgrade) (*analyzer.Result, error) {
	svcs, err := c.Services(ctx)
	if err != nil {
		return nil, err
	}

	lbs := loadBalancerServices(svcs)
	if len(lbs) == 0 {
		return analyzer.Skip("no LoadBalancer Services defined"), nil
	}

	var issues []analyzer.AffectedResource
	for _, s := range lbs {
		var found []string
		for key := range s.Annotations {
			dep, ok := deprecatedOctaviaAnnotations[key]
			if !ok {
				continue
			}
			switch {
			case dep.Replacement == "":
				found = append(found, fmt.Sprintf("%s (%s)", key, dep.Note))
			case dep.Replacement == key:
				continue
			default:
				found = append(found, fmt.Sprintf("%s → %s", key, dep.Replacement))
			}
		}
		if len(found) > 0 {
			sort.Strings(found)
			issues = append(issues, analyzer.AffectedResource{
				Kind: "Service", APIVersion: "v1", Namespace: s.Namespace, Name: s.Name,
				Detail: strings.Join(found, "; "),
			})
		}
	}

	if len(issues) == 0 {
		return analyzer.Pass("all %d LoadBalancer Service(s) use current Octavia annotations", len(lbs)), nil
	}
	return analyzer.Warn("%d LoadBalancer Service(s) use legacy Octavia annotations", len(issues)).
		WithResources(issues...).
		WithRemediation("Superseded annotations are ignored rather than rejected, so the load " +
			"balancer keeps running with default settings instead of the ones you intended. " +
			"Update these to the current annotation names.").
		WithDocs("https://github.com/kubernetes/cloud-provider-openstack/blob/master/docs/openstack-cloud-controller-manager/expose-applications-using-loadbalancer-type-service.md"), nil
}

// checkLoadBalancerHealth finds LoadBalancer Services without an assigned
// address. These indicate the CCM is not reconciling them, which will not
// improve during an upgrade.
func checkLoadBalancerHealth(ctx context.Context, c *analyzer.Cluster, _ analyzer.Upgrade) (*analyzer.Result, error) {
	svcs, err := c.Services(ctx)
	if err != nil {
		return nil, err
	}

	lbs := loadBalancerServices(svcs)
	if len(lbs) == 0 {
		return analyzer.Skip("no LoadBalancer Services defined"), nil
	}

	var pending []analyzer.AffectedResource
	var managed int
	for _, s := range lbs {
		if len(s.Status.LoadBalancer.Ingress) == 0 {
			pending = append(pending, analyzer.AffectedResource{
				Kind: "Service", APIVersion: "v1", Namespace: s.Namespace, Name: s.Name,
				Detail: "no external address assigned",
			})
			continue
		}
		if s.Annotations["loadbalancer.openstack.org/load-balancer-id"] != "" {
			managed++
		}
	}

	if len(pending) == 0 {
		return analyzer.Pass("all %d LoadBalancer Service(s) have an external address (%d with a tracked Octavia LB id)",
			len(lbs), managed), nil
	}
	return analyzer.Warn("%d of %d LoadBalancer Service(s) have no external address", len(pending), len(lbs)).
		WithResources(pending...).
		WithRemediation("A LoadBalancer Service without an address means the OpenStack cloud " +
			"controller manager has not reconciled it - commonly a quota, credential, or " +
			"connectivity problem. Resolve it before the upgrade, since the CCM itself restarts " +
			"during the rollout and the failure will be harder to attribute afterwards."), nil
}

// loadBalancerServices filters services down to type=LoadBalancer.
func loadBalancerServices(svcs []corev1.Service) []corev1.Service {
	var out []corev1.Service
	for _, s := range svcs {
		if s.Spec.Type == corev1.ServiceTypeLoadBalancer {
			out = append(out, s)
		}
	}
	return out
}

// Package openstack implements OpenStack-specific upgrade preflight checks.
//
// All detection and checking is done by reading Kubernetes objects. The package
// never calls the OpenStack API directly, so it needs no OpenStack credentials.
package openstack

import (
	"context"
	"strings"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
	"github.com/Rusty-Gopher/kupre/pkg/provider"
)

// Provider implements provider.Provider for OpenStack clusters.
type Provider struct{}

func init() { provider.Register(Provider{}) }

// Name returns the provider identifier.
func (Provider) Name() string { return "openstack" }

// openstackDrivers are the CSI drivers shipped by cloud-provider-openstack.
var openstackDrivers = map[string]string{
	"cinder.csi.openstack.org": "Cinder",
	"manila.csi.openstack.org": "Manila",
}

// Detect reports whether the cluster runs on OpenStack.
//
// Detection reads three independent signals, any of which is sufficient:
// the node provider ID prefix, a registered OpenStack CSI driver, and
// OpenStack-specific StorageClass provisioners. Using several signals means a
// cluster with, say, Cinder CSI but no CCM is still recognised.
func (Provider) Detect(ctx context.Context, c *analyzer.Cluster) (bool, error) {
	nodes, err := c.Nodes(ctx)
	if err != nil {
		return false, err
	}
	for _, n := range nodes {
		if strings.HasPrefix(n.Spec.ProviderID, "openstack://") {
			return true, nil
		}
	}

	drivers, err := c.CSIDrivers(ctx)
	if err != nil {
		return false, err
	}
	for _, d := range drivers {
		if _, ok := openstackDrivers[d.Name]; ok {
			return true, nil
		}
	}

	scs, err := c.StorageClasses(ctx)
	if err != nil {
		return false, err
	}
	for _, sc := range scs {
		if _, ok := openstackDrivers[sc.Provisioner]; ok {
			return true, nil
		}
		if sc.Provisioner == "kubernetes.io/cinder" {
			return true, nil
		}
	}
	return false, nil
}

// Checks returns the OpenStack preflight checks.
func (Provider) Checks() []analyzer.Check {
	var out []analyzer.Check
	out = append(out, cinderChecks()...)
	out = append(out, octaviaChecks()...)
	out = append(out, ccmChecks()...)
	return out
}

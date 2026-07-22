// Package provider hosts cloud-specific preflight check plugins and the
// auto-detection that decides which of them apply to a cluster.
package provider

import (
	"context"
	"fmt"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
)

// Provider is a cloud-specific check plugin.
type Provider interface {
	// Name is the provider's short identifier, e.g. "openstack".
	Name() string
	// Detect reports whether this provider's checks apply to the cluster. It
	// must be read-only and must not error on unrelated clusters.
	Detect(ctx context.Context, c *analyzer.Cluster) (bool, error)
	// Checks returns the provider's checks.
	Checks() []analyzer.Check
}

// registry holds every compiled-in provider.
var registry []Provider

// Register adds a provider to the registry. It is called from provider package
// init functions.
func Register(p Provider) { registry = append(registry, p) }

// Registered returns all known providers.
func Registered() []Provider { return registry }

// Detect returns every provider whose checks apply to the cluster, plus a
// message for each provider whose detection FAILED.
//
// The distinction matters: "this is not an OpenStack cluster" and "I could not
// tell whether this is an OpenStack cluster" are different answers, and an
// earlier version collapsed both into silently skipping the provider's checks.
// A scan missing a whole provider family must be inconclusive, not clean.
func Detect(ctx context.Context, c *analyzer.Cluster) (applies []Provider, failures []string) {
	for _, p := range registry {
		ok, err := p.Detect(ctx, c)
		switch {
		case err != nil:
			failures = append(failures, fmt.Sprintf(
				"provider %s: detection failed (%v) - its checks did not run and their "+
					"subjects are unverified", p.Name(), err))
		case ok:
			applies = append(applies, p)
		}
	}
	return applies, failures
}

// ChecksFor returns the checks of every provider detected on the cluster and
// the detection failures the caller must surface as tool-level errors.
func ChecksFor(ctx context.Context, c *analyzer.Cluster) ([]analyzer.Check, []string) {
	providers, failures := Detect(ctx, c)
	var out []analyzer.Check
	for _, p := range providers {
		out = append(out, p.Checks()...)
	}
	return out, failures
}

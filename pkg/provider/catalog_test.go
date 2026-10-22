package provider_test

import (
	"testing"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
	"github.com/Rusty-Gopher/kupre/pkg/provider"
	_ "github.com/Rusty-Gopher/kupre/pkg/provider/capi"
	_ "github.com/Rusty-Gopher/kupre/pkg/provider/kubeadm"
	_ "github.com/Rusty-Gopher/kupre/pkg/provider/openstack"
)

// Every check any mission can run must be in the catalog exactly once:
// `kupre checks` and policy validation both trust it.
func TestCatalogCoversEveryMission(t *testing.T) {
	cat := map[string][]string{}
	for _, e := range provider.Catalog() {
		if _, dup := cat[e.Name]; dup {
			t.Fatalf("check %q listed twice", e.Name)
		}
		cat[e.Name] = e.Missions
	}
	for _, m := range analyzer.Missions() {
		for _, c := range m.Checks() {
			if _, ok := cat[c.Name]; !ok {
				t.Errorf("%s check %q missing from catalog", m.Name, c.Name)
			}
		}
	}
	for _, name := range []string{"pod-failure-causes", "tls-secret-expiry", "capi-drain-hang"} {
		if len(cat[name]) == 0 {
			t.Errorf("%q has no missions in the catalog", name)
		}
	}
}

package provider

import "github.com/Rusty-Gopher/kupre/pkg/analyzer"

// CatalogEntry is one check and the missions that run it.
type CatalogEntry struct {
	analyzer.Check
	Missions []string
}

// Catalog lists every check the binary carries exactly once - built-in checks
// of all missions plus provider checks - with the missions that run each.
// Provider checks only run where their provider is detected.
func Catalog() []CatalogEntry {
	var (
		out   []CatalogEntry
		index = map[string]int{}
	)
	add := func(c analyzer.Check, mission string) {
		i, ok := index[c.Name]
		if !ok {
			index[c.Name] = len(out)
			out = append(out, CatalogEntry{Check: c})
			i = len(out) - 1
		}
		out[i].Missions = append(out[i].Missions, mission)
	}
	for _, m := range analyzer.Missions() {
		for _, c := range m.Checks() {
			add(c, m.Name)
		}
		for _, p := range registry {
			for _, c := range p.Checks() {
				if m.ProviderChecks != nil && m.ProviderChecks(c.Name) {
					add(c, m.Name)
				}
			}
		}
	}
	return out
}

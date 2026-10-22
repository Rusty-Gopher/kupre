package deprecation

import "testing"

func TestRemovedBetween(t *testing.T) {
	tests := []struct {
		name      string
		from, to  string
		wantCount int
		wantGVK   string // one GVK that must be present, or "" to skip the check
	}{
		{
			name: "1.24 to 1.25 finds the PSP removal",
			from: "1.24", to: "1.25",
			wantCount: 7,
			wantGVK:   "policy/v1beta1 PodSecurityPolicy",
		},
		{
			name: "1.35 to 1.36 has no served API removals",
			// 1.33 through 1.36 removed no served APIs. Only alpha resources
			// went away, and 1.36's is scheduling.k8s.io/v1alpha1 Workload.
			from: "1.35", to: "1.36",
			wantCount: 1,
			wantGVK:   "scheduling.k8s.io/v1alpha1 Workload",
		},
		{
			name: "1.36 to 1.37 finds the scheduling v1alpha2 removal",
			// CHANGELOG-1.37: Workload and PodGroup promoted to v1beta1;
			// "Remove all v1alpha2 objects ... before upgrading".
			from: "1.36", to: "1.37",
			wantCount: 2,
			wantGVK:   "scheduling.k8s.io/v1alpha2 PodGroup",
		},
		{
			name: "1.31 to 1.32 finds the flowcontrol v1beta3 removal",
			from: "1.31", to: "1.32",
			wantCount: 2,
			wantGVK:   "flowcontrol.apiserver.k8s.io/v1beta3 FlowSchema",
		},
		{
			name: "1.27 to 1.28 is empty",
			from: "1.27", to: "1.28",
			wantCount: 0,
		},
		{
			name: "multi-version span accumulates",
			from: "1.24", to: "1.27",
			wantCount: 11,
		},
		{
			name: "downgrade returns nothing",
			from: "1.36", to: "1.35",
			wantCount: 0,
		},
		{
			name: "same version returns nothing",
			from: "1.35", to: "1.35",
			wantCount: 0,
		},
		{
			name: "unparseable input returns nothing",
			from: "garbage", to: "1.36",
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RemovedBetween(tt.from, tt.to)
			if len(got) != tt.wantCount {
				var names []string
				for _, r := range got {
					names = append(names, r.GVK())
				}
				t.Errorf("RemovedBetween(%s, %s) returned %d entries, want %d: %v",
					tt.from, tt.to, len(got), tt.wantCount, names)
			}
			if tt.wantGVK == "" {
				return
			}
			found := false
			for _, r := range got {
				if r.GVK() == tt.wantGVK {
					found = true
				}
			}
			if !found {
				t.Errorf("RemovedBetween(%s, %s) did not include %q", tt.from, tt.to, tt.wantGVK)
			}
		})
	}
}

func TestRemovalMetadata(t *testing.T) {
	// Every entry must carry enough information to render actionable advice.
	for _, r := range All() {
		if r.Kind == "" || r.Resource == "" || r.Version == "" {
			t.Errorf("removal %+v is missing Kind, Resource, or Version", r)
		}
		if r.RemovedIn == "" {
			t.Errorf("removal %s has no RemovedIn", r.GVK())
		}
		if _, _, ok := splitMinor(r.RemovedIn); !ok {
			t.Errorf("removal %s has unparseable RemovedIn %q", r.GVK(), r.RemovedIn)
		}
		// A removal with no replacement must explain what to do instead.
		if r.ReplacementVersion == "" && r.Notes == "" {
			t.Errorf("removal %s has neither a replacement nor migration notes", r.GVK())
		}
		if r.Resource != lower(r.Resource) {
			t.Errorf("removal %s: Resource %q must be the lowercase plural form", r.GVK(), r.Resource)
		}
	}
}

func TestBreakingChangesBetween(t *testing.T) {
	tests := []struct {
		name     string
		from, to string
		wantID   string
		wantAny  bool
	}{
		{name: "1.35 to 1.36 includes the gitRepo removal", from: "1.35", to: "1.36",
			wantID: "gitrepo-volume-disabled", wantAny: true},
		{name: "1.34 to 1.35 includes the cgroup v1 change", from: "1.34", to: "1.35",
			wantID: "cgroup-v1-fails-closed", wantAny: true},
		{name: "1.35 to 1.36 excludes the cgroup v1 change", from: "1.35", to: "1.36",
			wantID: "cgroup-v1-fails-closed", wantAny: false},
		{name: "1.34 to 1.35 excludes 1.36 changes", from: "1.34", to: "1.35",
			wantID: "gitrepo-volume-disabled", wantAny: false},
		{name: "patch-level span has nothing", from: "1.36", to: "1.36", wantAny: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BreakingChangesBetween(tt.from, tt.to)
			found := false
			for _, bc := range got {
				if bc.ID == tt.wantID {
					found = true
				}
			}
			if found != tt.wantAny {
				t.Errorf("BreakingChangesBetween(%s, %s) containing %q = %v, want %v",
					tt.from, tt.to, tt.wantID, found, tt.wantAny)
			}
		})
	}
}

func TestVerifiedUpstreamSemantics(t *testing.T) {
	t.Run("policy v1 PDB empty selector matches all pods", func(t *testing.T) {
		var got string
		for _, r := range All() {
			if r.Group == "policy" && r.Version == "v1beta1" && r.Kind == "PodDisruptionBudget" {
				got = r.Notes
				break
			}
		}
		want := "an empty spec.selector in policy/v1 matches every pod in the namespace; in policy/v1beta1 it matched no pods"
		if got != want {
			t.Errorf("PDB migration note = %q, want %q", got, want)
		}
	})

	t.Run("failCgroupV1 default flips in 1.35, not 1.36", func(t *testing.T) {
		// CHANGELOG-1.35 Urgent Upgrade Notes: "ACTION REQUIRED: failCgroupV1
		// will be set to true from 1.35." Re-verified against the raw changelog
		// on 2026-07-22 after two sessions disagreed. Placing it in 1.36 hides
		// the advisory from every 1.34 -> 1.35 upgrade.
		bc, ok := BreakingChangeByID("cgroup-v1-fails-closed")
		if !ok {
			t.Fatal("cgroup-v1-fails-closed advisory missing")
		}
		if bc.ReleaseMinor != "1.35" {
			t.Errorf("cgroup-v1-fails-closed ReleaseMinor = %q, want 1.35 (primary source: CHANGELOG-1.35 urgent upgrade notes)", bc.ReleaseMinor)
		}
	})

	t.Run("kubeadm 1.36 external etcd minimum is 3.5.24", func(t *testing.T) {
		components, ok := ComponentsFor("1.36")
		if !ok {
			t.Fatal("no component data for Kubernetes 1.36")
		}
		if components.MinExternalEtcdVersion != "3.5.24-0" {
			t.Errorf("minimum external etcd = %q, want 3.5.24-0", components.MinExternalEtcdVersion)
		}
		if _, exists := BreakingChangeByID("etcd-36-required"); exists {
			t.Error("obsolete etcd-36-required advisory still exists")
		}
	})
}

func TestBreakingChangeMetadata(t *testing.T) {
	seen := map[string]bool{}
	for _, bc := range breakingChanges {
		if seen[bc.ID] {
			t.Errorf("duplicate BreakingChange ID %q", bc.ID)
		}
		seen[bc.ID] = true

		if bc.Title == "" || bc.Detail == "" || bc.Remediation == "" {
			t.Errorf("BreakingChange %q is missing Title, Detail, or Remediation", bc.ID)
		}
		if _, _, ok := splitMinor(bc.ReleaseMinor); !ok {
			t.Errorf("BreakingChange %q has unparseable ReleaseMinor %q", bc.ID, bc.ReleaseMinor)
		}
	}
}

// lower is a local ASCII lowercase helper so the test does not depend on the
// implementation's own string handling.
func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// TestRelease137Facts pins the 1.37 data to CHANGELOG-1.37 (v1.37.0) and
// kubeadm's constants at the v1.37.0 tag, both read 2026-10-22.
func TestRelease137Facts(t *testing.T) {
	ids := map[string]bool{}
	for _, bc := range BreakingChangesBetween("1.36", "1.37") {
		ids[bc.ID] = true
	}
	for _, want := range []string{
		"selinux-mount-ga", "kubelet-event-qps-zero-unlimited", "kubelet-cadvisor-flags-removed",
		"static-pod-api-references-prohibited", "kubeadm-v1beta3-removed", "removed-feature-gates-137",
	} {
		if !ids[want] {
			t.Errorf("1.36 -> 1.37 is missing breaking change %q", want)
		}
	}
	if ids["cgroup-v1-fails-closed"] {
		t.Error("cgroup-v1-fails-closed belongs to 1.35, not the 1.36 -> 1.37 path")
	}

	rc, ok := ComponentsFor("1.37")
	if !ok {
		t.Fatal("no kubeadm component data for 1.37")
	}
	if rc.EtcdVersion != "3.7.0-0" || rc.CoreDNSVersion != "v1.14.6" || rc.MinExternalEtcdVersion != "3.5.24-0" {
		t.Errorf("1.37 components = %+v, want etcd 3.7.0-0, CoreDNS v1.14.6, min external etcd 3.5.24-0", rc)
	}

	gates := map[string]bool{}
	for _, g := range FeatureGatesRemovedBetween("1.36", "1.37") {
		gates[g.Name] = true
	}
	if !gates["SidecarContainers"] || !gates["ConsistentListFromCache"] {
		t.Errorf("1.37 removed gates incomplete: %v", gates)
	}
	if BeyondHorizon("1.37") {
		t.Error("1.37 data is present, so 1.37 must be inside the data horizon")
	}
}

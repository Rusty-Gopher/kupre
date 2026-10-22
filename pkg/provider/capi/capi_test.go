package capi

import (
	"strings"
	"testing"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func md(spec map[string]any) unstructured.Unstructured {
	return unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cluster.x-k8s.io/v1beta2", "kind": "MachineDeployment",
		"metadata": map[string]any{"name": "workers", "namespace": "default"},
		"spec":     spec,
	}}
}

func TestStrategyOf(t *testing.T) {
	sixty := int64(600)

	tests := []struct {
		name      string
		spec      map[string]any
		wantSurge string
		wantUnav  string
		wantDrain *int64
	}{
		{
			// The MetaKube/legacy shape verified against the live cluster.
			name: "cluster.k8s.io spec.strategy",
			spec: map[string]any{"strategy": map[string]any{
				"type":          "RollingUpdate",
				"rollingUpdate": map[string]any{"maxSurge": int64(1), "maxUnavailable": int64(0)},
			}},
			wantSurge: "1", wantUnav: "0",
		},
		{
			name: "v1beta2 spec.rollout.strategy with percentage",
			spec: map[string]any{"rollout": map[string]any{"strategy": map[string]any{
				"type":          "RollingUpdate",
				"rollingUpdate": map[string]any{"maxSurge": "25%", "maxUnavailable": int64(1)},
			}}},
			wantSurge: "25%", wantUnav: "1",
		},
		{
			name: "v1beta2 drain timeout under deletion",
			spec: map[string]any{
				"template": map[string]any{"spec": map[string]any{
					"deletion": map[string]any{"nodeDrainTimeoutSeconds": int64(600)},
				}},
			},
			wantSurge: "1", wantUnav: "0", wantDrain: &sixty,
		},
		{
			// Absent strategy must fall back to the documented defaults, and an
			// absent drain field must stay nil - nil and zero mean different
			// things to the drain-hang check.
			name:      "defaults when nothing set",
			spec:      map[string]any{},
			wantSurge: "1", wantUnav: "0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := strategyOf(md(tt.spec))
			if s.MaxSurge != tt.wantSurge || s.MaxUnavailable != tt.wantUnav {
				t.Errorf("surge/unavail = %s/%s, want %s/%s",
					s.MaxSurge, s.MaxUnavailable, tt.wantSurge, tt.wantUnav)
			}
			switch {
			case tt.wantDrain == nil && s.DrainTimeoutSeconds != nil:
				t.Errorf("drain = %d, want nil (field absent)", *s.DrainTimeoutSeconds)
			case tt.wantDrain != nil && (s.DrainTimeoutSeconds == nil || *s.DrainTimeoutSeconds != *tt.wantDrain):
				t.Errorf("drain = %v, want %d", s.DrainTimeoutSeconds, *tt.wantDrain)
			}
		})
	}
}

// TestDrainHangVerdict pins the per-family severity split, sourced from the
// controllers themselves:
//
//   - cluster.x-k8s.io: a blocked PDB with no nodeDrainTimeout hangs the
//     rollout indefinitely (CAPI retries evictions every 20s with no
//     deadline) - blocking.
//   - cluster.k8s.io: the Kubermatic machine-controller skips eviction once a
//     machine deletion is older than -skip-eviction-after (default 2h) and
//     deletes the machine without honoring the PDB - a bounded stall plus a
//     PDB bypass, so a warning for manual review, never a blocker. See the
//     source citations on drainHangVerdict.
func TestDrainHangVerdict(t *testing.T) {
	xk8s := schema.GroupVersionResource{
		Group: "cluster.x-k8s.io", Version: "v1beta2", Resource: "machinedeployments"}
	legacy := schema.GroupVersionResource{
		Group: "cluster.k8s.io", Version: "v1alpha1", Resource: "machinedeployments"}

	noTimeout := md(map[string]any{})
	withTimeout := md(map[string]any{
		"template": map[string]any{"spec": map[string]any{
			"deletion": map[string]any{"nodeDrainTimeoutSeconds": int64(600)},
		}},
	})

	tests := []struct {
		name        string
		gvr         schema.GroupVersionResource
		mds         []unstructured.Unstructured
		blockedPDBs int
		wantStatus  analyzer.Status
		wantIn      string
	}{
		{
			name: "upstream CAPI, no timeout, blocked PDB is blocking",
			gvr:  xk8s, mds: []unstructured.Unstructured{noTimeout}, blockedPDBs: 1,
			wantStatus: analyzer.StatusFail, wantIn: "hang indefinitely",
		},
		{
			name: "upstream CAPI, no timeout, no blocked PDB warns",
			gvr:  xk8s, mds: []unstructured.Unstructured{noTimeout}, blockedPDBs: 0,
			wantStatus: analyzer.StatusWarn,
		},
		{
			name: "upstream CAPI with timeout passes",
			gvr:  xk8s, mds: []unstructured.Unstructured{withTimeout}, blockedPDBs: 1,
			wantStatus: analyzer.StatusPass,
		},
		{
			name: "Kubermatic, blocked PDB is a warning for manual review, not a blocker",
			gvr:  legacy, mds: []unstructured.Unstructured{noTimeout}, blockedPDBs: 1,
			wantStatus: analyzer.StatusWarn, wantIn: "skip-eviction",
		},
		{
			name: "Kubermatic, no blocked PDB passes",
			gvr:  legacy, mds: []unstructured.Unstructured{noTimeout}, blockedPDBs: 0,
			wantStatus: analyzer.StatusPass,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := drainHangVerdict(tt.gvr, tt.mds, tt.blockedPDBs)
			if got.Status != tt.wantStatus {
				t.Fatalf("status = %v, want %v (message: %s)", got.Status, tt.wantStatus, got.Message)
			}
			if tt.wantIn != "" && !strings.Contains(got.Message, tt.wantIn) {
				t.Errorf("message should mention %q; got: %s", tt.wantIn, got.Message)
			}
			// The Kubermatic path must never claim an indefinite hang - that
			// behavior is disproven by the controller source.
			if tt.gvr.Group == "cluster.k8s.io" && strings.Contains(got.Message+got.Remediation, "indefinitely") {
				t.Errorf("cluster.k8s.io finding claims an indefinite hang: %s", got.Message)
			}
			// A blocked-PDB Kubermatic finding is manual review by declaration.
			if tt.gvr.Group == "cluster.k8s.io" && tt.blockedPDBs > 0 {
				if got.OverrideAction == nil || *got.OverrideAction != analyzer.ActionVerifyManually {
					t.Errorf("expected the finding to be rebucketed to verify-manually")
				}
			}
		})
	}
}

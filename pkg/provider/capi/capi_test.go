package capi

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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

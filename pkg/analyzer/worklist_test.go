package analyzer

import (
	"context"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestFindingBucket(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		action   Action
		result   *Result
		checkErr string
		want     Bucket
	}{
		{
			name:     "blocking and quick goes to the top",
			severity: SeverityError, action: ActionFixBeforeStart,
			result: Fail("bad"), want: BucketFixBeforeStart,
		},
		{
			name:     "blocking but slow goes to plan-ahead",
			severity: SeverityError, action: ActionPlanAhead,
			result: Fail("bad"), want: BucketPlanAhead,
		},
		{
			// The guarantee: anything blocking lands in the first two sections,
			// whatever Action it declared. Otherwise a misfiled Action could
			// bury an upgrade-stopping finding in the collapsed tail.
			name:     "blocking with a review-later action is still escalated",
			severity: SeverityError, action: ActionReviewLater,
			result: Fail("bad"), want: BucketFixBeforeStart,
		},
		{
			name:     "warning with plan-ahead needs lead time",
			severity: SeverityWarning, action: ActionPlanAhead,
			result: Warn("hmm"), want: BucketPlanAhead,
		},
		{
			name:     "warning that is pre-existing degradation",
			severity: SeverityWarning, action: ActionResolveFirst,
			result: Warn("hmm"), want: BucketResolveFirst,
		},
		{
			name:     "unverifiable advisory",
			severity: SeverityWarning, action: ActionVerifyManually,
			result: Warn("hmm"), want: BucketVerifyManually,
		},
		{
			name:     "plain warning is review-later",
			severity: SeverityWarning, action: ActionReviewLater,
			result: Warn("hmm"), want: BucketReviewLater,
		},
		{
			name:     "failure at warning severity does not block, keeps its action",
			severity: SeverityWarning, action: ActionResolveFirst,
			result: Fail("bad"), want: BucketResolveFirst,
		},
		{name: "pass has no bucket", severity: SeverityError, result: Pass("ok"), want: BucketNone},
		{name: "skip has no bucket", severity: SeverityError, result: Skip("n/a"), want: BucketNone},
		{name: "errored check is inconclusive", checkErr: "boom", want: BucketInconclusive},
		{name: "nil result is inconclusive", want: BucketInconclusive},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := Finding{
				Check: "t", Severity: tt.severity, Action: tt.action,
				Result: tt.result, Error: tt.checkErr,
			}
			if got := f.Bucket(); got != tt.want {
				t.Errorf("Bucket() = %v (%q), want %v (%q)",
					got, got.Title(), tt.want, tt.want.Title())
			}
		})
	}
}

func TestWorklistOrderAndCompleteness(t *testing.T) {
	r := &Report{
		Findings: []Finding{
			{Check: "later", Severity: SeverityWarning, Action: ActionReviewLater, Result: Warn("x")},
			{Check: "manual", Severity: SeverityWarning, Action: ActionVerifyManually, Result: Warn("x")},
			{Check: "blocking", Severity: SeverityError, Action: ActionFixBeforeStart, Result: Fail("x")},
			{Check: "hygiene", Severity: SeverityWarning, Action: ActionResolveFirst, Result: Warn("x")},
			{Check: "lead", Severity: SeverityWarning, Action: ActionPlanAhead, Result: Warn("x")},
			{Check: "passing", Severity: SeverityError, Result: Pass("x")},
		},
	}

	got := r.Worklist()
	want := []Bucket{
		BucketFixBeforeStart, BucketPlanAhead,
		BucketVerifyManually, BucketResolveFirst, BucketReviewLater,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d groups, want %d", len(got), len(want))
	}
	for i, b := range want {
		if got[i].Bucket != b {
			t.Errorf("group %d = %q, want %q", i, got[i].Bucket.Title(), b.Title())
		}
	}

	// Every non-passing finding must appear exactly once. A finding that falls
	// out of the worklist is a finding the operator never sees.
	seen := 0
	for _, g := range got {
		seen += len(g.Findings)
	}
	if seen != 5 {
		t.Errorf("worklist holds %d findings, want 5 (the passing one is excluded)", seen)
	}
}

func TestEveryNonPassingFindingReachesTheWorklist(t *testing.T) {
	c := clusterFromFixtures(t, "blocking_pdb.yaml", "gitrepo_pod.yaml", "stale_kubelet_node.yaml")
	up := Upgrade{From: MustParseVersion("1.35.3"), To: MustParseVersion("1.36.0")}
	rep := NewEngine(AllChecks()...).Run(context.Background(), c, up)

	inWorklist := map[string]bool{}
	for _, g := range rep.Worklist() {
		for _, f := range g.Findings {
			inWorklist[f.Check] = true
		}
	}

	for _, f := range rep.Findings {
		interesting := f.Error != "" || f.Blocking() || f.Concerning()
		if interesting && !inWorklist[f.Check] {
			t.Errorf("finding %q is interesting but absent from the worklist", f.Check)
		}
	}
}

// pdbWithSelector builds a PDB whose selector matches the given labels.
func pdbWithSelector(name string, lbls map[string]string, expected, healthy, desired int32) *policyv1.PodDisruptionBudget {
	ma := intstr.FromInt32(desired)
	return &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MinAvailable: &ma,
			Selector:     &metav1.LabelSelector{MatchLabels: lbls},
		},
		Status: policyv1.PodDisruptionBudgetStatus{
			ObservedGeneration: 1, ExpectedPods: expected,
			CurrentHealthy: healthy, DesiredHealthy: desired, DisruptionsAllowed: 0,
		},
	}
}

// deployWithLabels builds a Deployment whose pod template carries lbls.
func deployWithLabels(name string, replicas int32, lbls map[string]string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Template: corePodTemplate(lbls),
		},
	}
}

func TestScaleCommandsAreCorrectOrAbsent(t *testing.T) {
	lbls := map[string]string{"app": "api"}

	tests := []struct {
		name        string
		pdb         *policyv1.PodDisruptionBudget
		deploy      *appsv1.Deployment
		wantContain string
		wantAbsent  string
	}{
		{
			// All pods healthy but only one replica: scaling genuinely helps.
			name:        "under-replicated workload gets a scale command",
			pdb:         pdbWithSelector("api", lbls, 1, 1, 1),
			deploy:      deployWithLabels("api-deploy", 1, lbls),
			wantContain: "kubectl scale deployment/api-deploy -n default --replicas=2",
		},
		{
			// Enough replicas, but one is unhealthy. Scaling is a no-op here -
			// suggesting it would send the operator down the wrong path.
			name:        "unhealthy pods get an inspect command, never a scale",
			pdb:         pdbWithSelector("api", lbls, 2, 1, 1),
			deploy:      deployWithLabels("api-deploy", 2, lbls),
			wantContain: "repair these, do not scale",
			wantAbsent:  "kubectl scale",
		},
		{
			// Already above the requirement; scaling would change nothing.
			name:       "sufficiently scaled workload gets no scale command",
			pdb:        pdbWithSelector("api", lbls, 3, 3, 1),
			deploy:     deployWithLabels("api-deploy", 3, lbls),
			wantAbsent: "kubectl scale",
		},
		{
			// The selector matches nothing, so the workload cannot be named.
			// Guessing from the PDB's name would be wrong.
			name:       "unresolvable workload is not guessed at",
			pdb:        pdbWithSelector("api", map[string]string{"app": "other"}, 1, 1, 1),
			deploy:     deployWithLabels("api-deploy", 1, lbls),
			wantAbsent: "kubectl scale",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestCluster(tt.pdb, tt.deploy)
			got, err := checkPDBBlocksDrain(context.Background(), c, testUpgrade())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			joined := strings.Join(got.Commands, "\n")

			if tt.wantContain != "" && !strings.Contains(joined, tt.wantContain) {
				t.Errorf("commands missing %q:\n%s", tt.wantContain, joined)
			}
			if tt.wantAbsent != "" && strings.Contains(joined, tt.wantAbsent) {
				t.Errorf("commands should not contain %q:\n%s", tt.wantAbsent, joined)
			}
		})
	}
}

// corePodTemplate builds a pod template spec carrying the given labels.
func corePodTemplate(lbls map[string]string) corev1.PodTemplateSpec {
	return corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{Labels: lbls},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "busybox"}}},
	}
}

// TestResultActionOverride guards the per-outcome reclassification: a check
// whose possible results differ in urgency can rebucket a specific outcome,
// but a blocking finding can never demote itself out of the top sections.
func TestResultActionOverride(t *testing.T) {
	warned := Finding{
		Check: "two-outcome", Severity: SeverityError, Action: ActionPlanAhead,
		Result: Warn("stale but harmless").WithAction(ActionReviewLater),
	}
	if got := warned.Bucket(); got != BucketReviewLater {
		t.Errorf("overridden warn bucket = %q, want review-later", got.Title())
	}

	// The escalation invariant survives the override mechanism.
	blocking := Finding{
		Check: "still-blocking", Severity: SeverityError, Action: ActionPlanAhead,
		Result: Fail("broken").WithAction(ActionReviewLater),
	}
	if got := blocking.Bucket(); got != BucketFixBeforeStart {
		t.Errorf("blocking finding demoted itself to %q - must stay in the top sections", got.Title())
	}
}

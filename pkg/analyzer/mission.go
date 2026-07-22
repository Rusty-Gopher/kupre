package analyzer

// Mission is one of kupre's analysis modes. All missions share the same
// engine, evidence model, worklist and report formats; a mission decides which
// checks run, whether a target version is needed, and how the worklist
// sections are titled for its context.
type Mission struct {
	// Name is the stable identifier: "upgrade", "health", "certs".
	Name string
	// Title is the human heading.
	Title string
	// Description is one line for pickers.
	Description string
	// NeedsTarget reports whether the mission compares against a target
	// Kubernetes version. Missions without one analyze the cluster as it is.
	NeedsTarget bool
	// Checks returns the mission's analyzer-level check suite.
	Checks func() []Check
	// ProviderChecks filters which provider checks join this mission, by check
	// name. Nil means none; the upgrade mission accepts all.
	ProviderChecks func(name string) bool
	// BucketTitles overrides worklist section titles for this mission's
	// context. Missing buckets fall back to the upgrade-era defaults.
	BucketTitles map[Bucket]string
}

// Missions returns every mission, in presentation order.
func Missions() []Mission {
	return []Mission{
		{
			Name:        "upgrade",
			Title:       "Upgrade preflight",
			Description: "Is this cluster ready to upgrade to a target Kubernetes version?",
			NeedsTarget: true,
			Checks:      AllChecks,
			// The upgrade mission runs every provider check.
			ProviderChecks: func(string) bool { return true },
		},
		{
			Name:        "health",
			Title:       "Health check",
			Description: "What is wrong with this cluster right now, and why?",
			NeedsTarget: false,
			Checks:      HealthChecks,
			ProviderChecks: func(name string) bool {
				// Provider checks that describe current health rather than
				// upgrade readiness.
				switch name {
				case "openstack-cinder-csi-health", "openstack-loadbalancer-health",
					"openstack-node-provider-id", "capi-machines-consistent":
					return true
				}
				return false
			},
			BucketTitles: map[Bucket]string{
				BucketFixBeforeStart: "BROKEN: fix now",
				BucketPlanAhead:      "AT RISK: address soon",
				BucketVerifyManually: "VERIFY BY HAND: kupre cannot check these",
				BucketResolveFirst:   "DEGRADED: investigate",
				BucketReviewLater:    "HYGIENE: when you have time",
			},
		},
		{
			Name:        "certs",
			Title:       "Certificate audit",
			Description: "Every certificate a read-only client can see, and when it expires.",
			NeedsTarget: false,
			Checks:      CertAuditChecks,
			BucketTitles: map[Bucket]string{
				BucketFixBeforeStart: "EXPIRED OR BROKEN: fix now",
				BucketPlanAhead:      "EXPIRING SOON: renew now",
				BucketVerifyManually: "VERIFY BY HAND: kupre cannot check these",
				BucketResolveFirst:   "DEGRADED: investigate",
				BucketReviewLater:    "HYGIENE: when you have time",
			},
		},
	}
}

// MissionByName looks a mission up; ok is false for unknown names.
func MissionByName(name string) (Mission, bool) {
	for _, m := range Missions() {
		if m.Name == name {
			return m, true
		}
	}
	return Mission{}, false
}

// TitleFor renders a bucket's section title in a mission's vocabulary. An
// empty mission name falls back to the upgrade titles, which keeps every
// pre-mission call site working unchanged.
func (b Bucket) TitleFor(missionName string) string {
	if m, ok := MissionByName(missionName); ok && m.BucketTitles != nil {
		if t, ok := m.BucketTitles[b]; ok {
			return t
		}
	}
	return b.Title()
}

package analyzer

// AllChecks returns every built-in, cloud-agnostic check. Provider-specific
// checks are appended separately by the provider registry.
func AllChecks() []Check {
	var out []Check
	out = append(out, APIChecks()...)
	out = append(out, WorkloadChecks()...)
	out = append(out, NodeChecks()...)
	out = append(out, WebhookChecks()...)
	out = append(out, StorageChecks()...)
	out = append(out, ReleaseChecks()...)
	out = append(out, HelmChecks()...)
	out = append(out, MetricsChecks()...)
	out = append(out, CertChecks()...)
	out = append(out, PlatformChecks()...)
	out = append(out, CoreDNSChecks()...)
	out = append(out, LifecycleChecks()...)
	out = append(out, AddonChecks()...)
	return out
}

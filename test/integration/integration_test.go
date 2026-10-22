//go:build integration

// Package integration runs the kupre binary end to end against a real,
// disposable cluster (kind in CI). It is the only place the product is tested
// as users run it: real discovery, real RBAC, real pagination, real exit codes.
//
// Run with:
//
//	kind create cluster --name kupre-it
//	KUBECONFIG=$(kind get kubeconfig-path) make integration
//
// The tests write fixtures into the cluster with kubectl. kupre itself stays
// read-only; only this harness mutates, and only inside its own namespace plus
// one IngressClass and the deploy/rbac.yaml objects.
package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const ns = "kupre-it"

var (
	bin        string // path to the kupre binary under test
	kubeconfig string
	repoRoot   string
)

type finding struct {
	Check  string `json:"check"`
	Status string `json:"status"`
	Error  string `json:"error"`
}

type report struct {
	Upgrade struct {
		From string `json:"from"`
		To   string `json:"to"`
	} `json:"upgrade"`
	Verdict  string    `json:"verdict"`
	ExitCode int       `json:"exitCode"`
	Findings []finding `json:"findings"`
	Errors   []string  `json:"errors"`
}

func (r report) status(check string) string {
	for _, f := range r.Findings {
		if f.Check == check {
			return f.Status
		}
	}
	return ""
}

func TestMain(m *testing.M) {
	kubeconfig = os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		// An integration run without a cluster must fail loudly, never pass
		// by running nothing.
		fmt.Fprintln(os.Stderr, "integration: KUBECONFIG must point at a disposable cluster")
		os.Exit(1)
	}
	_, file, _, _ := runtime.Caller(0)
	repoRoot = filepath.Join(filepath.Dir(file), "..", "..")

	dir, err := os.MkdirTemp("", "kupre-it")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	bin = filepath.Join(dir, "kupre")
	build := exec.Command("go", "build", "-o", bin, "./cmd/kupre")
	build.Dir = repoRoot
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build kupre: %v\n%s", err, out)
		os.Exit(1)
	}

	if err := setupFixtures(); err != nil {
		fmt.Fprintln(os.Stderr, "fixtures:", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func kubectl(args ...string) (string, error) {
	// stdout only: kubectl prints warnings (version skew and the like) on
	// stderr, and callers parse what comes back.
	cmd := exec.Command("kubectl", append([]string{"--kubeconfig", kubeconfig}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return string(out), fmt.Errorf("kubectl %s: %w\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return string(out), nil
}

func kubectlApply(manifest string) error {
	cmd := exec.Command("kubectl", "--kubeconfig", kubeconfig, "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("kubectl apply: %w\n%s", err, out)
	}
	return nil
}

// setupFixtures plants known upgrade hazards: a single-replica workload behind
// a PDB that permits zero evictions, and an IngressClass bound to the retired
// ingress-nginx controller.
func setupFixtures() error {
	manifest := `
apiVersion: v1
kind: Namespace
metadata:
  name: ` + ns + `
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pinned
  namespace: ` + ns + `
spec:
  replicas: 1
  selector:
    matchLabels: {app: pinned}
  template:
    metadata:
      labels: {app: pinned}
    spec:
      containers:
        - name: pause
          image: registry.k8s.io/pause:3.10
          resources:
            requests: {cpu: 1m, memory: 4Mi}
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: pinned
  namespace: ` + ns + `
spec:
  minAvailable: 1
  selector:
    matchLabels: {app: pinned}
`
	if err := kubectlApply(manifest); err != nil {
		return err
	}
	if _, err := kubectl("apply", "-f", filepath.Join(repoRoot, "testdata", "ingress_nginx_class.yaml")); err != nil {
		return err
	}
	if _, err := kubectl("apply", "-f", filepath.Join(repoRoot, "deploy", "rbac.yaml")); err != nil {
		return err
	}
	if _, err := kubectl("-n", ns, "rollout", "status", "deployment/pinned", "--timeout=180s"); err != nil {
		return err
	}
	// The disruption controller fills in status asynchronously; the drain
	// check reads disruptionsAllowed, so wait until it has been computed.
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		out, err := kubectl("-n", ns, "get", "pdb", "pinned", "-o", "jsonpath={.status.currentHealthy}")
		if err == nil && strings.TrimSpace(out) == "1" {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return errors.New("PDB status was never computed")
}

// run executes kupre with the given args against cfg and decodes its JSON.
func run(t *testing.T, cfg string, args ...string) (report, int) {
	t.Helper()
	args = append(args, "--kubeconfig", cfg, "-o", "json")
	cmd := exec.Command(bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run kupre %v: %v", args, err)
	}
	var r report
	if jerr := json.Unmarshal(stdout.Bytes(), &r); jerr != nil {
		t.Fatalf("kupre %v (exit %d) did not emit JSON: %v\nstdout: %s\nstderr: %s",
			args, code, jerr, stdout.String(), stderr.String())
	}
	if code != r.ExitCode {
		t.Errorf("process exit %d disagrees with JSON exitCode %d", code, r.ExitCode)
	}
	return r, code
}

// nextMinor returns the minor after the cluster's own, e.g. "1.36.4" -> "1.37.0".
func nextMinor(t *testing.T) string {
	t.Helper()
	out, err := kubectl("version", "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		ServerVersion struct {
			Major, Minor string
		} `json:"serverVersion"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatal(err)
	}
	var major, minor int
	fmt.Sscanf(v.ServerVersion.Major, "%d", &major)
	fmt.Sscanf(strings.TrimSuffix(v.ServerVersion.Minor, "+"), "%d", &minor)
	return fmt.Sprintf("%d.%d.0", major, minor+1)
}

func TestUpgradeMissionAdmin(t *testing.T) {
	r, code := run(t, kubeconfig, "check", "--target-version", nextMinor(t))
	if len(r.Errors) > 0 {
		t.Fatalf("scan reported tool errors: %v", r.Errors)
	}
	for _, f := range r.Findings {
		if f.Error != "" {
			t.Errorf("check %s errored on an admin kubeconfig: %s", f.Check, f.Error)
		}
	}
	if r.status("pdb-blocks-drain") != "fail" {
		t.Errorf("pdb-blocks-drain = %q, want fail for a PDB permitting zero evictions", r.status("pdb-blocks-drain"))
	}
	if got := r.status("ingress-nginx-retired"); got != "warn" {
		t.Errorf("ingress-nginx-retired = %q, want warn for an ingress-nginx IngressClass", got)
	}
	if code != 1 || r.Verdict != "blocked" {
		t.Errorf("verdict %q exit %d, want blocked exit 1", r.Verdict, code)
	}
}

func TestHealthAndCertsMissionsComplete(t *testing.T) {
	for _, mission := range []string{"health", "certs"} {
		t.Run(mission, func(t *testing.T) {
			r, code := run(t, kubeconfig, mission)
			if len(r.Errors) > 0 || r.Verdict == "inconclusive" || code == 3 {
				t.Fatalf("%s did not complete: verdict %q exit %d errors %v", mission, r.Verdict, code, r.Errors)
			}
			if len(r.Findings) == 0 {
				t.Fatalf("%s ran no checks", mission)
			}
		})
	}
}

func TestBeyondDataHorizonIsNeverReady(t *testing.T) {
	// A target far past any data kupre carries must not come back clean.
	r, _ := run(t, kubeconfig, "check", "--target-version", "1.99.0")
	if r.Verdict == "ready" {
		t.Fatal("a target beyond the deprecation data horizon was reported ready")
	}
}

// tokenKubeconfig writes a kubeconfig that authenticates as the given service
// account, reusing the admin kubeconfig's server and CA.
func tokenKubeconfig(t *testing.T, namespace, sa string) string {
	t.Helper()
	token, err := kubectl("-n", namespace, "create", "token", sa, "--duration=10m")
	if err != nil {
		t.Fatal(err)
	}
	server, err := kubectl("config", "view", "--minify", "--raw", "-o", "jsonpath={.clusters[0].cluster.server}")
	if err != nil {
		t.Fatal(err)
	}
	ca, err := kubectl("config", "view", "--minify", "--raw", "-o", "jsonpath={.clusters[0].cluster.certificate-authority-data}")
	if err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: it
  cluster:
    server: %s
    certificate-authority-data: %s
users:
- name: %s
  user:
    token: %s
contexts:
- name: it
  context: {cluster: it, user: %s}
current-context: it
`, server, ca, sa, strings.TrimSpace(token), sa)
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLeastPrivilegeRBACCompletes(t *testing.T) {
	cfg := tokenKubeconfig(t, "kube-system", "kupre")
	r, code := run(t, cfg, "check", "--target-version", nextMinor(t))
	if len(r.Errors) > 0 || code == 3 {
		t.Fatalf("deploy/rbac.yaml is not sufficient for a complete scan: exit %d errors %v", code, r.Errors)
	}
	if r.status("pdb-blocks-drain") != "fail" {
		t.Errorf("pdb-blocks-drain = %q under deploy/rbac.yaml, want fail", r.status("pdb-blocks-drain"))
	}
}

func TestNoPermissionsIsNeverReady(t *testing.T) {
	if err := kubectlApply("apiVersion: v1\nkind: ServiceAccount\nmetadata: {name: nobody, namespace: " + ns + "}\n"); err != nil {
		t.Fatal(err)
	}
	cfg := tokenKubeconfig(t, ns, "nobody")
	r, code := run(t, cfg, "check", "--target-version", nextMinor(t))
	if r.Verdict == "ready" || code == 0 {
		t.Fatalf("a service account with no RBAC was reported ready (exit %d)", code)
	}
	for _, f := range r.Findings {
		if f.Status == "pass" && (f.Check == "pdb-blocks-drain" || f.Check == "ingress-nginx-retired") {
			t.Errorf("%s passed without permission to read its inputs", f.Check)
		}
	}
}

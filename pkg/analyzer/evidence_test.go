package analyzer

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// encodeHelmRelease builds a payload exactly as Helm's encodeRelease does:
// JSON → gzip → base64. (The Kubernetes Secret layer is client-go's concern.)
func encodeHelmRelease(t *testing.T, rel map[string]any, compress bool) []byte {
	t.Helper()
	raw, err := json.Marshal(rel)
	if err != nil {
		t.Fatal(err)
	}
	if compress {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(raw); err != nil {
			t.Fatal(err)
		}
		zw.Close()
		raw = buf.Bytes()
	}
	return []byte(base64.StdEncoding.EncodeToString(raw))
}

func TestDecodeHelmRelease(t *testing.T) {
	rel := map[string]any{
		"name": "demo", "namespace": "default", "version": 3,
		"manifest": "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata:\n  name: legacy\n",
		"info":     map[string]any{"status": "deployed"},
		"chart": map[string]any{"metadata": map[string]any{
			"name": "demo-chart", "version": "1.2.3",
		}},
	}

	for _, compressed := range []bool{true, false} {
		got, err := decodeHelmRelease(encodeHelmRelease(t, rel, compressed))
		if err != nil {
			t.Fatalf("compressed=%v: %v", compressed, err)
		}
		if got.Name != "demo" || got.Version != 3 || got.Chart.Metadata.Name != "demo-chart" {
			t.Errorf("compressed=%v: decoded %+v", compressed, got)
		}
		if !strings.Contains(got.Manifest, "batch/v1beta1") {
			t.Errorf("compressed=%v: manifest lost original apiVersion", compressed)
		}
	}

	if _, err := decodeHelmRelease([]byte("not base64 at all!!")); err == nil {
		t.Error("garbage input should fail, not decode")
	}
}

func TestManifestDocs(t *testing.T) {
	manifest := `# Source: chart/templates/a.yaml
apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: legacy-job
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fine
---
this is not yaml at all {{{
---
`
	docs := manifestDocs(manifest)
	if len(docs) != 2 {
		t.Fatalf("parsed %d docs, want 2 (the broken one skipped, not fatal)", len(docs))
	}
	if docs[0].APIVersion != "batch/v1beta1" || docs[0].Metadata.Name != "legacy-job" {
		t.Errorf("first doc = %+v", docs[0])
	}
}

func TestHelmReleaseRemovedAPIs(t *testing.T) {
	legacy := map[string]any{
		"name": "legacy-app", "namespace": "prod", "version": 2,
		"manifest": "apiVersion: policy/v1beta1\nkind: PodSecurityPolicy\nmetadata:\n  name: restricted\n",
		"chart": map[string]any{"metadata": map[string]any{
			"name": "old-chart", "version": "0.9.0",
		}},
	}
	clean := map[string]any{
		"name": "clean-app", "namespace": "prod", "version": 5,
		"manifest": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n",
		"chart": map[string]any{"metadata": map[string]any{
			"name": "new-chart", "version": "2.0.0",
		}},
	}
	secret := func(name string, rel map[string]any) *corev1.Secret {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "sh.helm.release.v1." + name, Namespace: "prod"},
			Type:       "helm.sh/release.v1",
			Data:       map[string][]byte{"release": encodeHelmRelease(t, rel, true)},
		}
	}

	// The fake clientset ignores field selectors, which is fine here: only
	// helm-typed secrets are seeded.
	c := newTestCluster(secret("legacy-app.v2", legacy), secret("clean-app.v5", clean))
	up := Upgrade{From: MustParseVersion("1.24.0"), To: MustParseVersion("1.25.0")}

	got, err := checkHelmReleaseRemovedAPIs(context.Background(), c, up)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Status != StatusFail {
		t.Fatalf("status = %v, want Fail: %s", got.Status, got.Message)
	}
	if len(got.Resources) != 1 {
		t.Fatalf("resources = %d, want exactly the PSP from the legacy release", len(got.Resources))
	}
	if !strings.Contains(got.Resources[0].Detail, "old-chart") {
		t.Errorf("finding should name the owning chart: %s", got.Resources[0].Detail)
	}
}

func TestHelmReleaseLatestRevisionWins(t *testing.T) {
	old := map[string]any{
		"name": "app", "namespace": "prod", "version": 1,
		"manifest": "apiVersion: policy/v1beta1\nkind: PodSecurityPolicy\nmetadata:\n  name: psp\n",
		"chart":    map[string]any{"metadata": map[string]any{"name": "c", "version": "1"}},
	}
	fixed := map[string]any{
		"name": "app", "namespace": "prod", "version": 2,
		"manifest": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n",
		"chart":    map[string]any{"metadata": map[string]any{"name": "c", "version": "2"}},
	}
	mk := func(n string, rel map[string]any) *corev1.Secret {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: n, Namespace: "prod"},
			Type:       "helm.sh/release.v1",
			Data:       map[string][]byte{"release": encodeHelmRelease(t, rel, true)},
		}
	}
	c := newTestCluster(mk("sh.helm.release.v1.app.v1", old), mk("sh.helm.release.v1.app.v2", fixed))
	up := Upgrade{From: MustParseVersion("1.24.0"), To: MustParseVersion("1.25.0")}

	got, err := checkHelmReleaseRemovedAPIs(context.Background(), c, up)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Revision 1 used a removed API but revision 2 fixed it; superseded history
	// must not be reported as a live problem.
	if got.Status != StatusPass {
		t.Errorf("status = %v, want Pass - only the latest revision matters: %s", got.Status, got.Message)
	}
}

func TestParseDeprecatedAPIMetrics(t *testing.T) {
	raw := []byte(`# HELP apiserver_requested_deprecated_apis [STABLE] Gauge of deprecated APIs...
# TYPE apiserver_requested_deprecated_apis gauge
apiserver_requested_deprecated_apis{group="",removed_release="",resource="endpoints",subresource="",version="v1"} 1
apiserver_requested_deprecated_apis{group="policy",removed_release="1.25",resource="podsecuritypolicies",subresource="",version="v1beta1"} 1
apiserver_request_total{code="200",resource="endpoints"} 941
`)
	uses := parseDeprecatedAPIMetrics(raw)
	if len(uses) != 2 {
		t.Fatalf("parsed %d series, want 2", len(uses))
	}
	// Output order is by group/version, not input order; index by resource.
	byResource := map[string]deprecatedAPIUse{}
	for _, u := range uses {
		byResource[u.Resource] = u
	}
	if u := byResource["endpoints"]; u.GroupVersion() != "v1" || u.RemovedRelease != "" {
		t.Errorf("endpoints series = %+v", u)
	}
	if u := byResource["podsecuritypolicies"]; u.GroupVersion() != "policy/v1beta1" || u.RemovedRelease != "1.25" {
		t.Errorf("psp series = %+v", u)
	}
}

func TestDeprecatedAPIRequestsSplitsByRemovalRelease(t *testing.T) {
	up := Upgrade{From: MustParseVersion("1.24.0"), To: MustParseVersion("1.25.0")}

	uses := []deprecatedAPIUse{
		{Group: "policy", Version: "v1beta1", Resource: "podsecuritypolicies", RemovedRelease: "1.25"},
		{Group: "", Version: "v1", Resource: "endpoints", RemovedRelease: ""},
	}
	// Drive the classification logic the check applies, without a live /metrics.
	breaking := 0
	for _, u := range uses {
		if u.RemovedRelease == "" {
			continue
		}
		if v, err := ParseVersion(u.RemovedRelease); err == nil && up.Crosses(v) {
			breaking++
		}
	}
	if breaking != 1 {
		t.Errorf("breaking = %d, want 1 (PSP crosses, endpoints never removed)", breaking)
	}
}

// testCertPEM builds a self-signed cert expiring at the given time.
func testCertPEM(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestTrustBundleExpiry(t *testing.T) {
	fail := admissionv1.Fail
	mkWebhook := func(name string, ca []byte) *admissionv1.ValidatingWebhookConfiguration {
		return &admissionv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Webhooks: []admissionv1.ValidatingWebhook{{
				Name: name + ".example.invalid", FailurePolicy: &fail,
				ClientConfig: admissionv1.WebhookClientConfig{CABundle: ca},
			}},
		}
	}

	tests := []struct {
		name       string
		notAfter   time.Time
		wantStatus Status
	}{
		{name: "healthy cert passes", notAfter: time.Now().Add(365 * 24 * time.Hour), wantStatus: StatusPass},
		{name: "expiring cert warns", notAfter: time.Now().Add(10 * 24 * time.Hour), wantStatus: StatusWarn},
		{name: "expired cert fails", notAfter: time.Now().Add(-24 * time.Hour), wantStatus: StatusFail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestCluster(mkWebhook("wh", testCertPEM(t, tt.notAfter)))
			got, err := checkTrustBundleExpiry(context.Background(), c, testUpgrade())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Status != tt.wantStatus {
				t.Errorf("status = %v, want %v: %s", got.Status, tt.wantStatus, got.Message)
			}
		})
	}

	t.Run("unparseable bundle is a failure, not a skip", func(t *testing.T) {
		c := newTestCluster(mkWebhook("bad", []byte("definitely not a certificate")))
		got, err := checkTrustBundleExpiry(context.Background(), c, testUpgrade())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Status != StatusFail {
			t.Errorf("status = %v, want Fail - a bundle the API server cannot parse breaks admission: %s",
				got.Status, got.Message)
		}
	})
}

func TestWebhookBackendFragility(t *testing.T) {
	fail, ignore := admissionv1.Fail, admissionv1.Ignore
	webhook := func(policy *admissionv1.FailurePolicyType, svcNS, svcName string) *admissionv1.ValidatingWebhookConfiguration {
		return &admissionv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "gate"},
			Webhooks: []admissionv1.ValidatingWebhook{{
				Name: "gate.example.invalid", FailurePolicy: policy,
				ClientConfig: admissionv1.WebhookClientConfig{
					Service: &admissionv1.ServiceReference{Namespace: svcNS, Name: svcName},
				},
			}},
		}
	}
	service := func(ns, name string, sel map[string]string) *corev1.Service {
		return &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Spec:       corev1.ServiceSpec{Selector: sel},
		}
	}
	backend := func(replicas int32, lbls map[string]string) *appsv1.Deployment {
		return &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "infra", Name: "webhook-backend"},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Template: corePodTemplate(lbls),
			},
		}
	}
	lbls := map[string]string{"app": "webhook"}

	tests := []struct {
		name       string
		objs       []any
		wantStatus Status
	}{
		{
			name:       "multi-replica backend passes",
			objs:       []any{webhook(&fail, "infra", "hooksvc"), service("infra", "hooksvc", lbls), backend(3, lbls)},
			wantStatus: StatusPass,
		},
		{
			name:       "single replica behind fail-closed webhook fails",
			objs:       []any{webhook(&fail, "infra", "hooksvc"), service("infra", "hooksvc", lbls), backend(1, lbls)},
			wantStatus: StatusFail,
		},
		{
			name:       "fail-open webhook is not this check's problem",
			objs:       []any{webhook(&ignore, "infra", "hooksvc"), service("infra", "hooksvc", lbls), backend(1, lbls)},
			wantStatus: StatusPass,
		},
		{
			name:       "missing backing service fails",
			objs:       []any{webhook(&fail, "infra", "ghost")},
			wantStatus: StatusFail,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestCluster(tt.objs...)
			got, err := checkWebhookBackendFragility(context.Background(), c, testUpgrade())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Status != tt.wantStatus {
				t.Errorf("status = %v, want %v: %s", got.Status, tt.wantStatus, got.Message)
			}
		})
	}
}

package analyzer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
)

// certManagerCertGVR is cert-manager's Certificate resource.
var certManagerCertGVR = schema.GroupVersionResource{
	Group: "cert-manager.io", Version: "v1", Resource: "certificates",
}

// Certificate freshness thresholds. An upgrade adds churn and restarts at
// exactly the moment an expiring trust anchor is hardest to debug, so the
// warning window is deliberately generous.
const (
	certExpiredIsFailure = 0
	certWarnWithin       = 30 * 24 * time.Hour
)

// CertChecks returns certificate-expiry checks. kubeadm's own preflight never
// checks expiry (it silently renews what it manages, node-locally); these
// cover what a read-only API client can actually see.
func CertChecks() []Check {
	return []Check{
		{
			Name:        "trust-bundle-expiry",
			Description: "Expiring CA bundles on webhooks, aggregated APIs, and CRD conversion",
			Category:    CategoryWebhook,
			Severity:    SeverityError,
			Action:      ActionFixBeforeStart,
			Evidence: "Parses the X.509 certificates in every caBundle: admission webhook " +
				"clientConfig, APIService spec, and CRD conversion webhook clientConfig.",
			Limits: "A caBundle is the trust anchor the API server verifies the backend " +
				"against - not the backend's serving certificate, whose expiry is invisible " +
				"here. A healthy bundle therefore does not prove the serving cert is healthy. " +
				"Bundles that fail to parse are reported, not skipped.",
			Run: checkTrustBundleExpiry,
		},
		{
			Name:        "apiserver-cert-expiry",
			Description: "The API server's serving certificate is not close to expiry",
			Category:    CategoryNode,
			Severity:    SeverityWarning,
			Action:      ActionFixBeforeStart,
			Evidence: "Reads the serving certificate chain from the TLS handshake of a new " +
				"connection to the API server endpoint kupre is already talking to.",
			Limits: "Covers one endpoint only - on an HA control plane each member serves its " +
				"own certificate and kupre sees whichever the load balancer picked. Says " +
				"nothing about etcd, kubelet, or kubeconfig client certificates, which are " +
				"not visible to a read-only API client at all.",
			Run: checkAPIServerCertExpiry,
		},
	}
}

// bundleCert is one parsed certificate from one caBundle.
type bundleCert struct {
	owner    AffectedResource
	notAfter time.Time
	subject  string
}

// parseCABundle extracts every certificate from a base64 PEM bundle.
func parseCABundle(b64 []byte) ([]*x509.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(string(b64))
	if err != nil {
		// Kubernetes delivers []byte caBundles already base64-decoded by the
		// typed client; unstructured objects deliver the base64 string. Accept
		// both by falling back to treating the input as raw PEM.
		der = b64
	}
	var certs []*x509.Certificate
	for rest := der; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return certs, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates in bundle")
	}
	return certs, nil
}

// collectTrustBundles gathers every caBundle a read-only client can see,
// tagged with its owning object.
func collectTrustBundles(ctx context.Context, c *Cluster) (bundles []bundleCert, unparseable []AffectedResource, err error) {
	add := func(owner AffectedResource, raw []byte) {
		if len(raw) == 0 {
			return
		}
		certs, perr := parseCABundle(raw)
		if perr != nil && len(certs) == 0 {
			owner.Detail = "caBundle could not be parsed: " + perr.Error()
			unparseable = append(unparseable, owner)
			return
		}
		for _, cert := range certs {
			bundles = append(bundles, bundleCert{
				owner: owner, notAfter: cert.NotAfter, subject: cert.Subject.CommonName,
			})
		}
	}

	vals, err := c.ValidatingWebhooks(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, cfg := range vals {
		for _, w := range cfg.Webhooks {
			add(AffectedResource{
				Kind: "ValidatingWebhookConfiguration", Name: cfg.Name,
				Detail: "webhook " + w.Name,
			}, w.ClientConfig.CABundle)
		}
	}
	muts, err := c.MutatingWebhooks(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, cfg := range muts {
		for _, w := range cfg.Webhooks {
			add(AffectedResource{
				Kind: "MutatingWebhookConfiguration", Name: cfg.Name,
				Detail: "webhook " + w.Name,
			}, w.ClientConfig.CABundle)
		}
	}

	crds, err := c.CustomResourceDefinitions(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, crd := range crds {
		conv := crd.Spec.Conversion
		if conv == nil || conv.Webhook == nil || conv.Webhook.ClientConfig == nil {
			continue
		}
		add(AffectedResource{
			Kind: "CustomResourceDefinition", Name: crd.Name,
			Detail: "conversion webhook",
		}, conv.Webhook.ClientConfig.CABundle)
	}

	apiServices, err := c.APIServices(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, svc := range apiServices {
		raw, found, _ := unstructuredString(svc.Object, "spec", "caBundle")
		if found && raw != "" {
			add(AffectedResource{
				Kind: "APIService", Name: svc.GetName(),
			}, []byte(raw))
		}
	}

	return bundles, unparseable, nil
}

// checkTrustBundleExpiry reports expired and soon-to-expire trust anchors.
func checkTrustBundleExpiry(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	bundles, unparseable, err := collectTrustBundles(ctx, c)
	if err != nil {
		return nil, err
	}
	if len(bundles) == 0 && len(unparseable) == 0 {
		return Skip("no caBundles found on webhooks, APIServices, or CRD conversion"), nil
	}

	now := time.Now()
	var expired, expiring []AffectedResource
	for _, b := range bundles {
		left := b.notAfter.Sub(now)
		res := b.owner
		switch {
		case left <= certExpiredIsFailure:
			res.Detail += fmt.Sprintf(" - CA %q EXPIRED %s", b.subject, b.notAfter.Format("2006-01-02"))
			expired = append(expired, res)
		case left < certWarnWithin:
			res.Detail += fmt.Sprintf(" - CA %q expires %s (%dd left)",
				b.subject, b.notAfter.Format("2006-01-02"), int(left.Hours()/24))
			expiring = append(expiring, res)
		}
	}

	switch {
	case len(expired) > 0 || len(unparseable) > 0:
		all := append(append(expired, expiring...), unparseable...)
		sortResources(all)
		return Fail("%d trust bundle problem(s): %d expired, %d unparseable",
			len(expired)+len(unparseable), len(expired), len(unparseable)).
			WithResources(all...).
			WithRemediation("An expired or broken caBundle means the API server cannot verify " +
				"that backend: fail-closed webhooks reject all matching writes, aggregated APIs " +
				"and CRD conversion stop working. During an upgrade that becomes a rolling " +
				"outage. Reissue the CA and update the bundle (cert-manager's cainjector, or " +
				"the operator that owns the object) before starting."), nil
	case len(expiring) > 0:
		sortResources(expiring)
		return Warn("%d trust bundle(s) expire within %d days", len(expiring), int(certWarnWithin.Hours()/24)).
			WithResources(expiring...).
			WithRemediation("These CAs outlive today but may not outlive the upgrade window plus " +
				"the debugging time after it. Rotate them first so certificate expiry and " +
				"upgrade fallout cannot land in the same incident."), nil
	default:
		return Pass("all %d certificate(s) across caBundles are valid for at least %d days",
			len(bundles), int(certWarnWithin.Hours()/24)), nil
	}
}

// checkAPIServerCertExpiry reads the serving certificate from a fresh TLS
// handshake against the configured API server endpoint.
func checkAPIServerCertExpiry(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	cfg := c.RESTConfig()
	if cfg == nil {
		return Skip("no client configuration available (in-process test cluster)"), nil
	}

	u, err := url.Parse(cfg.Host)
	if err != nil || u.Host == "" {
		return Skip("cannot determine the API server address from the client configuration"), nil
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}

	tlsCfg, err := rest.TLSConfigFor(cfg)
	if err != nil || tlsCfg == nil {
		tlsCfg = &tls.Config{}
	}
	if tlsCfg.ServerName == "" {
		tlsCfg.ServerName = u.Hostname()
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, tlsCfg)
	if err != nil {
		return Skip("could not complete a TLS handshake with %s: %v", host, err), nil
	}
	defer conn.Close()

	peers := conn.ConnectionState().PeerCertificates
	if len(peers) == 0 {
		return Skip("the API server presented no certificates"), nil
	}

	leaf := peers[0]
	left := time.Until(leaf.NotAfter)
	res := AffectedResource{
		Kind: "APIServer", Name: host,
		Detail: fmt.Sprintf("serving cert %q expires %s (%dd left)",
			leaf.Subject.CommonName, leaf.NotAfter.Format("2006-01-02"), int(left.Hours()/24)),
	}

	switch {
	case left <= 0:
		return Fail("the API server's serving certificate has expired").
			WithResources(res).
			WithRemediation("Every client, kubelet, and controller loses the API the moment " +
				"their connections cycle. Renew the serving certificate before doing anything " +
				"else - on kubeadm clusters, kubeadm certs renew apiserver."), nil
	case left < certWarnWithin:
		return Warn("the API server's serving certificate expires in %d days", int(left.Hours()/24)).
			WithResources(res).
			WithRemediation("Renew it now. On kubeadm clusters `kubeadm upgrade apply` renews " +
				"managed certificates itself; everywhere else an expired serving cert is a " +
				"full API outage."), nil
	default:
		return Pass("API server serving certificate is valid for %d more days", int(left.Hours()/24)), nil
	}
}

// unstructuredString reads a nested string field from an unstructured object.
func unstructuredString(obj map[string]any, fields ...string) (string, bool, error) {
	cur := any(obj)
	for _, f := range fields {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", false, nil
		}
		cur, ok = m[f]
		if !ok {
			return "", false, nil
		}
	}
	s, ok := cur.(string)
	return s, ok, nil
}

// CertAuditChecks returns the certificate-audit mission's suite: the two
// checks shared with the upgrade mission plus the audit-only ones.
func CertAuditChecks() []Check {
	out := CertChecks()
	out = append(out,
		Check{
			Name:        "tls-secret-expiry",
			Description: "Expiry of every certificate stored in a kubernetes.io/tls Secret",
			Category:    CategoryWorkload,
			Severity:    SeverityError,
			Action:      ActionFixBeforeStart,
			Evidence: "Parses the tls.crt of every Secret of type kubernetes.io/tls and " +
				"reads each certificate's NotAfter. Only the certificate is read; keys " +
				"are never parsed and never leave the cluster connection.",
			Limits: "Covers Secrets of type kubernetes.io/tls only - certificates in " +
				"Opaque secrets, mounted files, or external stores are invisible. " +
				"Requires list access on Secrets; skipped without it. Whether anything " +
				"still uses a given Secret is not evaluated.",
			Run: checkTLSSecretExpiry,
		},
		Check{
			Name:        "certmanager-certificates",
			Description: "cert-manager Certificates that are not Ready or failing renewal",
			Category:    CategoryWorkload,
			Severity:    SeverityWarning,
			Action:      ActionResolveFirst,
			Evidence: "Reads the Ready condition and renewal timestamps from " +
				"certificates.cert-manager.io resources, where cert-manager is installed.",
			Limits: "Reports cert-manager's own view of its certificates. Why an issuer " +
				"is failing (ACME limits, DNS, upstream CA) is in cert-manager's logs, " +
				"not its status.",
			Run: checkCertManagerCertificates,
		},
	)
	return out
}

// checkTLSSecretExpiry audits every TLS secret's certificate chain.
func checkTLSSecretExpiry(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	secrets, err := c.TLSSecrets(ctx)
	if err != nil {
		if apierrors.IsForbidden(err) {
			return Skip("no permission to list Secrets; grant list on secrets (see deploy/rbac.yaml)"), nil
		}
		return nil, err
	}
	if len(secrets) == 0 {
		return Skip("no kubernetes.io/tls Secrets in the cluster"), nil
	}

	now := time.Now()
	var expired, expiring, unparseable []AffectedResource
	total := 0
	for _, s := range secrets {
		crt, ok := s.Data["tls.crt"]
		if !ok || len(crt) == 0 {
			continue
		}
		certs, perr := parseCABundle(crt)
		if perr != nil && len(certs) == 0 {
			unparseable = append(unparseable, AffectedResource{
				Kind: "Secret", APIVersion: "v1", Namespace: s.Namespace, Name: s.Name,
				Detail: "tls.crt does not parse: " + perr.Error(),
			})
			continue
		}
		// The leaf is what peers validate; judge the soonest expiry in the chain.
		soonest := certs[0]
		for _, cert := range certs {
			if cert.NotAfter.Before(soonest.NotAfter) {
				soonest = cert
			}
		}
		total++
		left := soonest.NotAfter.Sub(now)
		res := AffectedResource{
			Kind: "Secret", APIVersion: "v1", Namespace: s.Namespace, Name: s.Name,
			Detail: fmt.Sprintf("%q expires %s (%dd)", soonest.Subject.CommonName,
				soonest.NotAfter.Format("2006-01-02"), int(left.Hours()/24)),
		}
		switch {
		case left <= 0:
			res.Detail = strings.Replace(res.Detail, "expires", "EXPIRED", 1)
			expired = append(expired, res)
		case left < certWarnWithin:
			expiring = append(expiring, res)
		}
	}

	switch {
	case len(expired) > 0 || len(unparseable) > 0:
		all := append(append(expired, expiring...), unparseable...)
		sortResources(all)
		return Fail("%d TLS secret problem(s): %d expired, %d unparseable",
			len(expired)+len(unparseable), len(expired), len(unparseable)).
			WithResources(all...).
			WithRemediation("Whatever serves these certificates is presenting expired or " +
				"broken material to its clients right now. Renew and update the Secret; if " +
				"cert-manager owns it, check why renewal did not happen."), nil
	case len(expiring) > 0:
		sortResources(expiring)
		return Warn("%d of %d TLS certificate(s) expire within %d days",
			len(expiring), total, int(certWarnWithin.Hours()/24)).
			WithResources(expiring...).
			WithRemediation("Renew before expiry. Certificates that renew automatically " +
				"should not appear here - presence usually means the automation is broken."), nil
	default:
		return Pass("all %d TLS certificate(s) are valid for at least %d days",
			total, int(certWarnWithin.Hours()/24)), nil
	}
}

// checkCertManagerCertificates reads cert-manager's Certificate statuses.
func checkCertManagerCertificates(ctx context.Context, c *Cluster, _ Upgrade) (*Result, error) {
	served, err := c.Serves(ctx, certManagerCertGVR)
	if err != nil {
		return nil, err
	}
	if !served {
		return Skip("cert-manager is not installed (Certificate API not served)"), nil
	}
	certs, err := c.ListGVR(ctx, certManagerCertGVR)
	switch {
	case err == nil:
	case apierrors.IsForbidden(err):
		return Skip("no permission to read cert-manager Certificates; their renewal state is unknown"), nil
	case apierrors.IsNotFound(err) || errors.Is(err, ErrNoDynamicClient):
		return Skip("cert-manager is not installed (no Certificate resources served)"), nil
	default:
		return nil, err
	}
	if len(certs) == 0 {
		return Skip("cert-manager is installed but has no Certificate resources"), nil
	}

	var notReady []AffectedResource
	for _, crt := range certs {
		conds, ok, _ := nestedSlice(crt.Object, "status", "conditions")
		if !ok {
			continue
		}
		for _, raw := range conds {
			m, ok := raw.(map[string]any)
			if !ok || m["type"] != "Ready" || m["status"] == "True" {
				continue
			}
			msg, _ := m["message"].(string)
			notReady = append(notReady, AffectedResource{
				Kind: "Certificate", APIVersion: "cert-manager.io/v1",
				Namespace: crt.GetNamespace(), Name: crt.GetName(),
				Detail: truncateDetail(msg, 150),
			})
		}
	}

	if len(notReady) == 0 {
		return Pass("all %d cert-manager Certificate(s) report Ready", len(certs)), nil
	}
	sortResources(notReady)
	return Warn("%d cert-manager Certificate(s) are not Ready", len(notReady)).
		WithResources(notReady...).
		WithRemediation("cert-manager is failing to obtain or renew these. The message is " +
			"cert-manager's own; the underlying cause (ACME rate limits, DNS-01 failures, " +
			"issuer misconfiguration) is in the cert-manager controller logs."), nil
}

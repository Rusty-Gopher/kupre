package analyzer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	storagev1 "k8s.io/api/storage/v1"
	apiextclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Cluster is a read-only handle on a Kubernetes cluster.
//
// Every accessor performs only Get/List calls. The type deliberately exposes no
// method capable of mutating cluster state, and results are memoized so that a
// full check run issues each List exactly once.
type Cluster struct {
	// Name identifies the cluster in reports; it is the kubeconfig context name.
	Name string
	// ServerVersion is the reported API server version.
	ServerVersion Version

	clientset kubernetes.Interface
	dynamic   dynamic.Interface
	discovery discovery.DiscoveryInterface
	apiext    apiextclient.Interface

	restCfg *rest.Config

	mu    sync.Mutex
	cache map[string]any
}

// Cluster deliberately does NOT export its typed or dynamic clients. Both are
// capable of Create/Update/Delete, and exposing them made "read-only by
// construction" a comment rather than a property. Checks that need a resource
// get a narrow accessor below; adding a new accessor is the intended (and
// reviewable) path, reaching into the clients is not.

// GetConfigMap reads a single ConfigMap. Results are memoized per name.
func (c *Cluster) GetConfigMap(ctx context.Context, namespace, name string) (*corev1.ConfigMap, error) {
	return memo(c, "configmap:"+namespace+"/"+name, func() (*corev1.ConfigMap, error) {
		return c.clientset.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
	})
}

// Endpoints lists all Endpoints objects across namespaces.
func (c *Cluster) Endpoints(ctx context.Context) ([]corev1.Endpoints, error) {
	return memo(c, "endpoints", func() ([]corev1.Endpoints, error) {
		return listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]corev1.Endpoints, string, error) {
			l, err := c.clientset.CoreV1().Endpoints(metav1.NamespaceAll).List(ctx, o)
			if err != nil {
				return nil, "", fmt.Errorf("list endpoints: %w", err)
			}
			return l.Items, l.Continue, nil
		})
	})
}

// Connect builds a read-only cluster handle from a kubeconfig file and context
// name. An empty kubeconfig path falls back to the standard loading rules
// (KUBECONFIG env var, then ~/.kube/config). An empty context uses the
// kubeconfig's current-context.
func Connect(ctx context.Context, kubeconfig, contextName string) (*Cluster, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules = &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig}
	}
	overrides := &clientcmd.ConfigOverrides{}
	if contextName != "" {
		overrides.CurrentContext = contextName
	}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)

	restCfg, err := cc.ClientConfig()
	if err != nil {
		// client-go's own error is opaque here and cites KUBERNETES_MASTER, an
		// env var nobody has used in years. Say where kupre actually looked.
		return nil, fmt.Errorf("no usable kubeconfig found.\n\n%s", kubeconfigHelp(kubeconfig))
	}
	// Preflight scans issue many small List calls; raise the client-side limits
	// so they are not artificially serialized.
	restCfg.QPS, restCfg.Burst = 50, 100
	if restCfg.UserAgent == "" {
		restCfg.UserAgent = "kupre (read-only preflight)"
	}
	// The API server returns deprecation warnings for exactly the APIs kupre
	// goes looking for. client-go logs them to stderr by default, which is noise
	// in table mode and corrupts JSON output. kupre reports those deprecations
	// itself, through the checks, so drop the client-go copies.
	restCfg.WarningHandler = rest.NoWarnings{}

	name := contextName
	if name == "" {
		raw, err := cc.RawConfig()
		if err == nil {
			name = raw.CurrentContext
		}
	}
	return newCluster(ctx, restCfg, name)
}

// kubeconfigHelp explains where kupre searched for a kubeconfig and how to
// point it somewhere else. Shown when config loading fails, which for a
// first-time user is the most likely thing to go wrong.
func kubeconfigHelp(explicit string) string {
	var b strings.Builder
	b.WriteString("kupre looked in this order:\n")
	if explicit != "" {
		b.WriteString(fmt.Sprintf("  1. --kubeconfig %s  (not readable, or not a valid kubeconfig)\n", explicit))
	} else {
		if env := os.Getenv("KUBECONFIG"); env != "" {
			b.WriteString(fmt.Sprintf("  1. $KUBECONFIG = %s\n", env))
		} else {
			b.WriteString("  1. $KUBECONFIG            (not set)\n")
		}
		home, err := os.UserHomeDir()
		if err == nil {
			def := filepath.Join(home, ".kube", "config")
			status := "not found"
			if _, err := os.Stat(def); err == nil {
				status = "found, but could not be parsed"
			}
			b.WriteString(fmt.Sprintf("  2. %s  (%s)\n", def, status))
		}
	}
	b.WriteString("\nPoint kupre at a cluster with any of:\n")
	b.WriteString("  kupre check --kubeconfig /path/to/kubeconfig --target-version 1.36.0\n")
	b.WriteString("  KUBECONFIG=/path/to/kubeconfig kupre check --target-version 1.36.0\n")
	b.WriteString("\nTo see the contexts in a kubeconfig:  kupre contexts --kubeconfig /path/to/kubeconfig")
	return b.String()
}

func newCluster(ctx context.Context, restCfg *rest.Config, name string) (*Cluster, error) {
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("build kubernetes client: %w", err)
	}
	dyn, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("build dynamic client: %w", err)
	}
	ext, err := apiextclient.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("build apiextensions client: %w", err)
	}

	c := &Cluster{
		Name:      name,
		restCfg:   restCfg,
		clientset: cs,
		dynamic:   dyn,
		discovery: cs.Discovery(),
		apiext:    ext,
		cache:     map[string]any{},
	}

	info, err := c.discovery.ServerVersion()
	if err != nil {
		return nil, fmt.Errorf("query server version (check connectivity and credentials): %w", err)
	}
	v, err := ParseVersion(info.GitVersion)
	if err != nil {
		return nil, fmt.Errorf("parse server version %q: %w", info.GitVersion, err)
	}
	c.ServerVersion = v
	return c, nil
}

// NewClusterForTest builds a Cluster around pre-built clients. It exists so
// unit tests can drive checks with fake clientsets.
func NewClusterForTest(cs kubernetes.Interface, version Version) *Cluster {
	return &Cluster{
		Name:          "test",
		ServerVersion: version,
		clientset:     cs,
		discovery:     cs.Discovery(),
		cache:         map[string]any{},
	}
}

// memo runs load once per key for the lifetime of the Cluster and caches both
// the value and any error.
func memo[T any](c *Cluster, key string, load func() (T, error)) (T, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if hit, ok := c.cache[key]; ok {
		e := hit.(*memoEntry[T])
		return e.val, e.err
	}
	val, err := load()
	c.cache[key] = &memoEntry[T]{val: val, err: err}
	return val, err
}

type memoEntry[T any] struct {
	val T
	err error
}

// listAll pages through a List call, accumulating every item. K8s caps page
// size server-side, so large clusters need this to avoid truncated results.
func listAll[T any](ctx context.Context, page func(context.Context, metav1.ListOptions) ([]T, string, error)) ([]T, error) {
	var out []T
	opts := metav1.ListOptions{Limit: 500}
	for {
		items, next, err := page(ctx, opts)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
		if next == "" {
			return out, nil
		}
		opts.Continue = next
	}
}

// Nodes lists all nodes.
func (c *Cluster) Nodes(ctx context.Context) ([]corev1.Node, error) {
	return memo(c, "nodes", func() ([]corev1.Node, error) {
		return listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]corev1.Node, string, error) {
			l, err := c.clientset.CoreV1().Nodes().List(ctx, o)
			if err != nil {
				return nil, "", fmt.Errorf("list nodes: %w", err)
			}
			return l.Items, l.Continue, nil
		})
	})
}

// Pods lists all pods in all namespaces.
func (c *Cluster) Pods(ctx context.Context) ([]corev1.Pod, error) {
	return memo(c, "pods", func() ([]corev1.Pod, error) {
		return listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]corev1.Pod, string, error) {
			l, err := c.clientset.CoreV1().Pods(metav1.NamespaceAll).List(ctx, o)
			if err != nil {
				return nil, "", fmt.Errorf("list pods: %w", err)
			}
			return l.Items, l.Continue, nil
		})
	})
}

// Namespaces lists all namespaces.
func (c *Cluster) Namespaces(ctx context.Context) ([]corev1.Namespace, error) {
	return memo(c, "namespaces", func() ([]corev1.Namespace, error) {
		return listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]corev1.Namespace, string, error) {
			l, err := c.clientset.CoreV1().Namespaces().List(ctx, o)
			if err != nil {
				return nil, "", fmt.Errorf("list namespaces: %w", err)
			}
			return l.Items, l.Continue, nil
		})
	})
}

// Services lists all services in all namespaces.
func (c *Cluster) Services(ctx context.Context) ([]corev1.Service, error) {
	return memo(c, "services", func() ([]corev1.Service, error) {
		return listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]corev1.Service, string, error) {
			l, err := c.clientset.CoreV1().Services(metav1.NamespaceAll).List(ctx, o)
			if err != nil {
				return nil, "", fmt.Errorf("list services: %w", err)
			}
			return l.Items, l.Continue, nil
		})
	})
}

// Deployments lists all deployments in all namespaces.
func (c *Cluster) Deployments(ctx context.Context) ([]appsv1.Deployment, error) {
	return memo(c, "deployments", func() ([]appsv1.Deployment, error) {
		return listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]appsv1.Deployment, string, error) {
			l, err := c.clientset.AppsV1().Deployments(metav1.NamespaceAll).List(ctx, o)
			if err != nil {
				return nil, "", fmt.Errorf("list deployments: %w", err)
			}
			return l.Items, l.Continue, nil
		})
	})
}

// DaemonSets lists all daemonsets in all namespaces.
func (c *Cluster) DaemonSets(ctx context.Context) ([]appsv1.DaemonSet, error) {
	return memo(c, "daemonsets", func() ([]appsv1.DaemonSet, error) {
		return listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]appsv1.DaemonSet, string, error) {
			l, err := c.clientset.AppsV1().DaemonSets(metav1.NamespaceAll).List(ctx, o)
			if err != nil {
				return nil, "", fmt.Errorf("list daemonsets: %w", err)
			}
			return l.Items, l.Continue, nil
		})
	})
}

// StatefulSets lists all statefulsets in all namespaces.
func (c *Cluster) StatefulSets(ctx context.Context) ([]appsv1.StatefulSet, error) {
	return memo(c, "statefulsets", func() ([]appsv1.StatefulSet, error) {
		return listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]appsv1.StatefulSet, string, error) {
			l, err := c.clientset.AppsV1().StatefulSets(metav1.NamespaceAll).List(ctx, o)
			if err != nil {
				return nil, "", fmt.Errorf("list statefulsets: %w", err)
			}
			return l.Items, l.Continue, nil
		})
	})
}

// PodDisruptionBudgets lists all PDBs in all namespaces.
func (c *Cluster) PodDisruptionBudgets(ctx context.Context) ([]policyv1.PodDisruptionBudget, error) {
	return memo(c, "pdbs", func() ([]policyv1.PodDisruptionBudget, error) {
		return listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]policyv1.PodDisruptionBudget, string, error) {
			l, err := c.clientset.PolicyV1().PodDisruptionBudgets(metav1.NamespaceAll).List(ctx, o)
			if err != nil {
				return nil, "", fmt.Errorf("list poddisruptionbudgets: %w", err)
			}
			return l.Items, l.Continue, nil
		})
	})
}

// ValidatingWebhooks lists all validating webhook configurations.
func (c *Cluster) ValidatingWebhooks(ctx context.Context) ([]admissionv1.ValidatingWebhookConfiguration, error) {
	return memo(c, "validatingwebhooks", func() ([]admissionv1.ValidatingWebhookConfiguration, error) {
		return listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]admissionv1.ValidatingWebhookConfiguration, string, error) {
			l, err := c.clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, o)
			if err != nil {
				return nil, "", fmt.Errorf("list validatingwebhookconfigurations: %w", err)
			}
			return l.Items, l.Continue, nil
		})
	})
}

// MutatingWebhooks lists all mutating webhook configurations.
func (c *Cluster) MutatingWebhooks(ctx context.Context) ([]admissionv1.MutatingWebhookConfiguration, error) {
	return memo(c, "mutatingwebhooks", func() ([]admissionv1.MutatingWebhookConfiguration, error) {
		return listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]admissionv1.MutatingWebhookConfiguration, string, error) {
			l, err := c.clientset.AdmissionregistrationV1().MutatingWebhookConfigurations().List(ctx, o)
			if err != nil {
				return nil, "", fmt.Errorf("list mutatingwebhookconfigurations: %w", err)
			}
			return l.Items, l.Continue, nil
		})
	})
}

// StorageClasses lists all storage classes.
func (c *Cluster) StorageClasses(ctx context.Context) ([]storagev1.StorageClass, error) {
	return memo(c, "storageclasses", func() ([]storagev1.StorageClass, error) {
		return listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]storagev1.StorageClass, string, error) {
			l, err := c.clientset.StorageV1().StorageClasses().List(ctx, o)
			if err != nil {
				return nil, "", fmt.Errorf("list storageclasses: %w", err)
			}
			return l.Items, l.Continue, nil
		})
	})
}

// CSIDrivers lists all registered CSI drivers.
func (c *Cluster) CSIDrivers(ctx context.Context) ([]storagev1.CSIDriver, error) {
	return memo(c, "csidrivers", func() ([]storagev1.CSIDriver, error) {
		return listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]storagev1.CSIDriver, string, error) {
			l, err := c.clientset.StorageV1().CSIDrivers().List(ctx, o)
			if err != nil {
				return nil, "", fmt.Errorf("list csidrivers: %w", err)
			}
			return l.Items, l.Continue, nil
		})
	})
}

// PersistentVolumes lists all persistent volumes.
func (c *Cluster) PersistentVolumes(ctx context.Context) ([]corev1.PersistentVolume, error) {
	return memo(c, "pvs", func() ([]corev1.PersistentVolume, error) {
		return listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]corev1.PersistentVolume, string, error) {
			l, err := c.clientset.CoreV1().PersistentVolumes().List(ctx, o)
			if err != nil {
				return nil, "", fmt.Errorf("list persistentvolumes: %w", err)
			}
			return l.Items, l.Continue, nil
		})
	})
}

// CustomResourceDefinitions lists all CRDs. An unreadable API is an error: an
// empty list is reserved for a verified cluster with no CRDs.
func (c *Cluster) CustomResourceDefinitions(ctx context.Context) ([]apiextv1.CustomResourceDefinition, error) {
	return memo(c, "crds", func() ([]apiextv1.CustomResourceDefinition, error) {
		if c.apiext == nil {
			return nil, nil
		}
		return listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]apiextv1.CustomResourceDefinition, string, error) {
			l, err := c.apiext.ApiextensionsV1().CustomResourceDefinitions().List(ctx, o)
			if err != nil {
				return nil, "", fmt.Errorf("list customresourcedefinitions: %w", err)
			}
			return l.Items, l.Continue, nil
		})
	})
}

// ServerGroups returns the API groups and versions the server advertises.
func (c *Cluster) ServerGroups(ctx context.Context) ([]metav1.APIGroup, error) {
	return memo(c, "servergroups", func() ([]metav1.APIGroup, error) {
		if c.discovery == nil {
			return nil, nil
		}
		g, err := c.discovery.ServerGroups()
		if err != nil {
			return nil, fmt.Errorf("discover server groups: %w", err)
		}
		return g.Groups, nil
	})
}

type servedResourceSnapshot struct {
	resources map[string][]metav1.APIResource
	failures  map[string]error
}

// discoverySnapshot returns both successful discovery data and the exact
// group/versions whose discovery failed. Keeping both prevents an unavailable
// API group from looking identical to one the cluster does not serve.
func (c *Cluster) discoverySnapshot(ctx context.Context) (servedResourceSnapshot, error) {
	return memo(c, "servedresources", func() (servedResourceSnapshot, error) {
		if c.discovery == nil {
			return servedResourceSnapshot{}, fmt.Errorf("no discovery client")
		}
		_, lists, err := c.discovery.ServerGroupsAndResources()
		failures := map[string]error{}
		if err != nil {
			var partial *discovery.ErrGroupDiscoveryFailed
			if !errors.As(err, &partial) {
				return servedResourceSnapshot{}, fmt.Errorf("discover server resources: %w", err)
			}
			for gv, cause := range partial.Groups {
				failures[gv.String()] = cause
			}
		}
		out := make(map[string][]metav1.APIResource, len(lists))
		for _, l := range lists {
			if l == nil {
				continue
			}
			out[l.GroupVersion] = append(out[l.GroupVersion], l.APIResources...)
		}
		return servedResourceSnapshot{resources: out, failures: failures}, nil
	})
}

// ServedResources returns every successfully discovered
// group/version/resource, keyed by "group/version". Callers asking about one
// specific GVR should use Serves, which also checks targeted partial failures.
func (c *Cluster) ServedResources(ctx context.Context) (map[string][]metav1.APIResource, error) {
	snapshot, err := c.discoverySnapshot(ctx)
	return snapshot.resources, err
}

// DiscoveryFailures returns the group versions discovery could not enumerate,
// sorted. Non-empty means part of the API surface is unknown, and any
// "nothing found" claim covering those groups is uninformed.
func (c *Cluster) DiscoveryFailures(ctx context.Context) ([]string, error) {
	snapshot, err := c.discoverySnapshot(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(snapshot.failures))
	for gv := range snapshot.failures {
		out = append(out, gv)
	}
	sort.Strings(out)
	return out, nil
}

// Serves reports whether the API server currently serves the given
// group/version/resource. An empty group means the core API group.
func (c *Cluster) Serves(ctx context.Context, gvr schema.GroupVersionResource) (bool, error) {
	snapshot, err := c.discoverySnapshot(ctx)
	if err != nil {
		return false, err
	}
	gv := gvr.GroupVersion().String()
	if cause, failed := snapshot.failures[gv]; failed {
		return false, fmt.Errorf("discover %s: %w", gv, cause)
	}
	for _, r := range snapshot.resources[gv] {
		if r.Name == gvr.Resource {
			return true, nil
		}
	}
	return false, nil
}

// ListGVR lists all objects of a known-served group/version/resource using the
// dynamic client. Absence should be established with Serves before calling;
// an unreadable resource is always returned as an error, never as an empty list.
// ErrNoDynamicClient marks probes that cannot run because the cluster handle
// has no dynamic client (in-process test clusters). Checks treat it as an
// explicit skip, never as emptiness.
var ErrNoDynamicClient = errors.New("no dynamic client")

func (c *Cluster) ListGVR(ctx context.Context, gvr schema.GroupVersionResource) ([]unstructured.Unstructured, error) {
	if c.dynamic == nil {
		return nil, fmt.Errorf("list %s: %w", gvr.String(), ErrNoDynamicClient)
	}
	return memo(c, "gvr:"+gvr.String(), func() ([]unstructured.Unstructured, error) {
		return listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]unstructured.Unstructured, string, error) {
			l, err := c.dynamic.Resource(gvr).Namespace(metav1.NamespaceAll).List(ctx, o)
			if err != nil {
				return nil, "", fmt.Errorf("list %s: %w", gvr.String(), err)
			}
			return l.Items, l.GetContinue(), nil
		})
	})
}

// restConfig is retained so checks can derive read-only side channels from the
// same credentials: the /metrics endpoint and the API server's TLS handshake.
func (c *Cluster) RESTConfig() *rest.Config { return c.restCfg }

// HelmReleaseSecrets lists Secrets of type helm.sh/release.v1 across all
// namespaces. The field selector keeps the transfer to Helm releases only, but
// note RBAC cannot scope by field: this call needs list on secrets, and a
// cluster that declines to grant it makes the caller Skip, not fail.
func (c *Cluster) HelmReleaseSecrets(ctx context.Context) ([]corev1.Secret, error) {
	return memo(c, "helmsecrets", func() ([]corev1.Secret, error) {
		return listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]corev1.Secret, string, error) {
			o.FieldSelector = "type=helm.sh/release.v1"
			l, err := c.clientset.CoreV1().Secrets(metav1.NamespaceAll).List(ctx, o)
			if err != nil {
				return nil, "", fmt.Errorf("list helm release secrets: %w", err)
			}
			return l.Items, l.Continue, nil
		})
	})
}

// HelmReleaseConfigMaps lists ConfigMaps carrying Helm's configmap storage
// backend (label owner=helm). Rare, but kubent was the only tool that read it
// and some clusters do use it.
func (c *Cluster) HelmReleaseConfigMaps(ctx context.Context) ([]corev1.ConfigMap, error) {
	return memo(c, "helmconfigmaps", func() ([]corev1.ConfigMap, error) {
		return listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]corev1.ConfigMap, string, error) {
			o.LabelSelector = "owner=helm"
			l, err := c.clientset.CoreV1().ConfigMaps(metav1.NamespaceAll).List(ctx, o)
			if err != nil {
				return nil, "", fmt.Errorf("list helm release configmaps: %w", err)
			}
			return l.Items, l.Continue, nil
		})
	})
}

// RawMetrics fetches the API server's /metrics endpoint. Callers must treat a
// permission error as "unknown", never as "no findings".
func (c *Cluster) RawMetrics(ctx context.Context) ([]byte, error) {
	return memo(c, "rawmetrics", func() ([]byte, error) {
		if c.discovery == nil {
			return nil, fmt.Errorf("no discovery client")
		}
		rc := c.discovery.RESTClient()
		if rc == nil {
			// Fake clientsets used in tests expose no REST client.
			return nil, fmt.Errorf("metrics endpoint not reachable through this client")
		}
		return rc.Get().AbsPath("/metrics").DoRaw(ctx)
	})
}

// APIServices lists aggregated API registrations via the dynamic client.
func (c *Cluster) APIServices(ctx context.Context) ([]unstructured.Unstructured, error) {
	gvr := schema.GroupVersionResource{
		Group: "apiregistration.k8s.io", Version: "v1", Resource: "apiservices",
	}
	served, err := c.Serves(ctx, gvr)
	if err != nil || !served {
		return nil, err
	}
	return c.ListGVR(ctx, gvr)
}

// Events lists all events across namespaces. Health checks join these to
// unhealthy objects to name root causes.
func (c *Cluster) Events(ctx context.Context) ([]corev1.Event, error) {
	return memo(c, "events", func() ([]corev1.Event, error) {
		return listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]corev1.Event, string, error) {
			l, err := c.clientset.CoreV1().Events(metav1.NamespaceAll).List(ctx, o)
			if err != nil {
				return nil, "", fmt.Errorf("list events: %w", err)
			}
			return l.Items, l.Continue, nil
		})
	})
}

// Jobs lists all Jobs across namespaces.
func (c *Cluster) Jobs(ctx context.Context) ([]batchv1.Job, error) {
	return memo(c, "jobs", func() ([]batchv1.Job, error) {
		return listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]batchv1.Job, string, error) {
			l, err := c.clientset.BatchV1().Jobs(metav1.NamespaceAll).List(ctx, o)
			if err != nil {
				return nil, "", fmt.Errorf("list jobs: %w", err)
			}
			return l.Items, l.Continue, nil
		})
	})
}

// NodeMetrics lists live node utilization from the metrics API, when a
// metrics-server (or equivalent) is installed. Absence is not an error.
func (c *Cluster) NodeMetrics(ctx context.Context) ([]unstructured.Unstructured, error) {
	gvr := schema.GroupVersionResource{
		Group: "metrics.k8s.io", Version: "v1beta1", Resource: "nodes",
	}
	served, err := c.Serves(ctx, gvr)
	if err != nil || !served {
		return nil, err
	}
	return c.ListGVR(ctx, gvr)
}

// IngressClasses lists all IngressClasses.
func (c *Cluster) IngressClasses(ctx context.Context) ([]networkingv1.IngressClass, error) {
	return memo(c, "ingressclasses", func() ([]networkingv1.IngressClass, error) {
		return listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]networkingv1.IngressClass, string, error) {
			l, err := c.clientset.NetworkingV1().IngressClasses().List(ctx, o)
			if err != nil {
				return nil, "", fmt.Errorf("list ingressclasses: %w", err)
			}
			return l.Items, l.Continue, nil
		})
	})
}

// Ingresses lists all Ingresses across namespaces.
func (c *Cluster) Ingresses(ctx context.Context) ([]networkingv1.Ingress, error) {
	return memo(c, "ingresses", func() ([]networkingv1.Ingress, error) {
		return listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]networkingv1.Ingress, string, error) {
			l, err := c.clientset.NetworkingV1().Ingresses(metav1.NamespaceAll).List(ctx, o)
			if err != nil {
				return nil, "", fmt.Errorf("list ingresses: %w", err)
			}
			return l.Items, l.Continue, nil
		})
	})
}

// TLSSecrets lists Secrets of type kubernetes.io/tls across all namespaces.
func (c *Cluster) TLSSecrets(ctx context.Context) ([]corev1.Secret, error) {
	return memo(c, "tlssecrets", func() ([]corev1.Secret, error) {
		return listAll(ctx, func(ctx context.Context, o metav1.ListOptions) ([]corev1.Secret, string, error) {
			o.FieldSelector = "type=kubernetes.io/tls"
			l, err := c.clientset.CoreV1().Secrets(metav1.NamespaceAll).List(ctx, o)
			if err != nil {
				return nil, "", fmt.Errorf("list tls secrets: %w", err)
			}
			return l.Items, l.Continue, nil
		})
	})
}

package tui

import (
	"context"
	"fmt"
	"sort"

	tea "charm.land/bubbletea/v2"
	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
	"k8s.io/client-go/tools/clientcmd"
)

// loadContextsCmd reads the kubeconfig and lists its contexts.
func loadContextsCmd(kubeconfig string) tea.Cmd {
	return func() tea.Msg {
		names, current, err := ListContexts(kubeconfig)
		return contextsMsg{contexts: names, current: current, err: err}
	}
}

// ListContexts returns the context names in a kubeconfig along with the
// current-context. An empty path uses the standard loading rules.
func ListContexts(kubeconfig string) (names []string, current string, err error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules = &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig}
	}
	cfg, err := rules.Load()
	if err != nil {
		return nil, "", fmt.Errorf("load kubeconfig: %w", err)
	}
	if len(cfg.Contexts) == 0 {
		return nil, "", fmt.Errorf("kubeconfig contains no contexts")
	}
	for name := range cfg.Contexts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, cfg.CurrentContext, nil
}

// connectCmd opens a read-only connection to the selected cluster.
func connectCmd(kubeconfig, contextName string) tea.Cmd {
	return func() tea.Msg {
		cluster, err := analyzer.Connect(context.Background(), kubeconfig, contextName)
		return connectedMsg{cluster: cluster, err: err}
	}
}

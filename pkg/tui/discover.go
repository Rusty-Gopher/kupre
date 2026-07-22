package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	tea "charm.land/bubbletea/v2"
	"k8s.io/client-go/tools/clientcmd"
)

// KubeconfigCandidate is a kubeconfig file kupre found and could use.
type KubeconfigCandidate struct {
	// Path is the absolute path to the file.
	Path string
	// Origin says where it was found, e.g. "$KUBECONFIG" or "current directory".
	Origin string
	// Contexts are the context names it defines.
	Contexts []string
	// Current is its current-context.
	Current string
	// Err is set when the file exists but could not be parsed.
	Err error
}

// Label renders the candidate for a picker row.
func (k KubeconfigCandidate) Label() string {
	base := k.Path
	if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(base, home) {
		base = "~" + strings.TrimPrefix(base, home)
	}
	return base
}

// Detail renders the candidate's context summary, or the parse error.
func (k KubeconfigCandidate) Detail() string {
	if k.Err != nil {
		return "unreadable: " + k.Err.Error()
	}
	switch len(k.Contexts) {
	case 0:
		return "no contexts"
	case 1:
		return "1 cluster: " + k.Contexts[0]
	default:
		return fmt.Sprintf("%d clusters", len(k.Contexts))
	}
}

// Usable reports whether the candidate can actually be scanned.
func (k KubeconfigCandidate) Usable() bool { return k.Err == nil && len(k.Contexts) > 0 }

// DiscoverKubeconfigs looks for kubeconfig files in the places they normally
// live, so the first run can offer a choice rather than silently inheriting
// whatever happens to be in the environment.
//
// Search order, de-duplicated by resolved path:
//  1. every entry in $KUBECONFIG (colon-separated, as client-go treats it)
//  2. ~/.kube/config
//  3. kubeconfig-like files in the working directory
//  4. other files in ~/.kube/
//
// Unreadable files are returned with Err set rather than dropped: a kubeconfig
// that exists but fails to parse is something the user needs told about, not
// something to hide.
func DiscoverKubeconfigs() []KubeconfigCandidate {
	var out []KubeconfigCandidate
	seen := map[string]bool{}

	add := func(path, origin string) {
		abs, err := filepath.Abs(path)
		if err != nil || seen[abs] {
			return
		}
		info, err := os.Stat(abs)
		if err != nil || info.IsDir() {
			return
		}
		seen[abs] = true

		c := KubeconfigCandidate{Path: abs, Origin: origin}
		cfg, err := clientcmd.LoadFromFile(abs)
		if err != nil {
			c.Err = err
			out = append(out, c)
			return
		}
		for name := range cfg.Contexts {
			c.Contexts = append(c.Contexts, name)
		}
		sort.Strings(c.Contexts)
		c.Current = cfg.CurrentContext
		out = append(out, c)
	}

	for _, p := range filepath.SplitList(os.Getenv("KUBECONFIG")) {
		if p != "" {
			add(p, "$KUBECONFIG")
		}
	}

	home, homeErr := os.UserHomeDir()
	if homeErr == nil {
		add(filepath.Join(home, ".kube", "config"), "default location")
	}

	if wd, err := os.Getwd(); err == nil {
		if entries, err := os.ReadDir(wd); err == nil {
			for _, e := range entries {
				if !e.IsDir() && looksLikeKubeconfig(e.Name()) {
					add(filepath.Join(wd, e.Name()), "current directory")
				}
			}
		}
	}

	if homeErr == nil {
		kubeDir := filepath.Join(home, ".kube")
		if entries, err := os.ReadDir(kubeDir); err == nil {
			for _, e := range entries {
				if !e.IsDir() && looksLikeKubeconfig(e.Name()) {
					add(filepath.Join(kubeDir, e.Name()), "~/.kube")
				}
			}
		}
	}

	return out
}

// looksLikeKubeconfig reports whether a filename is plausibly a kubeconfig.
// Deliberately conservative: a false positive costs the user a confusing row in
// the picker, and every candidate is parsed before being offered anyway.
func looksLikeKubeconfig(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, ".") {
		return false
	}
	switch {
	case lower == "config", lower == "kubeconfig":
		return true
	case strings.HasPrefix(lower, "kubeconfig"):
		return true
	case strings.HasSuffix(lower, ".kubeconfig"):
		return true
	default:
		return false
	}
}

// discoverKubeconfigsCmd runs discovery off the UI goroutine.
func discoverKubeconfigsCmd() tea.Cmd {
	return func() tea.Msg {
		return kubeconfigsMsg{candidates: DiscoverKubeconfigs()}
	}
}

// validateKubeconfigCmd checks that a hand-typed path is usable before the flow
// moves on, so a typo is caught at the prompt rather than at connect time.
func validateKubeconfigCmd(path string) tea.Cmd {
	return func() tea.Msg {
		expanded := expandHome(path)
		names, current, err := ListContexts(expanded)
		if err != nil {
			return kubeconfigChosenMsg{err: err}
		}
		return kubeconfigChosenMsg{
			path: expanded, contexts: names, current: current,
		}
	}
}

// expandHome resolves a leading ~ in a path.
func expandHome(p string) string {
	if !strings.HasPrefix(p, "~") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, strings.TrimPrefix(p, "~"))
}

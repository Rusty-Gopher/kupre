package tui

import (
	"regexp"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
)

// key builds a KeyPressMsg for the given key name, as Bubble Tea would deliver it.
func key(s string) tea.KeyPressMsg {
	switch s {
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "esc":
		return tea.KeyPressMsg{Code: tea.KeyEscape}
	case "up":
		return tea.KeyPressMsg{Code: tea.KeyUp}
	case "down":
		return tea.KeyPressMsg{Code: tea.KeyDown}
	case "backspace":
		return tea.KeyPressMsg{Code: tea.KeyBackspace}
	default:
		r := []rune(s)[0]
		return tea.KeyPressMsg{Code: r, Text: s}
	}
}

// send feeds messages to the model in order and returns the final model.
func send(m Model, msgs ...tea.Msg) Model {
	for _, msg := range msgs {
		next, _ := m.Update(msg)
		m = next.(Model)
	}
	return m
}

func TestContextPickerNavigation(t *testing.T) {
	m := send(New(Options{}),
		kubeconfigChosenMsg{path: "/a", contexts: []string{"alpha", "beta", "gamma"}, current: "beta"})

	// The picker should start on the kubeconfig's current-context.
	if m.ctxCursor != 1 {
		t.Errorf("cursor = %d, want 1 (current-context 'beta')", m.ctxCursor)
	}

	m = send(m, key("down"))
	if m.ctxCursor != 2 {
		t.Errorf("after down: cursor = %d, want 2", m.ctxCursor)
	}

	// The cursor must not run past the end of the list.
	m = send(m, key("down"), key("down"))
	if m.ctxCursor != 2 {
		t.Errorf("cursor ran past the end: %d, want 2", m.ctxCursor)
	}

	m = send(m, key("up"), key("up"), key("up"), key("up"))
	if m.ctxCursor != 0 {
		t.Errorf("cursor ran past the start: %d, want 0", m.ctxCursor)
	}

	m = send(m, key("enter"))
	if m.stage != stageTargetVersion {
		t.Errorf("stage = %v, want stageTargetVersion after enter", m.stage)
	}
	if m.ctxChosen != "alpha" {
		t.Errorf("chose %q, want alpha", m.ctxChosen)
	}
}

func TestExplicitContextSkipsPicker(t *testing.T) {
	m := send(New(Options{Context: "preselected"}),
		kubeconfigChosenMsg{path: "/a", contexts: []string{"a", "b"}, current: "a"})

	if m.stage != stageTargetVersion {
		t.Errorf("stage = %v, want stageTargetVersion when --context is given", m.stage)
	}
	if m.ctxChosen != "preselected" {
		t.Errorf("chose %q, want preselected", m.ctxChosen)
	}
}

func TestVersionInputAcceptsOnlyVersionCharacters(t *testing.T) {
	m := New(Options{})
	m.stage = stageTargetVersion

	m = send(m, key("1"), key("."), key("3"), key("6"), key("."), key("0"))
	if m.versionBuf != "1.36.0" {
		t.Errorf("versionBuf = %q, want 1.36.0", m.versionBuf)
	}

	// Letters must be ignored rather than corrupting the buffer.
	m = send(m, key("x"), key("z"))
	if m.versionBuf != "1.36.0" {
		t.Errorf("letters leaked into versionBuf: %q", m.versionBuf)
	}

	m = send(m, key("backspace"))
	if m.versionBuf != "1.36." {
		t.Errorf("after backspace: versionBuf = %q, want 1.36.", m.versionBuf)
	}
}

func TestInvalidVersionDoesNotStartScan(t *testing.T) {
	m := New(Options{})
	m.stage = stageTargetVersion
	m.versionBuf = "1"

	m = send(m, key("enter"))
	if m.stage != stageTargetVersion {
		t.Errorf("stage = %v, want to stay on stageTargetVersion for an incomplete version", m.stage)
	}
}

func TestEscGoesBackFromVersion(t *testing.T) {
	// With several contexts, back means the context picker.
	m := New(Options{})
	m.contexts = []string{"a", "b"}
	m.stage = stageTargetVersion
	if m = send(m, key("esc")); m.stage != stagePickContext {
		t.Errorf("stage = %v, want stagePickContext", m.stage)
	}

	// With one context there was no picker to return to, so back skips past it
	// to the kubeconfig choice rather than showing a single-item list.
	m = New(Options{})
	m.contexts = []string{"only"}
	m.stage = stageTargetVersion
	if m = send(m, key("esc")); m.stage != stagePickKubeconfig {
		t.Errorf("stage = %v, want stagePickKubeconfig", m.stage)
	}
}

func TestStartsOnWelcomeNotAPicker(t *testing.T) {
	// The first screen must explain what kupre does. Opening straight into a
	// cluster list gives the operator no basis for trusting a tool that is
	// about to talk to production.
	m := New(Options{})
	if m.stage != stageWelcome {
		t.Fatalf("initial stage = %v, want stageWelcome", m.stage)
	}

	content := m.View().Content
	for _, want := range []string{"What this does", "never writes to your cluster"} {
		if !strings.Contains(content, want) {
			t.Errorf("welcome screen missing %q:\n%s", want, content)
		}
	}

	if m = send(m, key("enter")); m.stage != stagePickMission {
		t.Errorf("enter should advance to the mission picker, got %v", m.stage)
	}
	if m = send(m, key("enter")); m.stage != stagePickKubeconfig {
		t.Errorf("selecting a mission should advance to the kubeconfig picker, got %v", m.stage)
	}
}

func TestKubeconfigPickerNavigation(t *testing.T) {
	m := New(Options{})
	m.stage = stagePickKubeconfig
	m = send(m, kubeconfigsMsg{candidates: []KubeconfigCandidate{
		{Path: "/a/config", Origin: "$KUBECONFIG", Contexts: []string{"one"}},
		{Path: "/b/config", Origin: "~/.kube", Contexts: []string{"two", "three"}},
	}})

	content := m.View().Content
	for _, want := range []string{"/a/config", "/b/config", "2 clusters", "type a path"} {
		if !strings.Contains(content, want) {
			t.Errorf("picker missing %q:\n%s", want, content)
		}
	}

	// The cursor may travel one past the last file: that row is manual entry.
	m = send(m, key("down"), key("down"))
	if m.kcCursor != 2 {
		t.Errorf("cursor = %d, want 2 (the manual-entry row)", m.kcCursor)
	}
	m = send(m, key("down"))
	if m.kcCursor != 2 {
		t.Errorf("cursor ran past manual entry: %d", m.kcCursor)
	}

	if m = send(m, key("enter")); !m.kcTyping {
		t.Error("enter on the manual row should start text entry")
	}
}

func TestKubeconfigManualEntry(t *testing.T) {
	m := New(Options{})
	m.stage = stagePickKubeconfig
	m = send(m, kubeconfigsMsg{})
	m = send(m, key("e"))

	if !m.kcTyping {
		t.Fatal("'e' should start text entry")
	}
	for _, k := range []string{"/", "t", "m", "p", "/", "k"} {
		m = send(m, key(k))
	}
	if m.kcInput != "/tmp/k" {
		t.Errorf("input = %q, want /tmp/k", m.kcInput)
	}
	m = send(m, key("backspace"))
	if m.kcInput != "/tmp/" {
		t.Errorf("after backspace: %q, want /tmp/", m.kcInput)
	}
	if m = send(m, key("esc")); m.kcTyping {
		t.Error("esc should leave text entry")
	}
}

func TestUnusableKubeconfigIsRejected(t *testing.T) {
	// A file that exists but will not parse must be reported, not silently
	// selected and then failed at connect time.
	m := New(Options{})
	m.stage = stagePickKubeconfig
	m = send(m, kubeconfigsMsg{candidates: []KubeconfigCandidate{
		{Path: "/broken", Origin: "current directory", Err: errTest},
	}})

	m = send(m, key("enter"))
	if m.kcErr == nil {
		t.Error("selecting an unusable kubeconfig should surface an error")
	}
	if m.stage != stagePickKubeconfig {
		t.Errorf("stage = %v, should stay on the picker", m.stage)
	}
}

func TestSingleContextSkipsTheClusterPicker(t *testing.T) {
	m := New(Options{})
	m.stage = stagePickKubeconfig
	m = send(m, kubeconfigChosenMsg{
		path: "/a/config", contexts: []string{"only-one"}, current: "only-one",
	})

	if m.stage != stageTargetVersion {
		t.Errorf("stage = %v, want stageTargetVersion (no choice to offer)", m.stage)
	}
	if m.ctxChosen != "only-one" {
		t.Errorf("ctxChosen = %q, want only-one", m.ctxChosen)
	}
}

func TestMultipleContextsShowThePicker(t *testing.T) {
	m := New(Options{})
	m.stage = stagePickKubeconfig
	m = send(m, kubeconfigChosenMsg{
		path: "/a/config", contexts: []string{"alpha", "beta"}, current: "beta",
	})

	if m.stage != stagePickContext {
		t.Errorf("stage = %v, want stagePickContext", m.stage)
	}
	if m.ctxCursor != 1 {
		t.Errorf("cursor = %d, want 1 (the current-context)", m.ctxCursor)
	}
}

func TestResultsNavigationAndDetail(t *testing.T) {
	m := New(Options{})
	m = send(m, tea.WindowSizeMsg{Width: 100, Height: 40}, scanDoneMsg{report: sampleReport()})

	if m.stage != stageResults {
		t.Fatalf("stage = %v, want stageResults", m.stage)
	}

	// sampleReport has 3 findings but only 2 are actionable - the passing one
	// lives in the collapsed footer, not the navigable list.
	if len(m.ordered) != 2 {
		t.Fatalf("ordered = %d, want 2 (the pass is excluded)", len(m.ordered))
	}
	m = send(m, key("down"))
	if m.resCursor != 1 {
		t.Errorf("cursor = %d, want 1", m.resCursor)
	}

	// The cursor must stop at the last actionable finding.
	m = send(m, key("down"), key("down"), key("down"))
	if m.resCursor != 1 {
		t.Errorf("cursor ran past the last finding: %d, want 1", m.resCursor)
	}

	m = send(m, key("enter"))
	if m.stage != stageDetail {
		t.Errorf("stage = %v, want stageDetail", m.stage)
	}

	m = send(m, key("esc"))
	if m.stage != stageResults {
		t.Errorf("stage = %v, want stageResults after esc", m.stage)
	}
}

func TestViewsRenderWithoutPanicking(t *testing.T) {
	// Each stage must render even before its data has arrived - a TUI that
	// panics on an empty model is unusable in exactly the moments that matter.
	stages := []struct {
		name  string
		setup func(Model) Model
	}{
		{name: "welcome", setup: func(m Model) Model { return m }},
		{
			name:  "kubeconfig picker, still discovering",
			setup: func(m Model) Model { m.stage = stagePickKubeconfig; return m },
		},
		{
			name: "kubeconfig picker with candidates",
			setup: func(m Model) Model {
				m.stage = stagePickKubeconfig
				return send(m, kubeconfigsMsg{candidates: []KubeconfigCandidate{
					{Path: "/a/config", Origin: "$KUBECONFIG", Contexts: []string{"one"}},
				}})
			},
		},
		{
			name: "kubeconfig picker with nothing found",
			setup: func(m Model) Model {
				m.stage = stagePickKubeconfig
				return send(m, kubeconfigsMsg{})
			},
		},
		{
			name: "context picker",
			setup: func(m Model) Model {
				return send(m, kubeconfigChosenMsg{
					path: "/a", contexts: []string{"a", "b"}, current: "a"})
			},
		},
		{
			name:  "version prompt",
			setup: func(m Model) Model { m.stage = stageTargetVersion; return m },
		},
		{
			name:  "scanning before connect",
			setup: func(m Model) Model { m.stage = stageScanning; return m },
		},
		{
			name: "scanning with progress",
			setup: func(m Model) Model {
				m.stage = stageScanning
				return send(m, progressMsg{done: 3, total: 10, last: "node-ready"})
			},
		},
		{
			name:  "results",
			setup: func(m Model) Model { return send(m, scanDoneMsg{report: sampleReport()}) },
		},
		{
			name: "detail",
			setup: func(m Model) Model {
				m = send(m, scanDoneMsg{report: sampleReport()})
				return send(m, key("enter"))
			},
		},
		{
			name: "error",
			setup: func(m Model) Model {
				return send(m, contextsMsg{err: errTest})
			},
		},
	}

	for _, tt := range stages {
		t.Run(tt.name, func(t *testing.T) {
			m := tt.setup(send(New(Options{}), tea.WindowSizeMsg{Width: 100, Height: 40}))

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("View() panicked: %v", r)
				}
			}()

			v := m.View()
			if !strings.Contains(v.Content, "KUBERNETES PREFLIGHT & REVIEW ENGINE") {
				t.Error("view is missing the banner")
			}
			if !v.AltScreen {
				t.Error("view should request the alternate screen")
			}
		})
	}
}

func TestResultsViewShowsVerdict(t *testing.T) {
	m := send(New(Options{}),
		tea.WindowSizeMsg{Width: 100, Height: 40},
		scanDoneMsg{report: sampleReport()})

	content := m.View().Content
	for _, want := range []string{
		"pdb-blocks-drain", "NOT READY", "FAIL", "WARN",
		"BLOCKS THE UPGRADE", // worklist section headers, same as the CLI
		"PASSED (1)",         // passing checks collapse into the footer
	} {
		if !strings.Contains(content, want) {
			t.Errorf("results view missing %q\n---\n%s", want, content)
		}
	}

	// 'p' expands the passing footer.
	m = send(m, key("p"))
	if !strings.Contains(m.View().Content, "node-ready") {
		t.Error("expanding with p should list the passing checks")
	}
}

func TestSmallTerminalStillRenders(t *testing.T) {
	// visibleRows must never go negative or zero, which would slice out of range.
	m := send(New(Options{}),
		tea.WindowSizeMsg{Width: 20, Height: 5},
		scanDoneMsg{report: sampleReport()})

	if rows := m.visibleRows(); rows < 1 {
		t.Fatalf("visibleRows() = %d on a tiny terminal, want at least 1", rows)
	}
	if m.View().Content == "" {
		t.Error("tiny terminal produced empty output")
	}
}

var errTest = testError("could not load kubeconfig")

type testError string

func (e testError) Error() string { return string(e) }

// sampleReport builds a report with a blocking finding, a warning, and a pass.
func sampleReport() *analyzer.Report {
	return &analyzer.Report{
		Cluster: "test-cluster",
		Upgrade: analyzer.Upgrade{
			From: analyzer.MustParseVersion("1.35.3"),
			To:   analyzer.MustParseVersion("1.36.0"),
		},
		Findings: []analyzer.Finding{
			{
				Check: "pdb-blocks-drain", Category: analyzer.CategoryWorkload,
				Severity: analyzer.SeverityError,
				Result: &analyzer.Result{
					Status: analyzer.StatusFail, Message: "1 PDB blocks drain",
					Resources: []analyzer.AffectedResource{
						{Kind: "PodDisruptionBudget", Namespace: "prod", Name: "api"},
					},
					Remediation: "Scale the workload above minAvailable.",
					Docs:        "https://example.invalid/pdb",
				},
			},
			{
				Check: "webhook-timeout", Category: analyzer.CategoryWebhook,
				Severity: analyzer.SeverityWarning,
				Result:   &analyzer.Result{Status: analyzer.StatusWarn, Message: "slow webhook"},
			},
			{
				Check: "node-ready", Category: analyzer.CategoryNode,
				Severity: analyzer.SeverityError,
				Result:   &analyzer.Result{Status: analyzer.StatusPass, Message: "nodes ready"},
			},
		},
	}
}

// TestConnectUsesTheChosenKubeconfig guards a bug where the scan connected with
// opts.Kubeconfig instead of the file the user selected. With no --kubeconfig
// flag that resolved to ambient default rules, so picking a file in the UI had
// no effect and the scan could silently hit a different cluster.
func TestConnectUsesTheChosenKubeconfig(t *testing.T) {
	m := New(Options{}) // no --kubeconfig: ambient config would be used if the bug returned
	m = send(m, kubeconfigChosenMsg{
		path: "/explicitly/picked/config", contexts: []string{"prod"}, current: "prod",
	})

	if m.kcChosen != "/explicitly/picked/config" {
		t.Fatalf("kcChosen = %q, want the picked path", m.kcChosen)
	}
	if m.opts.Kubeconfig == m.kcChosen {
		t.Fatal("test is not meaningful unless opts.Kubeconfig differs from the choice")
	}

	// The scan must be driven from the choice, not from the flag.
	m.versionBuf = "1.36.0"
	m.stage = stageTargetVersion
	next, cmd := m.Update(key("enter"))
	m = next.(Model)
	if cmd == nil {
		t.Fatal("enter on a valid version should start connecting")
	}
	if m.kcChosen != "/explicitly/picked/config" {
		t.Errorf("kcChosen changed to %q during connect", m.kcChosen)
	}
}

// TestKubeconfigIsAlwaysAsked verifies --kubeconfig preselects rather than
// bypasses. The user should always see which cluster is about to be scanned.
func TestKubeconfigIsAlwaysAsked(t *testing.T) {
	m := New(Options{Kubeconfig: "/some/config"})
	m = send(m, key("enter"), key("enter")) // welcome → mission → kubeconfig

	if m.stage != stagePickKubeconfig {
		t.Errorf("stage = %v, want stagePickKubeconfig - a flag must not skip the question", m.stage)
	}
}

// TestNoCandidatesGoesStraightToTypingAPath avoids showing an empty list.
func TestNoCandidatesGoesStraightToTypingAPath(t *testing.T) {
	m := New(Options{})
	m = send(m, kubeconfigsMsg{})           // discovery found nothing
	m = send(m, key("enter"), key("enter")) // welcome → mission → kubeconfig

	if !m.kcTyping {
		t.Error("with nothing discovered, the path prompt should open immediately")
	}
	if !strings.Contains(m.View().Content, "Enter a path") {
		t.Errorf("should explain that a path is needed:\n%s", m.View().Content)
	}
}

// TestDetailShowsCommandsAndLimits guards TUI/CLI parity: the detail view must
// carry the same actionable content the printed worklist does.
func TestDetailShowsCommandsAndLimits(t *testing.T) {
	rep := sampleReport()
	rep.Findings[0].Result.Commands = []string{"kubectl scale deployment/api -n prod --replicas=2"}
	rep.Findings[0].Limits = "Replica count only; pod placement is not evaluated."

	m := send(New(Options{}),
		tea.WindowSizeMsg{Width: 110, Height: 44},
		scanDoneMsg{report: rep},
		key("enter"))

	content := m.View().Content
	for _, want := range []string{
		"kubectl scale deployment/api",
		"cannot conclude",
		"Replica count only",
		"finding 1 of 2",
		"BLOCKS THE UPGRADE",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("detail view missing %q\n---\n%s", want, content)
		}
	}
}

// TestMissionPicker covers the tool's new front door: choosing what to do.
func TestMissionPicker(t *testing.T) {
	m := send(New(Options{}), key("enter")) // welcome → mission picker
	if m.stage != stagePickMission {
		t.Fatalf("stage = %v, want stagePickMission", m.stage)
	}

	content := m.View().Content
	for _, want := range []string{"What do you want to do?", "Upgrade preflight", "Health check", "Certificate audit"} {
		if !strings.Contains(content, want) {
			t.Errorf("mission picker missing %q", want)
		}
	}

	// Pick the health mission (second entry).
	m = send(m, key("down"), key("enter"))
	if m.mission.Name != "health" {
		t.Fatalf("mission = %q, want health", m.mission.Name)
	}
	if m.stage != stagePickKubeconfig {
		t.Errorf("stage = %v, want stagePickKubeconfig", m.stage)
	}
}

// TestNoTargetMissionSkipsVersionPrompt: health and certs analyze the cluster
// as it is, so the version screen must never appear for them.
func TestNoTargetMissionSkipsVersionPrompt(t *testing.T) {
	m := send(New(Options{}), key("enter"), key("down"), key("enter")) // → health
	m = send(m, kubeconfigChosenMsg{
		path: "/a/config", contexts: []string{"only-one"}, current: "only-one",
	})

	if m.stage != stageScanning {
		t.Errorf("stage = %v, want stageScanning (no version prompt for health)", m.stage)
	}
}

// TestMissionBucketTitles: the health mission must not talk about upgrades.
func TestMissionBucketTitles(t *testing.T) {
	healthTitle := analyzer.BucketFixBeforeStart.TitleFor("health")
	if strings.Contains(strings.ToLower(healthTitle), "upgrade") {
		t.Errorf("health bucket title still mentions upgrades: %q", healthTitle)
	}
	upgradeTitle := analyzer.BucketFixBeforeStart.TitleFor("upgrade")
	if !strings.Contains(strings.ToLower(upgradeTitle), "upgrade") {
		t.Errorf("upgrade bucket title lost its meaning: %q", upgradeTitle)
	}
	// Unknown mission falls back to defaults rather than crashing or blanking.
	if analyzer.BucketFixBeforeStart.TitleFor("nonsense") == "" {
		t.Error("unknown mission must fall back to a default title")
	}
}

// TestInputBoxLinesShareIndent guards the skewed-box bug: a bordered input is
// three rendered lines, and indenting only the first visibly breaks the frame.
func TestInputBoxLinesShareIndent(t *testing.T) {
	m := New(Options{})
	m.width, m.height = 100, 40
	m.stage = stagePickKubeconfig
	m = send(m, kubeconfigsMsg{}, key("e"))
	for _, k := range []string{"/", "t", "m", "p"} {
		m = send(m, key(k))
	}

	var borders []int
	for _, line := range strings.Split(m.View().Content, "\n") {
		if i := strings.IndexAny(line, "╭│╰"); i >= 0 {
			borders = append(borders, i)
		}
	}
	if len(borders) < 3 {
		t.Fatalf("expected a 3-line box, found %d border lines", len(borders))
	}
	for _, col := range borders {
		if col != borders[0] {
			t.Fatalf("box lines start at columns %v; the frame is skewed", borders)
		}
	}
}

// TestLongPathShowsTail keeps a long typed path inside the screen by showing
// its end, which is the part that identifies the file.
func TestLongPathShowsTail(t *testing.T) {
	m := New(Options{})
	m.width, m.height = 60, 40
	m.stage = stagePickKubeconfig
	m = send(m, kubeconfigsMsg{}, key("e"))
	long := "/very/long/path/segments/that/never/seem/to/end/kubeconfig-cluster-a"
	for _, r := range long {
		m = send(m, key(string(r)))
	}

	content := m.View().Content
	if !strings.Contains(content, "kubeconfig-cluster-a") {
		t.Error("the tail of the path (the identifying part) is not visible")
	}
	// Measure visible width, not raw bytes: styled output carries ANSI escape
	// sequences that occupy no columns.
	ansi := regexp.MustCompile("\x1b\\[[0-9;]*m")
	for _, line := range strings.Split(content, "\n") {
		plain := ansi.ReplaceAllString(line, "")
		if n := len([]rune(plain)); n > m.width {
			t.Errorf("line overflows the terminal width (%d > %d): %q", n, m.width, plain)
		}
	}
}

// TestPasteIntoInputs: a paste arrives as one bracketed event, not keypresses,
// and must land in whichever text input is active.
func TestPasteIntoInputs(t *testing.T) {
	t.Run("path input accepts a pasted path", func(t *testing.T) {
		m := New(Options{})
		m.stage = stagePickKubeconfig
		m = send(m, kubeconfigsMsg{}, key("e"))
		m = send(m, tea.PasteMsg{Content: "/home/user/.kube/prod-config\n"})
		if m.kcInput != "/home/user/.kube/prod-config" {
			t.Errorf("kcInput = %q, want the pasted path without the newline", m.kcInput)
		}
	})

	t.Run("version input keeps only version characters", func(t *testing.T) {
		m := New(Options{})
		m.stage = stageTargetVersion
		m = send(m, tea.PasteMsg{Content: "v1.36.0 "})
		if m.versionBuf != "1.36.0" {
			t.Errorf("versionBuf = %q, want 1.36.0 (v and space filtered like typing)", m.versionBuf)
		}
	})

	t.Run("paste elsewhere is ignored", func(t *testing.T) {
		m := New(Options{})
		m = send(m, tea.PasteMsg{Content: "stray clipboard"})
		if m.kcInput != "" || m.versionBuf != "" {
			t.Error("paste on the welcome screen leaked into an input")
		}
	})

	t.Run("multi-line paste keeps only the first line", func(t *testing.T) {
		m := New(Options{})
		m.stage = stagePickKubeconfig
		m = send(m, kubeconfigsMsg{}, key("e"))
		m = send(m, tea.PasteMsg{Content: "/first/path\n/second/path"})
		if m.kcInput != "/first/path" {
			t.Errorf("kcInput = %q, want only the first line", m.kcInput)
		}
	})
}

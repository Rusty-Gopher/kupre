package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Rusty-Gopher/kupre/pkg/report"

	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
	"github.com/Rusty-Gopher/kupre/pkg/provider"
)

// stage is the TUI's current screen.
type stage int

const (
	stageWelcome stage = iota
	stagePickMission
	stagePickKubeconfig
	stagePickContext
	stageTargetVersion
	stageScanning
	stageResults
	stageDetail
	stageError
)

// Options configures the TUI.
type Options struct {
	// Kubeconfig is the explicit kubeconfig path, or "" for the default rules.
	Kubeconfig string
	// Context preselects a kubeconfig context, skipping the picker.
	Context string
	// TargetVersion preselects the upgrade target, skipping the prompt.
	TargetVersion string
}

// Model is the top-level Bubble Tea model.
type Model struct {
	opts   Options
	styles Styles

	stage stage
	width int
	// height is tracked so long result lists can be paged to the viewport.
	height int

	// mission is the selected analysis mode.
	mission       analyzer.Mission
	missionCursor int

	contexts   []string
	ctxCursor  int
	ctxChosen  string
	versionBuf string

	// Kubeconfig selection state.
	kubeconfigs []KubeconfigCandidate
	// kcDiscovered distinguishes "discovery finished and found nothing" from
	// "discovery has not run yet". A nil slice means both, and conflating them
	// left the screen stuck on "looking for kubeconfig files…".
	kcDiscovered bool
	kcCursor     int
	kcChosen     string
	// kcTyping is true while the user is entering a path by hand rather than
	// choosing a discovered one.
	kcTyping bool
	kcInput  string
	kcErr    error

	spinner  spinner.Model
	progress scanProgress

	cluster *analyzer.Cluster
	report  *analyzer.Report
	err     error

	// ordered holds the findings in worklist order - the same order the CLI
	// prints - with the owning bucket alongside for section headers. Passing
	// and skipped checks are kept separately and rendered collapsed.
	ordered []orderedFinding
	passed  []analyzer.Finding
	skipped []analyzer.Finding
	// showPassed expands the collapsed passing section.
	showPassed bool
	// reportPath is the saved HTML report for the current results.
	reportPath string
	reportErr  error

	resCursor int
	resScroll int

	// cancel stops an in-flight scan when the user quits.
	cancel context.CancelFunc

	// updates and done carry scan progress and the final result from the
	// engine goroutine. They are retained on the model because each delivery
	// must re-arm the listening command.
	updates chan scanProgress
	done    chan scanDoneMsg
}

// scanProgress carries live check-completion counts from the engine.
type scanProgress struct {
	done  int
	total int
	last  string
}

// New builds the TUI model.
func New(opts Options) Model {
	sp := spinner.New(spinner.WithSpinner(spinner.Dot))
	defaultMission, _ := analyzer.MissionByName("upgrade")
	return Model{
		mission:    defaultMission,
		opts:       opts,
		styles:     NewStyles(true),
		stage:      stageWelcome,
		spinner:    sp,
		versionBuf: opts.TargetVersion,
		width:      80,
		height:     24,
	}
}

// Init asks the terminal for its background colour so styles can adapt, and
// starts discovering kubeconfigs in the background so the picker is ready by
// the time the user has read the welcome screen.
//
// Note that it deliberately does not load ambient config and jump straight to a
// context list: silently inheriting whatever $KUBECONFIG happens to point at is
// how someone ends up scanning the wrong cluster.
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		tea.RequestBackgroundColor,
		discoverKubeconfigsCmd(),
	)
}

// Messages exchanged between commands and the model.
type (
	contextsMsg struct {
		contexts []string
		current  string
		err      error
	}
	connectedMsg struct {
		cluster *analyzer.Cluster
		err     error
	}
	progressMsg scanProgress
	scanDoneMsg struct {
		report *analyzer.Report
		err    error
		// reportPath is where the HTML report was saved, "" when saving failed.
		reportPath string
		reportErr  error
	}
	kubeconfigsMsg struct {
		candidates []KubeconfigCandidate
	}
	kubeconfigChosenMsg struct {
		path     string
		contexts []string
		current  string
		err      error
	}
)

// Update handles a single message.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case tea.BackgroundColorMsg:
		m.styles = NewStyles(msg.IsDark())
		return m, nil

	case tea.KeyPressMsg:
		return m.handleKey(msg)

	case tea.PasteMsg:
		// Terminals deliver a paste as one bracketed event, not keypresses.
		// Route it to whichever text input is active; ignore it elsewhere.
		return m.handlePaste(msg.Content)

	case kubeconfigsMsg:
		m.kubeconfigs = msg.candidates
		m.kcDiscovered = true
		// A path given on the command line preselects the matching row rather
		// than bypassing the question - the user still sees, and can change,
		// which cluster is about to be scanned.
		if m.opts.Kubeconfig != "" {
			abs, err := filepath.Abs(expandHome(m.opts.Kubeconfig))
			matched := false
			for i, k := range m.kubeconfigs {
				if err == nil && k.Path == abs {
					m.kcCursor, matched = i, true
					break
				}
			}
			if !matched {
				m.kcTyping = true
				m.kcInput = m.opts.Kubeconfig
			}
		}
		return m, nil

	case kubeconfigChosenMsg:
		if msg.err != nil {
			m.kcErr = msg.err
			return m, nil
		}
		m.kcErr = nil
		m.kcChosen = msg.path
		m.contexts = msg.contexts
		m.kcTyping = false
		for i, c := range msg.contexts {
			if c == msg.current {
				m.ctxCursor = i
			}
		}
		next := func() (stage, tea.Cmd) {
			if m.mission.NeedsTarget {
				return stageTargetVersion, nil
			}
			// No target needed: connect and scan immediately.
			return stageScanning, tea.Batch(m.spinner.Tick, connectCmd(m.kcChosen, m.ctxChosen))
		}
		if m.opts.Context != "" {
			m.ctxChosen = m.opts.Context
			st, cmd := next()
			m.stage = st
			return m, cmd
		}
		if len(msg.contexts) == 1 {
			// Only one cluster in the file - no meaningful choice to offer.
			m.ctxChosen = msg.contexts[0]
			st, cmd := next()
			m.stage = st
			return m, cmd
		}
		m.stage = stagePickContext
		return m, nil

	case contextsMsg:
		if msg.err != nil {
			m.err, m.stage = msg.err, stageError
			return m, nil
		}
		m.contexts = msg.contexts
		for i, c := range msg.contexts {
			if c == msg.current {
				m.ctxCursor = i
			}
		}
		// An explicit --context skips the picker entirely.
		if m.opts.Context != "" {
			m.ctxChosen = m.opts.Context
			m.stage = stageTargetVersion
		}
		return m, nil

	case connectedMsg:
		if msg.err != nil {
			m.err, m.stage = msg.err, stageError
			return m, nil
		}
		m.cluster = msg.cluster
		return m, m.startScan()

	case progressMsg:
		m.progress = scanProgress(msg)
		// Re-arm the listener. A Bubble Tea command fires exactly once, so
		// without this the scan would stall after its first progress update.
		return m, waitForProgress(m.updates, m.done)

	case scanDoneMsg:
		if msg.err != nil {
			m.err, m.stage = msg.err, stageError
			return m, nil
		}
		m.report = msg.report
		m.ordered, m.passed, m.skipped = orderFindings(msg.report)
		m.resCursor, m.resScroll = 0, 0
		m.reportPath, m.reportErr = msg.reportPath, msg.reportErr
		m.stage = stageResults
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	return m, nil
}

// handleKey routes key presses according to the current stage.
func (m Model) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Quit is always available. Cancelling an in-flight scan avoids leaking the
	// goroutines still talking to the API server.
	if key == "ctrl+c" {
		if m.cancel != nil {
			m.cancel()
		}
		return m, tea.Quit
	}

	switch m.stage {

	case stageWelcome:
		switch key {
		case "q", "esc":
			return m, tea.Quit
		case "enter", " ", "space":
			m.stage = stagePickMission
			// With nothing discovered there is nothing to pick from, so go
			// straight to asking for a path rather than showing an empty list.
			if m.kcDiscovered && len(m.kubeconfigs) == 0 {
				m.kcTyping = true
			}
		}
		return m, nil

	case stagePickMission:
		missions := analyzer.Missions()
		switch key {
		case "q", "esc":
			return m, tea.Quit
		case "up", "k":
			if m.missionCursor > 0 {
				m.missionCursor--
			}
		case "down", "j":
			if m.missionCursor < len(missions)-1 {
				m.missionCursor++
			}
		case "enter":
			m.mission = missions[m.missionCursor]
			m.stage = stagePickKubeconfig
			if m.kcDiscovered && len(m.kubeconfigs) == 0 {
				m.kcTyping = true
			}
		}
		return m, nil

	case stagePickKubeconfig:
		if m.kcTyping {
			return m.handleKubeconfigInput(key)
		}
		switch key {
		case "q", "esc":
			return m, tea.Quit
		case "up", "k":
			if m.kcCursor > 0 {
				m.kcCursor--
			}
		case "down", "j":
			if m.kcCursor < len(m.kubeconfigs) {
				m.kcCursor++
			}
		case "e", "o":
			// The row past the end of the list is "enter a path myself".
			m.kcTyping, m.kcCursor = true, len(m.kubeconfigs)
		case "enter":
			if m.kcCursor >= len(m.kubeconfigs) {
				m.kcTyping = true
				return m, nil
			}
			cand := m.kubeconfigs[m.kcCursor]
			if !cand.Usable() {
				m.kcErr = fmt.Errorf("%s cannot be used: %s", cand.Label(), cand.Detail())
				return m, nil
			}
			return m, validateKubeconfigCmd(cand.Path)
		}
		return m, nil

	case stagePickContext:
		switch key {
		case "q", "esc":
			return m, tea.Quit
		case "up", "k":
			if m.ctxCursor > 0 {
				m.ctxCursor--
			}
		case "down", "j":
			if m.ctxCursor < len(m.contexts)-1 {
				m.ctxCursor++
			}
		case "enter":
			if len(m.contexts) > 0 {
				m.ctxChosen = m.contexts[m.ctxCursor]
				if m.mission.NeedsTarget {
					m.stage = stageTargetVersion
				} else {
					m.stage = stageScanning
					return m, tea.Batch(m.spinner.Tick, connectCmd(m.kcChosen, m.ctxChosen))
				}
			}
		case "backspace", "left", "h":
			m.stage = stagePickKubeconfig
		}
		return m, nil

	case stageTargetVersion:
		switch key {
		case "esc":
			m.stage = stagePickContext
			if len(m.contexts) <= 1 {
				m.stage = stagePickKubeconfig
			}
		case "q":
			return m, tea.Quit
		case "backspace":
			if len(m.versionBuf) > 0 {
				m.versionBuf = m.versionBuf[:len(m.versionBuf)-1]
			}
		case "enter":
			if _, err := analyzer.ParseVersion(m.versionBuf); err != nil {
				return m, nil
			}
			m.stage = stageScanning
			// Connect with the kubeconfig the user actually chose. Using
			// opts.Kubeconfig here silently ignored the picker and fell back to
			// ambient default rules - so picking a file did nothing.
			return m, tea.Batch(m.spinner.Tick, connectCmd(m.kcChosen, m.ctxChosen))
		default:
			// Accept version characters only; ignore navigation and modifiers.
			if len(key) == 1 && (key[0] == '.' || (key[0] >= '0' && key[0] <= '9')) {
				m.versionBuf += key
			}
		}
		return m, nil

	case stageScanning:
		if key == "q" || key == "esc" {
			if m.cancel != nil {
				m.cancel()
			}
			return m, tea.Quit
		}
		return m, nil

	case stageResults:
		switch key {
		case "q", "esc":
			return m, tea.Quit
		case "up", "k":
			if m.resCursor > 0 {
				m.resCursor--
			}
		case "down", "j":
			if m.resCursor < len(m.ordered)-1 {
				m.resCursor++
			}
		case "home", "g":
			m.resCursor = 0
		case "end", "G":
			if len(m.ordered) > 0 {
				m.resCursor = len(m.ordered) - 1
			}
		case "p":
			m.showPassed = !m.showPassed
		case "enter", "right", "l":
			if len(m.ordered) > 0 {
				m.stage = stageDetail
			}
		case "r":
			m.stage = stageScanning
			m.report = nil
			return m, tea.Batch(m.spinner.Tick, m.startScan())
		}
		m.clampScroll()
		return m, nil

	case stageDetail:
		switch key {
		case "q", "esc", "left", "h", "enter":
			m.stage = stageResults
		case "up", "k":
			if m.resCursor > 0 {
				m.resCursor--
			}
		case "down", "j":
			if m.resCursor < len(m.ordered)-1 {
				m.resCursor++
			}
		}
		return m, nil

	case stageError:
		return m, tea.Quit
	}

	return m, nil
}

// handlePaste inserts pasted text into the active input field.
func (m Model) handlePaste(text string) (tea.Model, tea.Cmd) {
	switch {
	case m.stage == stagePickKubeconfig && m.kcTyping:
		// A pasted path arrives with whatever the clipboard had around it;
		// keep it to one line and drop control characters.
		m.kcInput += sanitizePaste(text, false)
	case m.stage == stageTargetVersion:
		m.versionBuf += sanitizePaste(text, true)
	}
	return m, nil
}

// sanitizePaste flattens pasted text to a single printable line. In version
// mode only digits and dots survive, matching what typing allows.
func sanitizePaste(text string, versionOnly bool) string {
	var b strings.Builder
	for _, r := range text {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			// stop at the first line break: a path or version is one line
			if b.Len() > 0 {
				return b.String()
			}
		case versionOnly && (r == '.' || (r >= '0' && r <= '9')):
			b.WriteRune(r)
		case versionOnly:
			// skip anything else, same as the keypress filter
		case r >= 32 && r != 127:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// handleKubeconfigInput handles typing a kubeconfig path by hand.
func (m Model) handleKubeconfigInput(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc":
		m.kcTyping, m.kcInput, m.kcErr = false, "", nil
	case "enter":
		if strings.TrimSpace(m.kcInput) == "" {
			return m, nil
		}
		return m, validateKubeconfigCmd(strings.TrimSpace(m.kcInput))
	case "backspace":
		if len(m.kcInput) > 0 {
			m.kcInput = m.kcInput[:len(m.kcInput)-1]
		}
	case "space":
		m.kcInput += " "
	default:
		// Accept printable single characters; ignore navigation and modifiers.
		if len([]rune(key)) == 1 {
			m.kcInput += key
		}
	}
	return m, nil
}

// orderedFinding pairs a finding with its worklist bucket for rendering.
type orderedFinding struct {
	Finding analyzer.Finding
	Bucket  analyzer.Bucket
}

// orderFindings flattens the report into worklist order - the same order the
// CLI prints - and splits out passing and skipped checks for the collapsed
// footer sections.
func orderFindings(r *analyzer.Report) (ordered []orderedFinding, passed, skipped []analyzer.Finding) {
	if r == nil {
		return nil, nil, nil
	}
	for _, g := range r.Worklist() {
		for _, f := range g.Findings {
			ordered = append(ordered, orderedFinding{Finding: f, Bucket: g.Bucket})
		}
	}
	for _, f := range r.Findings {
		if f.Error != "" || f.Result == nil {
			continue
		}
		switch f.Result.Status {
		case analyzer.StatusPass:
			passed = append(passed, f)
		case analyzer.StatusSkip:
			skipped = append(skipped, f)
		}
	}
	return ordered, passed, skipped
}

// visibleRows is how many finding rows fit on screen, leaving room for the
// header, summary, and help line.
func (m Model) visibleRows() int {
	n := m.height - 12
	if n < 3 {
		return 3
	}
	return n
}

// clampScroll keeps the cursor inside the visible window.
func (m *Model) clampScroll() {
	rows := m.visibleRows()
	if m.resCursor < m.resScroll {
		m.resScroll = m.resCursor
	}
	if m.resCursor >= m.resScroll+rows {
		m.resScroll = m.resCursor - rows + 1
	}
	if m.resScroll < 0 {
		m.resScroll = 0
	}
}

// startScan builds the engine and runs it in the background, streaming progress
// back into the model.
func (m *Model) startScan() tea.Cmd {
	cluster := m.cluster
	if cluster == nil {
		return nil
	}

	var target analyzer.Version
	if m.mission.NeedsTarget {
		var err error
		if target, err = analyzer.ParseVersion(m.versionBuf); err != nil {
			return func() tea.Msg { return scanDoneMsg{err: err} }
		}
	} else {
		target = cluster.ServerVersion
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel

	suite := analyzer.AllChecks
	if m.mission.Checks != nil {
		suite = m.mission.Checks
	}
	engine := analyzer.NewEngine(suite()...)
	providerChecks, detectFailures := provider.ChecksFor(ctx, cluster)
	for _, pc := range providerChecks {
		if m.mission.ProviderChecks != nil && m.mission.ProviderChecks(pc.Name) {
			engine.Register(pc)
		}
	}

	up := analyzer.Upgrade{From: cluster.ServerVersion, To: target}

	// Progress updates are delivered through a channel because the engine calls
	// the callback from many goroutines, while Bubble Tea needs one message at a
	// time on a single command.
	m.updates = make(chan scanProgress, engine.Len())
	m.done = make(chan scanDoneMsg, 1)
	updates, done := m.updates, m.done
	missionName := m.mission.Name

	saveReport := func(rep *analyzer.Report) (string, error) {
		path := fmt.Sprintf("kupre-%s-report.html", missionName)
		f, err := os.Create(path)
		if err != nil {
			return "", err
		}
		werr := report.WriteHTML(f, rep, report.Options{})
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return "", werr
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return path, nil
		}
		return abs, nil
	}

	go func() {
		rep := engine.Run(ctx, cluster, up, func(d, t int, name string) {
			// Never block the engine on a slow UI: drop an update rather than
			// stall a check goroutine. The final report still arrives on done.
			select {
			case updates <- scanProgress{done: d, total: t, last: name}:
			default:
			}
		})
		rep.Mission = missionName
		rep.Errors = append(rep.Errors, detectFailures...)
		path, perr := saveReport(rep)
		done <- scanDoneMsg{report: rep, reportPath: path, reportErr: perr}
	}()

	return tea.Batch(
		waitForProgress(updates, done),
		m.spinner.Tick,
	)
}

// waitForProgress blocks until either a progress update or the finished report
// is available, and reports whichever arrived. The caller re-arms it after each
// progress message; the scanDoneMsg ends the sequence.
//
// done is checked first on each wakeup so a completed scan is not delayed
// behind a backlog of buffered progress updates.
func waitForProgress(updates <-chan scanProgress, done <-chan scanDoneMsg) tea.Cmd {
	return func() tea.Msg {
		if updates == nil || done == nil {
			return scanDoneMsg{err: fmt.Errorf("scan was not started")}
		}
		select {
		case msg := <-done:
			return msg
		default:
		}
		select {
		case p := <-updates:
			return progressMsg(p)
		case msg := <-done:
			return msg
		}
	}
}

// Run starts the interactive program.
func Run(opts Options) error {
	p := tea.NewProgram(New(opts))
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("run interactive UI: %w", err)
	}
	return nil
}

// truncate shortens s to width, appending an ellipsis when it does not fit.
func truncate(s string, width int) string {
	if width <= 1 || len(s) <= width {
		return s
	}
	if width <= 2 {
		return s[:width]
	}
	return s[:width-1] + "…"
}

// wrap breaks s into lines no longer than width.
func wrap(s string, width int) []string {
	if width < 10 {
		width = 10
	}
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	var (
		lines []string
		cur   strings.Builder
	)
	for _, w := range words {
		if cur.Len() > 0 && cur.Len()+1+len(w) > width {
			lines = append(lines, cur.String())
			cur.Reset()
		}
		if cur.Len() > 0 {
			cur.WriteByte(' ')
		}
		cur.WriteString(w)
	}
	if cur.Len() > 0 {
		lines = append(lines, cur.String())
	}
	return lines
}

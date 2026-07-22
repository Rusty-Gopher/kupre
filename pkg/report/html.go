package report

import (
	"fmt"
	"html"
	"io"
	"strings"
	"time"

	"github.com/Rusty-Gopher/kupre/pkg/analyzer"
)

// WriteHTML renders the report as a single self-contained HTML file: inline
// CSS, no external assets, no scripts. It follows the terminal's light or dark
// preference, prints cleanly, and is safe to attach to a change ticket - every
// dynamic string is escaped, and it contains only what the terminal report
// contains (never kubeconfig paths, credentials, or Helm values).
// noDash replaces em-dashes in rendered text with plain punctuation.
func noDash(s string) string {
	s = strings.ReplaceAll(s, " — ", " - ")
	return strings.ReplaceAll(s, "—", "-")
}

func WriteHTML(w io.Writer, r *analyzer.Report, opts Options) error {
	sum := r.Summarize()
	e := func(s string) string { return html.EscapeString(noDash(s)) }

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>kupre preflight: %s</title>
<style>%s</style>
</head>
<body>
<main>
`, e(r.Cluster), htmlCSS)

	// ---- Hero: the answer first. ----
	verdictClass, verdictText, verdictSub := htmlVerdict(sum, r)
	fmt.Fprintf(w, `<header>
  <div class="brand">kupre <span>· Kubernetes upgrade preflight</span></div>
  <h1>%s</h1>
  <div class="cluster">%s</div>
  <div class="verdict %s">%s</div>
  <div class="verdict-sub">%s</div>
  <div class="chips">
    <span class="chip fail">%d blocking</span>
    <span class="chip warn">%d to review</span>
    <span class="chip pass">%d passed</span>
    <span class="chip mute">%d not applicable</span>
  </div>
</header>
`,
		htmlHeading(r), e(r.Cluster),
		verdictClass, e(verdictText), e(verdictSub),
		sum.Blocking, sum.Concerning, sum.Passed, sum.Skipped)

	for _, tl := range r.Errors {
		fmt.Fprintf(w, `<div class="toolerror">%s</div>`+"\n", e(tl))
	}

	// ---- Pages. Pure-CSS tabs: hidden radio inputs + labels; no scripts. ----
	groups := r.Worklist()

	// The first findings section is the landing page; "How to read this" sits
	// last, for the reader who wants the legend rather than the answer.
	firstPage := "quiet"
	if len(groups) > 0 {
		firstPage = pageID(groups[0].Bucket)
	}

	// Radio inputs must precede every page they control (CSS sibling selector).
	for _, g := range groups {
		checked := ""
		if pageID(g.Bucket) == firstPage {
			checked = " checked"
		}
		fmt.Fprintf(w, `<input type="radio" name="pg" id="pg-%s" class="pgr"%s>`+"\n", pageID(g.Bucket), checked)
	}
	if firstPage == "quiet" {
		fmt.Fprint(w, `<input type="radio" name="pg" id="pg-quiet" class="pgr" checked>`+"\n")
	} else {
		fmt.Fprint(w, `<input type="radio" name="pg" id="pg-quiet" class="pgr">`+"\n")
	}
	fmt.Fprint(w, `<input type="radio" name="pg" id="pg-overview" class="pgr">`+"\n")

	// Tab bar: findings first, passed, legend last.
	fmt.Fprint(w, `<nav class="tabs">`+"\n")
	for _, g := range groups {
		fmt.Fprintf(w, `  <label for="pg-%s" class="t-%s">%s <span>%d</span></label>`+"\n",
			pageID(g.Bucket), pageID(g.Bucket), e(tabTitle(g.Bucket, r.Mission)), len(g.Findings))
	}
	fmt.Fprintf(w, `  <label for="pg-quiet">Passed <span>%d</span></label>`+"\n", sum.Passed+sum.Skipped)
	fmt.Fprint(w, `  <label for="pg-overview">How to read this</label>`+"\n")
	fmt.Fprint(w, "</nav>\n")

	// One page per worklist section; finding cards unchanged.
	n := 0
	for _, g := range groups {
		fmt.Fprintf(w, `<div class="page" id="page-%s"><section class="bucket %s">
  <h2>%s</h2>
`, pageID(g.Bucket), htmlBucketClass(g.Bucket), e(g.Bucket.TitleFor(r.Mission)))
		for _, f := range g.Findings {
			n++
			writeHTMLFinding(w, n, f, opts)
		}
		fmt.Fprint(w, "</section></div>\n")
	}
	if len(groups) == 0 {
		fmt.Fprint(w, `<div class="page always"><section class="bucket ok"><h2>Nothing to do. No findings.</h2></section></div>`+"\n")
	}

	// Passing / skipped page.
	fmt.Fprint(w, `<div class="page" id="page-quiet">`+"\n")
	writeHTMLQuietChecks(w, r)
	fmt.Fprint(w, "</div>\n")

	// Legend page, last.
	writeHTMLOverview(w, r.Mission, groups, sum)

	fmt.Fprintf(w, `<footer>
  Generated %s by kupre. Read-only scan, nothing was modified.
  Absence of a finding is not proof of absence.
</footer>
</main>
</body>
</html>
`, e(time.Now().Format("2006-01-02 15:04 MST")))
	return nil
}

// pageID maps a bucket to its tab/page identifier.
func pageID(b analyzer.Bucket) string {
	return strings.TrimPrefix(htmlBucketClass(b), "b-")
}

// tabTitle is the short tab label for a bucket: the mission's section title up
// to its first dash.
func tabTitle(b analyzer.Bucket, mission string) string {
	t := b.TitleFor(mission)
	if i := strings.Index(t, ":"); i > 0 {
		t = t[:i]
	}
	// Tab labels read better in sentence case.
	return strings.ToUpper(t[:1]) + strings.ToLower(t[1:])
}

// writeHTMLOverview renders the legend page: what the classification layers
// mean, that they are kupre's own taxonomy, and an index into the sections.
func writeHTMLOverview(w io.Writer, mission string, groups []analyzer.BucketGroup, sum analyzer.Summary) {
	// List the active mission's own section titles.
	var sectionNames []string
	for _, b := range []analyzer.Bucket{
		analyzer.BucketFixBeforeStart, analyzer.BucketPlanAhead,
		analyzer.BucketVerifyManually, analyzer.BucketResolveFirst,
		analyzer.BucketReviewLater,
	} {
		t := b.TitleFor(mission)
		if i := strings.Index(t, ":"); i > 0 {
			t = t[:i]
		}
		sectionNames = append(sectionNames, t)
	}

	fmt.Fprintf(w, `<div class="page" id="page-overview">
<section class="legend">
  <h2>How to read this report</h2>
  <table class="deftable">
    <tr><th>Label</th><th>Meaning</th></tr>
    <tr><td><strong>Tabs</strong></td>
        <td>Findings grouped by urgency: %s.</td></tr>
    <tr><td><strong>Category</strong></td>
        <td>The subsystem: <code>api</code>, <code>webhook</code>, <code>storage</code>,
            <code>node</code>, <code>workload</code>, <code>cloud</code>.</td></tr>
    <tr><td><strong>Severity</strong></td>
        <td>Whether a failure of this check blocks: error, warning, info.</td></tr>
    <tr><td><strong>Badge</strong></td>
        <td>What this scan found:
            <span class="badge fail">FAIL</span> <span class="badge warn">WARN</span>
            <span class="badge pass">PASS</span> <span class="badge skip">SKIP</span></td></tr>
  </table>
  <p>Only a failed error-severity check blocks. A card can read "severity error"
     with a WARN badge: the check can block, what it found this time does not.</p>
  <p>Every card has an <strong>Evidence &amp; limits</strong> note: what was
     inspected, and what cannot be concluded from it. A pass claims only its
     stated evidence.</p>
  <p class="provenance">These groups are kupre&#39;s own, not a Kubernetes
     standard. The facts come from the cluster and from Kubernetes docs and
     changelogs.</p>

  <h2>Sections</h2>
  <ul class="secindex">
`, html.EscapeString(strings.Join(sectionNames, " · ")))
	descs := map[analyzer.Bucket]string{
		analyzer.BucketFixBeforeStart: "The most urgent findings. Fix these first; the fixes are usually quick.",
		analyzer.BucketPlanAhead:      "Needs lead time or planning.",
		analyzer.BucketVerifyManually: "Outside what a read-only Kubernetes client can see. A human must confirm each.",
		analyzer.BucketResolveFirst:   "Already degraded today. Worth clearing so new failures stay attributable.",
		analyzer.BucketReviewLater:    "Real findings, lower urgency.",
		analyzer.BucketInconclusive:   "Checks that could not run - treat their subjects as unverified, not clean.",
	}
	for _, g := range groups {
		fmt.Fprintf(w, `    <li><label for="pg-%s" class="t-%s"><strong>%s</strong> <span>%d finding(s)</span><br>%s</label></li>`+"\n",
			pageID(g.Bucket), pageID(g.Bucket),
			html.EscapeString(g.Bucket.TitleFor(mission)), len(g.Findings),
			html.EscapeString(descs[g.Bucket]))
	}
	fmt.Fprintf(w, `    <li><label for="pg-quiet"><strong>Passed</strong> <span>%d check(s)</span><br>Each states what it verified.</label></li>`+"\n",
		sum.Passed+sum.Skipped)
	fmt.Fprint(w, "  </ul>\n</section>\n</div>\n")
}

// writeHTMLFinding renders one finding card.
func writeHTMLFinding(w io.Writer, n int, f analyzer.Finding, opts Options) {
	e := func(s string) string { return html.EscapeString(noDash(s)) }
	msg := ""
	if f.Result != nil {
		msg = f.Result.Message
	}
	if f.Error != "" {
		msg = "check could not run: " + f.Error
	}

	fmt.Fprintf(w, `  <article class="finding">
    <div class="finding-head">
      <span class="num">%d</span>
      <span class="badge %s">%s</span>
      <h3>%s</h3>
    </div>
    <div class="meta"><code>%s</code> · %s · severity %s</div>
`, n, htmlStatusClass(f), e(mdStatus(f)), e(msg), e(f.Check), e(string(f.Category)), e(f.Severity.String()))

	if f.Result != nil {
		if len(f.Result.Resources) > 0 {
			limit := opts.resourceLimit()
			fmt.Fprint(w, `    <ul class="resources">`+"\n")
			for i, res := range f.Result.Resources {
				if i >= limit {
					fmt.Fprintf(w, `      <li class="more">… and %d more</li>`+"\n",
						len(f.Result.Resources)-limit)
					break
				}
				detail := ""
				if res.Detail != "" {
					detail = ` <span class="detail">· ` + e(res.Detail) + `</span>`
				}
				fmt.Fprintf(w, `      <li><code>%s</code>%s</li>`+"\n", e(res.String()), detail)
			}
			fmt.Fprint(w, "    </ul>\n")
		}
		if f.Result.Remediation != "" {
			fmt.Fprintf(w, `    <p class="fix"><strong>Fix</strong> %s</p>`+"\n", e(f.Result.Remediation))
		}
		if len(f.Result.Commands) > 0 {
			var b strings.Builder
			for _, c := range f.Result.Commands {
				b.WriteString("$ " + c + "\n")
			}
			fmt.Fprintf(w, `    <pre class="cmd">%s</pre>`+"\n", e(strings.TrimRight(b.String(), "\n")))
		}
	}
	if f.Evidence != "" || f.Limits != "" {
		fmt.Fprint(w, `    <details class="evidence"><summary>Evidence &amp; limits</summary>`+"\n")
		if f.Evidence != "" {
			fmt.Fprintf(w, `      <p><strong>Inspected</strong> %s</p>`+"\n", e(f.Evidence))
		}
		if f.Limits != "" {
			fmt.Fprintf(w, `      <p><strong>Cannot conclude</strong> %s</p>`+"\n", e(f.Limits))
		}
		fmt.Fprint(w, "    </details>\n")
	}
	if f.Result != nil && f.Result.Docs != "" {
		fmt.Fprintf(w, `    <a class="docs" href="%s">documentation ↗</a>`+"\n", e(f.Result.Docs))
	}
	fmt.Fprint(w, "  </article>\n")
}

// writeHTMLQuietChecks renders passing and skipped checks behind a disclosure.
func writeHTMLQuietChecks(w io.Writer, r *analyzer.Report) {
	e := func(s string) string { return html.EscapeString(noDash(s)) }
	var passed, skipped []string
	for _, f := range r.Findings {
		if f.Result == nil || f.Error != "" {
			continue
		}
		switch f.Result.Status {
		case analyzer.StatusPass:
			passed = append(passed, f.Check+" - "+f.Result.Message)
		case analyzer.StatusSkip:
			skipped = append(skipped, f.Check+" - "+f.Result.Message)
		}
	}
	if len(passed) == 0 && len(skipped) == 0 {
		return
	}
	fmt.Fprintf(w, `<section class="quiet"><h2>Passed (%d) · Not applicable (%d)</h2>
  <ul>
`, len(passed), len(skipped))
	for _, p := range passed {
		fmt.Fprintf(w, `    <li class="p">%s</li>`+"\n", e(p))
	}
	for _, sk := range skipped {
		fmt.Fprintf(w, `    <li class="s">%s</li>`+"\n", e(sk))
	}
	fmt.Fprint(w, "  </ul>\n</section>\n")
}

// htmlHeading renders the hero title for the report's mission.
func htmlHeading(r *analyzer.Report) string {
	e := func(s string) string { return html.EscapeString(noDash(s)) }
	name := r.Mission
	if name == "" {
		name = "upgrade"
	}
	if m, ok := analyzer.MissionByName(name); ok && !m.NeedsTarget {
		return e(m.Title) + ` <span class="arrow">·</span> ` + e(r.Upgrade.From.String())
	}
	return e(r.Upgrade.From.String()) + ` <span class="arrow">→</span> ` + e(r.Upgrade.To.String())
}

// htmlVerdict maps the summary to the hero verdict.
func htmlVerdict(sum analyzer.Summary, r *analyzer.Report) (class, text, sub string) {
	switch {
	case len(r.Errors) > 0 || sum.Errored > 0:
		return "inconclusive", "INCONCLUSIVE",
			"Some checks could not run. Do not treat this as a clean result."
	case sum.Blocking > 0:
		return "blocked", "NOT READY",
			fmt.Sprintf("%d blocking issue(s). Work the tabs left to right, then re-scan.", sum.Blocking)
	case sum.Concerning > 0:
		return "caveats", "READY, WITH CAVEATS",
			fmt.Sprintf("Nothing blocking. %d finding(s) worth a look.", sum.Concerning)
	default:
		return "ready", "READY", "All checks passed."
	}
}

// htmlBucketClass maps buckets to CSS classes.
func htmlBucketClass(b analyzer.Bucket) string {
	switch b {
	case analyzer.BucketFixBeforeStart, analyzer.BucketInconclusive:
		return "b-block"
	case analyzer.BucketPlanAhead:
		return "b-plan"
	case analyzer.BucketVerifyManually:
		return "b-verify"
	case analyzer.BucketResolveFirst:
		return "b-resolve"
	default:
		return "b-later"
	}
}

// htmlStatusClass maps a finding's status to a badge class.
func htmlStatusClass(f analyzer.Finding) string {
	switch {
	case f.Error != "":
		return "err"
	case f.Blocking():
		return "fail"
	case f.Concerning():
		return "warn"
	case f.Result != nil && f.Result.Status == analyzer.StatusSkip:
		return "skip"
	default:
		return "pass"
	}
}

// htmlCSS is the report's entire stylesheet. Light theme by default, dark via
// prefers-color-scheme; print rules keep cards intact across pages.
const htmlCSS = `
:root{
  --bg:#f6f8fa; --card:#ffffff; --fg:#1f2328; --muted:#59636e; --line:#d1d9e0;
  --red:#c1121f; --red-bg:#ffebe9; --amber:#9a6700; --amber-bg:#fff8c5;
  --green:#116329; --green-bg:#dafbe1; --blue:#0550ae; --blue-bg:#ddf4ff;
  --code-bg:#f0f2f5; --cmd-bg:#24292f; --cmd-fg:#7ee787;
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#0d1117; --card:#161b22; --fg:#e6edf3; --muted:#9198a1; --line:#30363d;
    --red:#ff7b72; --red-bg:#3c1618; --amber:#e3b341; --amber-bg:#3a2d12;
    --green:#56d364; --green-bg:#12261e; --blue:#79c0ff; --blue-bg:#121d2f;
    --code-bg:#1f242c; --cmd-bg:#010409; --cmd-fg:#7ee787;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:920px;margin:0 auto;padding:32px 20px 60px}
code,pre{font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;font-size:13px}
header{margin-bottom:28px}
.brand{font-weight:700;letter-spacing:.5px}
.brand span{font-weight:400;color:var(--muted)}
h1{margin:.35em 0 0;font-size:30px}
h1 .arrow{color:var(--muted);font-weight:400}
.cluster{color:var(--muted);margin-bottom:14px}
.verdict{display:inline-block;padding:6px 16px;border-radius:8px;font-weight:800;font-size:19px;letter-spacing:.5px}
.verdict.blocked{background:var(--red-bg);color:var(--red)}
.verdict.caveats{background:var(--amber-bg);color:var(--amber)}
.verdict.ready{background:var(--green-bg);color:var(--green)}
.verdict.inconclusive{background:var(--red-bg);color:var(--red)}
.verdict-sub{margin-top:8px;color:var(--muted)}
.chips{margin-top:14px;display:flex;gap:8px;flex-wrap:wrap}
.chip{padding:3px 10px;border-radius:999px;font-size:13px;font-weight:600;border:1px solid var(--line)}
.chip.fail{color:var(--red)} .chip.warn{color:var(--amber)}
.chip.pass{color:var(--green)} .chip.mute{color:var(--muted)}
.toolerror{background:var(--red-bg);color:var(--red);padding:10px 14px;border-radius:8px;margin:10px 0}
section.bucket{margin:26px 0}
section.bucket h2{font-size:14px;text-transform:uppercase;letter-spacing:1px;
  padding-left:10px;border-left:4px solid var(--muted);margin:0 0 12px}
.b-block h2{border-color:var(--red);color:var(--red)}
.b-plan h2{border-color:var(--amber);color:var(--amber)}
.b-verify h2{border-color:var(--blue);color:var(--blue)}
.b-resolve h2,.b-later h2{color:var(--muted)}
.finding{background:var(--card);border:1px solid var(--line);border-radius:10px;
  padding:16px 18px;margin-bottom:12px;break-inside:avoid}
.finding-head{display:flex;gap:10px;align-items:baseline}
.num{color:var(--muted);font-weight:700;min-width:1.4em}
.badge{font-size:11px;font-weight:800;padding:2px 8px;border-radius:6px;letter-spacing:.5px}
.badge.fail,.badge.err{background:var(--red-bg);color:var(--red)}
.badge.warn{background:var(--amber-bg);color:var(--amber)}
.badge.pass{background:var(--green-bg);color:var(--green)}
.badge.skip{background:var(--code-bg);color:var(--muted)}
.finding h3{margin:0;font-size:15.5px;font-weight:650}
.meta{color:var(--muted);font-size:13px;margin:6px 0 0 2.4em}
.meta code{background:var(--code-bg);padding:1px 6px;border-radius:5px}
.resources{list-style:none;margin:10px 0 0 2.4em;padding:0}
.resources li{padding:2px 0}
.resources li code{background:var(--code-bg);padding:1px 6px;border-radius:5px}
.resources .detail{color:var(--muted)}
.resources .more{color:var(--muted);font-style:italic}
.fix{margin:10px 0 0 2.4em}
.fix strong{color:var(--blue)}
pre.cmd{background:var(--cmd-bg);color:var(--cmd-fg);padding:10px 14px;border-radius:8px;
  margin:8px 0 0 2.4em;overflow-x:auto}
details.evidence{margin:10px 0 0 2.4em;color:var(--muted);font-size:13.5px}
details.evidence summary{cursor:pointer;user-select:none}
details.evidence p{margin:6px 0}
a.docs{display:inline-block;margin:8px 0 0 2.4em;color:var(--blue);font-size:13.5px;text-decoration:none}
a.docs:hover{text-decoration:underline}
section.quiet{color:var(--muted)}
section.quiet h2{font-size:14px;text-transform:uppercase;letter-spacing:1px;
  padding-left:10px;border-left:4px solid var(--green);color:var(--green);margin:0 0 12px}
section.quiet ul{list-style:none;padding-left:6px}
section.quiet li{padding:3px 0;font-size:13.5px}
section.quiet li.p::before{content:"✓ ";color:var(--green)}
section.quiet li.s::before{content:"– "}

/* ---- Pure-CSS pages: hidden radios drive which page is visible. ---- */
.pgr{position:absolute;opacity:0;pointer-events:none}
.page{display:none}
.page.always{display:block}
#pg-overview:checked ~ #page-overview{display:block}
#pg-block:checked ~ #page-block{display:block}
#pg-plan:checked ~ #page-plan{display:block}
#pg-verify:checked ~ #page-verify{display:block}
#pg-resolve:checked ~ #page-resolve{display:block}
#pg-later:checked ~ #page-later{display:block}
#pg-quiet:checked ~ #page-quiet{display:block}

nav.tabs{display:flex;flex-wrap:wrap;gap:6px;margin:22px 0 18px;
  border-bottom:1px solid var(--line);padding-bottom:10px}
nav.tabs label{cursor:pointer;padding:6px 12px;border-radius:8px;font-size:13.5px;
  font-weight:600;color:var(--muted);border:1px solid var(--line);user-select:none}
nav.tabs label span{opacity:.7;font-weight:700;margin-left:4px}
nav.tabs label:hover{color:var(--fg)}
nav.tabs label.t-block{color:var(--red)}
nav.tabs label.t-plan{color:var(--amber)}
nav.tabs label.t-verify{color:var(--blue)}
#pg-overview:checked ~ nav.tabs label[for="pg-overview"],
#pg-block:checked ~ nav.tabs label[for="pg-block"],
#pg-plan:checked ~ nav.tabs label[for="pg-plan"],
#pg-verify:checked ~ nav.tabs label[for="pg-verify"],
#pg-resolve:checked ~ nav.tabs label[for="pg-resolve"],
#pg-later:checked ~ nav.tabs label[for="pg-later"],
#pg-quiet:checked ~ nav.tabs label[for="pg-quiet"]{
  background:var(--card);border-color:currentColor;box-shadow:0 1px 3px rgba(0,0,0,.08)}

/* ---- Legend page ---- */
section.legend h2{font-size:16px;margin:0 0 10px}
section.legend h2 + p{margin-top:0}
section.legend > h2:not(:first-child){margin-top:26px}
.deftable{border-collapse:collapse;width:100%;margin:12px 0;font-size:14px}
.deftable th,.deftable td{text-align:left;padding:9px 12px;border:1px solid var(--line);vertical-align:top}
.deftable th{background:var(--code-bg);font-size:12.5px;text-transform:uppercase;letter-spacing:.5px}
.deftable code{background:var(--code-bg);padding:1px 6px;border-radius:5px}
.provenance{background:var(--blue-bg);border-left:4px solid var(--blue);
  padding:10px 14px;border-radius:0 8px 8px 0}
ul.secindex{list-style:none;padding:0;margin:0}
ul.secindex li{margin-bottom:8px}
ul.secindex label{display:block;cursor:pointer;background:var(--card);
  border:1px solid var(--line);border-radius:10px;padding:12px 16px;line-height:1.5}
ul.secindex label:hover{border-color:var(--muted)}
ul.secindex label span{color:var(--muted);font-weight:400;font-size:13px}
ul.secindex label.t-block strong{color:var(--red)}
ul.secindex label.t-plan strong{color:var(--amber)}
ul.secindex label.t-verify strong{color:var(--blue)}
footer{margin-top:40px;padding-top:14px;border-top:1px solid var(--line);
  color:var(--muted);font-size:13px}
@media print{
  body{background:#fff}
  .finding{border:1px solid #ccc;box-shadow:none}
  /* Print flattens the tabs back into one linear document. */
  nav.tabs{display:none}
  .page{display:block !important}
  .page{break-before:page}
  #page-overview{break-before:auto}
  /* details content is UA-hidden when closed; override so print shows it */
  details > *:not(summary){display:block !important}
  details summary{list-style:none}
}
`

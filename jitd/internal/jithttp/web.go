package jithttp

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
	"github.com/atoonk/tailscale-jit/jitd/internal/setup"
	"github.com/atoonk/tailscale-jit/jitd/internal/slack"
	"github.com/atoonk/tailscale-jit/jitd/internal/slackbot"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

var pages = map[string]*template.Template{}

func init() {
	funcs := template.FuncMap{
		"principals": func(ps []jit.Principal) string {
			s := make([]string, len(ps))
			for i, p := range ps {
				s[i] = string(p)
			}
			return strings.Join(s, ", ")
		},
		"join": func(ss []string) string { return strings.Join(ss, ", ") },
		"ts": func(t any) string {
			switch v := t.(type) {
			case time.Time:
				return v.Local().Format("Jan 2 15:04:05 MST")
			case *time.Time:
				if v == nil {
					return ""
				}
				return v.Local().Format("Jan 2 15:04:05 MST")
			}
			return ""
		},
		"ago": func(t any) string {
			var v time.Time
			switch x := t.(type) {
			case time.Time:
				v = x
			case *time.Time:
				if x == nil {
					return ""
				}
				v = *x
			}
			return relative(v)
		},
		"reversed": func(ev []jit.Event) []jit.Event {
			out := slices.Clone(ev)
			slices.Reverse(out)
			return out
		},
		"human":    jit.Duration.Human,
		"sub":      func(a, b int) int { return a - b },
		"attrname": func(attr string) string { return strings.TrimPrefix(attr, jit.AttrPrefix) },
		"seq": func(a, b int) []int {
			var out []int
			for i := a; i <= b; i++ {
				out = append(out, i)
			}
			return out
		},
		"initial": func(s string) string {
			r, n := utf8.DecodeRuneInString(s)
			if n == 0 {
				return "?"
			}
			return strings.ToUpper(string(r))
		},
		// mine: is this request the viewer's own (same definition as the service).
		"mine":          func(me *jit.Identity, r *jit.AccessRequest) bool { return me != nil && jit.IsMine(*me, r) },
		"secs":          func(d jit.Duration) int64 { return int64(time.Duration(d) / time.Second) },
		"durfield":      durField,
		"durationUnits": func() []durationUnit { return durationUnits },
		"maxApprovals":  func() int { return jit.MaxApprovalsRequired },
		"slackform": func(w *jit.Workflow, f *slackField) map[string]any {
			cur := w.Slack
			if cur == nil {
				cur = &jit.WorkflowSlack{}
			}
			return map[string]any{"F": f, "Current": cur}
		},
	}
	base := template.Must(template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html"))
	entries, _ := fs.Glob(templateFS, "templates/*.html")
	for _, e := range entries {
		name := strings.TrimSuffix(strings.TrimPrefix(e, "templates/"), ".html")
		if name == "layout" {
			continue
		}
		pages[name] = template.Must(template.Must(base.Clone()).ParseFS(templateFS, e))
	}
}

// durationUnit is one unit in the amount + unit duration inputs.
type durationUnit struct {
	Suffix string // what the API takes after the number: "m", "h", "d"
	Label  string
	Size   time.Duration
}

// Seconds is Size in seconds, as the request form's script uses it.
func (u durationUnit) Seconds() int64 { return int64(u.Size / time.Second) }

var durationUnits = []durationUnit{
	{"m", "minutes", time.Minute},
	{"h", "hours", time.Hour},
	{"d", "days", 24 * time.Hour},
}

// durFieldData fills one amount + unit input.
type durFieldData struct {
	Name, Unit string
	N          int64
}

// durField splits d into its largest whole unit (2 hours, not 120 minutes)
// for the amount + unit input called name.
func durField(name string, d jit.Duration) durFieldData {
	out := durFieldData{Name: name, Unit: "m", N: int64(time.Duration(d) / time.Minute)}
	for _, u := range durationUnits {
		if d > 0 && time.Duration(d)%u.Size == 0 {
			out.Unit, out.N = u.Suffix, int64(time.Duration(d)/u.Size)
		}
	}
	return out
}

// relative renders t relative to now, e.g. "3m ago" or "in 58m".
func relative(t time.Time) string {
	d := time.Until(t)
	future := d > 0
	if !future {
		d = -d
	}
	var s string
	switch {
	case d < time.Minute:
		s = fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		s = fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		s = fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		s = fmt.Sprintf("%dd", int(d.Hours()/24))
	}
	if future {
		return "in " + s
	}
	return s + " ago"
}

// flowRow is an approval flow with what the tailnet policy says about it.
type flowRow struct {
	Flow   *jit.Workflow
	Policy *jit.PolicyUse
	Slack  *slackField // nil: no Slack integration in this build
}

// slackField fills the Slack part of the flow form.
type slackField struct {
	Connected bool
	Channels  []slack.Channel
	Error     string // the channels could not be listed
	// Missing is the flow's channel when it is not among Channels (deleted,
	// or private and the bot was removed).
	Missing string
}

// slackField builds the flow form's Slack part for w.
func (s *Server) slackField(r *http.Request, w *jit.Workflow) *slackField {
	if s.Slack == nil {
		return nil
	}
	f := &slackField{Connected: s.Slack.Status().Configured()}
	if f.Connected {
		cs, err := s.Slack.Channels(r.Context())
		if err != nil {
			f.Error = err.Error()
		}
		f.Channels = cs
	}
	if w.Slack != nil && w.Slack.Channel != "" && !slices.ContainsFunc(f.Channels, func(c slack.Channel) bool { return c.ID == w.Slack.Channel }) {
		f.Missing = w.Slack.Channel
	}
	return f
}

type page struct {
	Title    string
	Nav      string
	Me       *jit.Identity
	MeErr    string
	Admin    bool
	Approver bool   // approves for at least one flow: shows the approval views
	SetupBad bool   // the last setup check failed: marks the Setup link (admins)
	SlackOn  bool   // the build has the Slack integration (admins see its page)
	SlackBad string // Slack is set up but not connected: why (marks the Slack link)
	Changes  uint64 // store change counter at render time, for auto-refresh
	Data     any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name, title, nav string, data any) {
	s.renderStatus(w, r, http.StatusOK, name, title, nav, data)
}

// renderAdmin renders an admin page; its sidebar entry lives under Manage,
// so the nav key is prefixed to keep it apart from the user pages.
func (s *Server) renderAdmin(w http.ResponseWriter, r *http.Request, name, title, nav string, data any) {
	s.renderStatus(w, r, http.StatusOK, name, title, "admin-"+nav, data)
}

func (s *Server) renderStatus(w http.ResponseWriter, r *http.Request, status int, name, title, nav string, data any) {
	p := page{Title: title, Nav: nav, Data: data, Changes: s.Svc.Store.Changes()}
	if id, err := s.Resolver.Resolve(r.Context(), r); err != nil {
		p.MeErr = jit.AsError(err).Message
	} else {
		p.Me = &id
		p.Admin = s.Svc.IsAdmin(r.Context(), id)
		p.Approver = s.Svc.IsApprover(r.Context(), id)
		if p.Admin && s.Setup != nil {
			if res := s.Setup.Last(); res != nil && !res.OK {
				p.SetupBad = true
			}
		}
		if p.Admin && s.Slack != nil {
			p.SlackOn, p.SlackBad = true, s.Slack.Problem()
		}
	}
	var buf bytes.Buffer
	if err := pages[name].ExecuteTemplate(&buf, "layout", p); err != nil {
		s.Log.Error("render", "page", name, "err", err)
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	buf.WriteTo(w)
}

func isStatic(p string) bool { return strings.HasPrefix(p, "/static/") }

func (s *Server) webRoutes(mux *http.ServeMux) {
	sub, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(sub)))

	// The user side: everything is personal (your requests, the ones you
	// approve for). Admins get the same pages plus the console under /admin.
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		s.render(w, r, "dashboard", "Overview", "overview", s.dashboard(r, false))
	})
	mux.HandleFunc("GET /requests", func(w http.ResponseWriter, r *http.Request) {
		s.requestsPage(w, r, false)
	})

	// The admin console.
	mux.HandleFunc("GET /admin", s.adminPage(func(w http.ResponseWriter, r *http.Request, _ jit.Identity) {
		s.renderAdmin(w, r, "dashboard", "Admin overview", "overview", s.dashboard(r, true))
	}))
	mux.HandleFunc("GET /admin/{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/admin", http.StatusFound) })
	mux.HandleFunc("GET /admin/requests", s.adminPage(func(w http.ResponseWriter, r *http.Request, _ jit.Identity) {
		s.requestsPage(w, r, true)
	}))
	mux.HandleFunc("GET /admin/workflows", s.adminPage(func(w http.ResponseWriter, r *http.Request, _ jit.Identity) {
		var rows []flowRow
		for _, wf := range s.Svc.ListWorkflows() {
			rows = append(rows, flowRow{Flow: wf, Policy: s.Svc.PolicyUse(r.Context(), wf)})
		}
		s.renderAdmin(w, r, "workflows", "Approval flows", "workflows", rows)
	}))
	mux.HandleFunc("GET /admin/workflows/new", s.adminPage(func(w http.ResponseWriter, r *http.Request, _ jit.Identity) {
		wf := &jit.Workflow{MaxDuration: jit.DefaultMaxDuration, ApprovalTimeout: jit.DefaultApprovalTimeout}
		wf.Normalize()
		wf.Attribute = ""
		s.renderAdmin(w, r, "workflow_form", "New approval flow", "workflows", flowRow{Flow: wf, Slack: s.slackField(r, wf)})
	}))
	mux.HandleFunc("GET /admin/workflows/{id}", s.adminPage(func(w http.ResponseWriter, r *http.Request, _ jit.Identity) {
		wf, err := s.Svc.GetWorkflow(r.PathValue("id"))
		if err != nil {
			s.notFound(w, r, err)
			return
		}
		s.renderAdmin(w, r, "workflow_form", "Edit approval flow", "workflows", flowRow{Flow: wf, Policy: s.Svc.PolicyUse(r.Context(), wf), Slack: s.slackField(r, wf)})
	}))
	mux.HandleFunc("GET /admin/policy", s.adminPage(func(w http.ResponseWriter, r *http.Request, _ jit.Identity) {
		missing := r.URL.Query().Get("missing") == "1"
		snip, err := s.Svc.CheckedSnippet(r.Context(), s.JITTag, missing)
		data := map[string]any{"Snippet": snip, "Missing": missing, "Checked": err == nil}
		if err != nil {
			data["Error"] = err.Error()
		}
		s.renderAdmin(w, r, "policy", "Policy snippet", "policy", data)
	}))
	mux.HandleFunc("GET /admin/setup", s.adminPage(func(w http.ResponseWriter, r *http.Request, _ jit.Identity) {
		var res *setup.Result
		if s.Setup != nil {
			res = s.setupResult(r)
		}
		s.renderAdmin(w, r, "setup", "Setup", "setup", res)
	}))
	mux.HandleFunc("GET /admin/slack", s.adminPage(func(w http.ResponseWriter, r *http.Request, id jit.Identity) {
		if s.Slack == nil {
			s.notFound(w, r, &jit.Error{Code: "not_found", Status: 404, Message: "no Slack integration in this build"})
			return
		}
		s.renderAdmin(w, r, "slack", "Slack", "slack", s.slackPage(r, id))
	}))
	// Old links.
	for _, old := range []string{"/workflows", "/workflows/{rest...}", "/policy"} {
		mux.HandleFunc("GET "+old, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/admin"+r.URL.RequestURI(), http.StatusMovedPermanently)
		})
	}
	mux.HandleFunc("GET /requests/new", func(w http.ResponseWriter, r *http.Request) {
		var wfs []jit.Requestable
		if id, err := s.Resolver.Resolve(r.Context(), r); err == nil {
			wfs = s.Svc.Requestable(r.Context(), id)
		}
		s.render(w, r, "request_form", "Request access", "requests", wfs)
	})
	mux.HandleFunc("GET /requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := s.Resolver.Resolve(r.Context(), r)
		if err != nil {
			s.notFound(w, r, err)
			return
		}
		req, err := s.Svc.GetRequest(r.Context(), id, r.PathValue("id"))
		if err == nil && unconfirmed(req) {
			req, err = s.Svc.VerifyNow(r.Context(), id, req.ID)
			s.Svc.CountVotes(r.Context(), req)
		}
		if err != nil {
			s.notFound(w, r, err)
			return
		}
		// Your own request sits under My requests; someone else's under the
		// overview where approvers find it (or All requests, for admins).
		nav := "requests"
		if !jit.IsMine(id, req) {
			nav = "overview"
			if s.Svc.IsAdmin(r.Context(), id) {
				nav = "admin-requests"
			}
		}
		s.render(w, r, "request", "Access request", nav, map[string]any{"R": req, "Can": s.Svc.Permissions(r.Context(), id, req), "SlackNote": s.slackNote(req)})
	})
	mux.HandleFunc("GET /help", func(w http.ResponseWriter, r *http.Request) {
		s.render(w, r, "help", "Help", "help", map[string]any{"MCPURL": s.base() + "/mcp", "AllowHTTP": strings.HasPrefix(s.base(), "http://")})
	})
}

// slackPageData fills the Slack page.
type slackPageData struct {
	Status   slackbot.Status
	Flows    []slackbot.FlowCheck
	CheckErr string
	Channels []slack.Channel
	// Domain is the admin's own email domain, the first guess for the
	// allowed domains.
	Domain string
}

func (s *Server) slackPage(r *http.Request, admin jit.Identity) slackPageData {
	d := slackPageData{Status: s.Slack.Status()}
	if _, dom, ok := strings.Cut(admin.Login, "@"); ok {
		d.Domain = strings.ToLower(dom)
	}
	if d.Status.Configured() {
		fcs, err := s.Slack.Check(r.Context())
		if err != nil {
			d.CheckErr = err.Error()
		}
		d.Flows = fcs
		d.Channels, _ = s.Slack.Channels(r.Context())
	}
	return d
}

// requestsPage lists requests: the viewer's own and the ones they approve
// for, or, in the admin console, everyone's.
func (s *Server) requestsPage(w http.ResponseWriter, r *http.Request, admin bool) {
	id, err := s.Resolver.Resolve(r.Context(), r)
	if err != nil {
		s.render(w, r, "requests", "Access requests", "requests", map[string]any{})
		return
	}
	q := r.URL.Query()
	st := jit.Status(q.Get("status"))
	scope := jit.Scope(q.Get("scope"))
	if admin {
		scope = jit.ScopeAll
	} else if scope != jit.ScopeApprovals {
		scope = jit.ScopeMine
	}
	counts := map[jit.Status]int{}
	all := s.Svc.ListRequests(r.Context(), jit.ListFilter{Viewer: id, Scope: scope})
	for _, q := range all {
		counts[q.Status]++
	}
	data := map[string]any{
		"Status":   st,
		"Scope":    scope,
		"Requests": s.Svc.ListRequests(r.Context(), jit.ListFilter{Viewer: id, Scope: scope, Status: st}),
		"Statuses": []jit.Status{jit.StatusPending, jit.StatusApproved, jit.StatusDeclined, jit.StatusExpired, jit.StatusRevoked, jit.StatusCancelled},
		"Counts":   counts,
		"Total":    len(all),
	}
	if admin {
		s.renderAdmin(w, r, "requests", "All requests", "requests", data)
		return
	}
	s.render(w, r, "requests", "Access requests", "requests", data)
}

// adminPage renders a "not allowed" page for non-admins.
func (s *Server) adminPage(h func(http.ResponseWriter, *http.Request, jit.Identity)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := s.Resolver.Resolve(r.Context(), r)
		if err != nil || !s.Svc.IsAdmin(r.Context(), id) {
			s.renderStatus(w, r, http.StatusForbidden, "forbidden", "Admins only", "", nil)
			return
		}
		h(w, r, id)
	}
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request, err error) {
	s.renderStatus(w, r, http.StatusNotFound, "notfound", "Not found", "", jit.AsError(err).Message)
}

// slackNote says why a pending request is missing from its flow's Slack
// channel, or "".
func (s *Server) slackNote(req *jit.AccessRequest) string {
	if s.Slack == nil {
		return ""
	}
	return s.Slack.RequestNote(req)
}

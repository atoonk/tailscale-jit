// Package jithttp serves jitd's JSON API and web UI.
package jithttp

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
	"github.com/atoonk/tailscale-jit/jitd/internal/setup"
	"github.com/atoonk/tailscale-jit/jitd/internal/tsapi"
)

// Server wires the service, caller identity and templates to HTTP.
type Server struct {
	Svc      *jit.Service
	Resolver jit.Resolver
	TS       tsapi.Client   // for the attribute passthrough endpoint
	Setup    *setup.Checker // the setup check behind /admin/setup; nil hides it
	JITTag   string         // tag used in the policy snippet, e.g. "tag:jit"
	BaseURL  string         // e.g. "http://jit"; used for approval links in responses
	// Hosts are the names and addresses jitd answers to (Host header,
	// without the port). A request for any other host is refused, so a page
	// whose DNS name is rebound to jitd's address cannot act as the viewer.
	// Empty allows any host (tests, the preview).
	Hosts []string
	Log   *slog.Logger
}

// Handler returns the full HTTP handler (API + web UI).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })

	mux.HandleFunc("GET /v1/me", s.withID(func(w http.ResponseWriter, r *http.Request, id jit.Identity) {
		writeJSON(w, http.StatusOK, map[string]any{
			"login": id.Login, "display_name": id.DisplayName, "device_id": id.DeviceID, "device_name": id.DeviceName,
			"tags": id.Tags, "admin": s.Svc.IsAdmin(r.Context(), id),
		})
	}))
	// Pages poll this to refresh when something changed.
	mux.HandleFunc("GET /v1/changes", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"changes": s.Svc.Store.Changes()})
	})

	// API description, for admins and the people building clients.
	mux.HandleFunc("GET /api/openapi.json", s.withAdmin(func(w http.ResponseWriter, r *http.Request, _ jit.Identity) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, s.openAPI())
	}))
	mux.HandleFunc("GET /api/docs", s.adminPage(func(w http.ResponseWriter, r *http.Request, _ jit.Identity) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, swaggerPage)
	}))
	mux.HandleFunc("GET /api", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/api/docs", http.StatusFound)
	})
	mux.HandleFunc("GET /api/{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/api/docs", http.StatusFound)
	})

	// Approval flows are admin-only; everyone else discovers what they may
	// request through /v1/requestable.
	mux.HandleFunc("GET /v1/workflows", s.withAdmin(func(w http.ResponseWriter, r *http.Request, _ jit.Identity) {
		writeJSON(w, http.StatusOK, map[string]any{"workflows": jit.OrEmpty(s.Svc.ListWorkflows())})
	}))
	mux.HandleFunc("POST /v1/workflows", s.withAdmin(func(w http.ResponseWriter, r *http.Request, _ jit.Identity) {
		var in jit.Workflow
		if !decode(w, r, &in) {
			return
		}
		out, err := s.Svc.CreateWorkflow(in)
		s.reply(w, http.StatusCreated, out, err)
	}))
	mux.HandleFunc("GET /v1/workflows/{id}", s.withAdmin(func(w http.ResponseWriter, r *http.Request, _ jit.Identity) {
		out, err := s.Svc.GetWorkflow(r.PathValue("id"))
		s.reply(w, http.StatusOK, out, err)
	}))
	mux.HandleFunc("PUT /v1/workflows/{id}", s.withAdmin(func(w http.ResponseWriter, r *http.Request, _ jit.Identity) {
		var in jit.Workflow
		if !decode(w, r, &in) {
			return
		}
		out, err := s.Svc.UpdateWorkflow(r.PathValue("id"), in)
		s.reply(w, http.StatusOK, out, err)
	}))
	mux.HandleFunc("DELETE /v1/workflows/{id}", s.withAdmin(func(w http.ResponseWriter, r *http.Request, _ jit.Identity) {
		if err := s.Svc.DeleteWorkflow(r.PathValue("id")); err != nil {
			writeErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	mux.HandleFunc("GET /v1/requestable", s.withID(func(w http.ResponseWriter, r *http.Request, id jit.Identity) {
		rs := s.Svc.Requestable(r.Context(), id)
		for i := range rs {
			if rs[i].ActiveRequestID != "" {
				rs[i].ActiveRequestURL = s.requestURL(rs[i].ActiveRequestID)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"identity": id, "requestable": jit.OrEmpty(rs)})
	}))

	mux.HandleFunc("GET /v1/requests", s.withID(func(w http.ResponseWriter, r *http.Request, id jit.Identity) {
		q := r.URL.Query()
		f := jit.ListFilter{Status: jit.Status(q.Get("status")), Viewer: id, Scope: jit.Scope(q.Get("scope"))}
		switch f.Scope {
		case "", jit.ScopeMine, jit.ScopeApprovals, jit.ScopeAll:
		default:
			writeErr(w, &jit.Error{Code: "bad_request", Status: http.StatusBadRequest, Message: "scope must be mine, approvals or all"})
			return
		}
		switch f.Status {
		case "", jit.StatusPending, jit.StatusApproved, jit.StatusDeclined, jit.StatusExpired, jit.StatusRevoked, jit.StatusCancelled:
		default:
			writeErr(w, &jit.Error{Code: "bad_request", Status: http.StatusBadRequest, Message: "status must be pending, approved, declined, cancelled, expired or revoked"})
			return
		}
		rs := s.Svc.ListRequests(r.Context(), f)
		for _, x := range rs {
			s.stamp(r.Context(), x)
		}
		writeJSON(w, http.StatusOK, map[string]any{"requests": jit.OrEmpty(rs)})
	}))
	mux.HandleFunc("POST /v1/requests", s.withID(func(w http.ResponseWriter, r *http.Request, id jit.Identity) {
		var in jit.NewRequest
		if !decode(w, r, &in) {
			return
		}
		out, err := s.Svc.Submit(r.Context(), id, in)
		s.reply(w, http.StatusCreated, s.stamp(r.Context(), out), err)
	}))
	mux.HandleFunc("GET /v1/requests/{id}", s.withID(func(w http.ResponseWriter, r *http.Request, id jit.Identity) {
		out, err := s.Svc.GetRequest(r.Context(), id, r.PathValue("id"))
		if err == nil && unconfirmed(out) {
			// Re-read the device while it is still worth it (just approved,
			// or ended and not yet seen gone).
			out, err = s.Svc.VerifyNow(r.Context(), id, out.ID)
		}
		s.reply(w, http.StatusOK, s.stamp(r.Context(), out), err)
	}))
	mux.HandleFunc("POST /v1/requests/{id}/{action}", s.withID(func(w http.ResponseWriter, r *http.Request, id jit.Identity) {
		var in struct {
			Note string `json:"note"`
		}
		if r.ContentLength != 0 && !decode(w, r, &in) {
			return
		}
		var act func(context.Context, jit.Identity, string, string) (*jit.AccessRequest, error)
		switch r.PathValue("action") {
		case "approve":
			act = s.Svc.Approve
		case "decline":
			act = s.Svc.Decline
		case "revoke":
			act = s.Svc.Revoke
		case "cancel":
			act = s.Svc.Cancel
		default:
			writeErr(w, &jit.Error{Code: "not_found", Status: http.StatusNotFound, Message: "unknown action " + r.PathValue("action")})
			return
		}
		out, err := act(r.Context(), id, r.PathValue("id"), in.Note)
		s.stamp(r.Context(), out)
		if err != nil && out != nil {
			// The action was recorded (e.g. approve_failed) but did not fully
			// succeed; return the error with the updated request.
			e := jit.AsError(err)
			writeJSON(w, e.Status, map[string]any{"error": errBody(e), "request": out})
			return
		}
		s.reply(w, http.StatusOK, out, err)
	}))

	mux.HandleFunc("GET /v1/setup", s.withAdmin(func(w http.ResponseWriter, r *http.Request, _ jit.Identity) {
		if s.Setup == nil {
			writeErr(w, &jit.Error{Code: "not_found", Status: 404, Message: "no setup check in this build"})
			return
		}
		writeJSON(w, 200, s.setupResult(r))
	}))
	mux.HandleFunc("POST /v1/setup/check", s.withAdmin(func(w http.ResponseWriter, r *http.Request, id jit.Identity) {
		if s.Setup == nil {
			writeErr(w, &jit.Error{Code: "not_found", Status: 404, Message: "no setup check in this build"})
			return
		}
		s.Log.Info("setup check requested", "by", id.Login)
		writeJSON(w, 200, s.Setup.Run(r.Context()))
	}))
	mux.HandleFunc("GET /v1/policy-snippet", s.withAdmin(func(w http.ResponseWriter, r *http.Request, _ jit.Identity) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		snip, _ := s.Svc.CheckedSnippet(r.Context(), s.JITTag, r.URL.Query().Get("missing") == "1")
		io.WriteString(w, snip)
	}))

	mux.HandleFunc("GET /v1/devices/{id}/attributes", s.withAdmin(func(w http.ResponseWriter, r *http.Request, _ jit.Identity) {
		a, err := s.TS.GetAttributes(r.Context(), r.PathValue("id"))
		if err != nil {
			writeErr(w, &jit.Error{Code: "tailscale_api_error", Status: http.StatusBadGateway, Message: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, a)
	}))

	s.webRoutes(mux)
	return s.logRequests(s.knownHost(secureHeaders(sameSite(mux))))
}

// secureHeaders stops the pages being framed (an overlay over an Approve
// button is a classic) and stops content-type sniffing. Pages may only run
// jitd's own script; the API docs page is the exception, as it loads
// Swagger UI from a CDN.
func secureHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Frame-Options", "DENY")
		csp := "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
		if r.URL.Path == "/api/docs" {
			csp = "frame-ancestors 'none'"
		}
		hd.Set("Content-Security-Policy", csp)
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "same-origin")
		h.ServeHTTP(w, r)
	})
}

// knownHost refuses requests addressed to a host jitd does not answer to.
// Without it, a web page whose DNS name the attacker re-points at jitd's
// tailnet address (DNS rebinding) would be same-origin with itself, pass
// sameSite, and be identified by WhoIs as whoever opened it.
func (s *Server) knownHost(h http.Handler) http.Handler {
	if len(s.Hosts) == 0 {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if hp, _, err := net.SplitHostPort(host); err == nil {
			host = hp
		}
		host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
		for _, ok := range s.Hosts {
			if ok != "" && strings.EqualFold(host, ok) {
				h.ServeHTTP(w, r)
				return
			}
		}
		writeErr(w, &jit.Error{Code: "unknown_host", Status: http.StatusMisdirectedRequest, Message: "this is jitd; use " + s.base()})
	})
}

// sameSite refuses browser-initiated cross-site mutations. Browsers send
// Sec-Fetch-Site (and Origin) on such requests; curl and the MCP client send
// neither and pass. Nothing mutates on GET, so GETs are not checked.
func sameSite(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
				writeErr(w, &jit.Error{Code: "forbidden", Status: http.StatusForbidden, Message: "cross-site request refused"})
				return
			}
			if o := r.Header.Get("Origin"); o != "" && !strings.EqualFold(strings.TrimPrefix(strings.TrimPrefix(o, "https://"), "http://"), r.Host) {
				writeErr(w, &jit.Error{Code: "forbidden", Status: http.StatusForbidden, Message: "cross-origin request refused"})
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

// unconfirmed reports whether the device state behind r still deserves a
// read-back: approved but not confirmed, or ended but not yet seen removed.
func unconfirmed(r *jit.AccessRequest) bool {
	if r.Enforcement.CheckedAt != nil && time.Since(*r.Enforcement.CheckedAt) < 10*time.Second {
		return false
	}
	return r.Unconfirmed(time.Now())
}

// setupResult returns the last setup result, running the check first if it
// has never run.
func (s *Server) setupResult(r *http.Request) *setup.Result {
	if res := s.Setup.Last(); res != nil {
		return res
	}
	return s.Setup.Run(r.Context())
}

// requestURL is the approval page for an access request.
func (s *Server) requestURL(id string) string {
	return s.base() + "/requests/" + id
}

// base is the URL people reach jitd at, without a trailing slash.
func (s *Server) base() string {
	return strings.TrimSuffix(cmp.Or(s.BaseURL, "http://jit"), "/")
}

// stamp fills in r.URL, r.Policy and r.ApprovalsCounted (r may be nil).
func (s *Server) stamp(ctx context.Context, r *jit.AccessRequest) *jit.AccessRequest {
	if r != nil {
		r.URL = s.requestURL(r.ID)
		r.Policy = s.Svc.RequestPolicy(ctx, r)
		s.Svc.CountVotes(ctx, r)
	}
	return r
}

// withID resolves the caller before calling h.
func (s *Server) withID(h func(http.ResponseWriter, *http.Request, jit.Identity)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := s.Resolver.Resolve(r.Context(), r)
		if err != nil {
			writeErr(w, err)
			return
		}
		h(w, r, id)
	}
}

// withAdmin resolves the caller and requires them to be an admin.
func (s *Server) withAdmin(h func(http.ResponseWriter, *http.Request, jit.Identity)) http.HandlerFunc {
	return s.withID(func(w http.ResponseWriter, r *http.Request, id jit.Identity) {
		if !s.Svc.IsAdmin(r.Context(), id) {
			writeErr(w, &jit.Error{Code: "forbidden", Status: http.StatusForbidden, Message: "admins only"})
			return
		}
		h(w, r, id)
	})
}

func (s *Server) reply(w http.ResponseWriter, status int, v any, err error) {
	if err != nil {
		e := jit.AsError(err)
		body := errBody(e)
		if e.RequestID != "" {
			body["url"] = s.requestURL(e.RequestID)
		}
		writeJSON(w, e.Status, map[string]any{"error": body})
		return
	}
	writeJSON(w, status, v)
}

func (s *Server) logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(sw, r)
		if r.URL.Path != "/healthz" && !isStatic(r.URL.Path) {
			s.Log.Debug("http", "method", r.Method, "path", r.URL.Path, "status", sw.status, "remote", r.RemoteAddr)
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) { w.status = code; w.ResponseWriter.WriteHeader(code) }

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, &jit.Error{Code: "bad_request", Status: http.StatusBadRequest, Message: "invalid JSON body: " + err.Error()})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	enc.Encode(v)
}

func errBody(e *jit.Error) map[string]string {
	m := map[string]string{"code": e.Code, "message": e.Message}
	if e.RequestID != "" {
		m["request_id"] = e.RequestID
	}
	return m
}

func writeErr(w http.ResponseWriter, err error) {
	e := jit.AsError(err)
	writeJSON(w, e.Status, map[string]any{"error": errBody(e)})
}

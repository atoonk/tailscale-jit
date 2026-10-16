package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"tailscale.com/client/local"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
)

// minDaemonVersion is the first tailscaled release that serves
// GET /localapi/v0/services (checked against published module sources:
// absent in v1.96.0, present in v1.98.0).
var minDaemonVersion = [2]int{1, 98}

const apiSource = "tailscaled LocalAPI GET /localapi/v0/services via tailscale.com/client/local.(*Client).GetServices"

// source is the subset of *local.Client used here, so tests can substitute it.
type source interface {
	StatusWithoutPeers(context.Context) (*ipnstate.Status, error)
	GetServices(context.Context) (map[tailcfg.ServiceName]tailcfg.ServiceDetails, error)
}

type discoverer struct {
	src     source
	timeout time.Duration
	log     *slog.Logger
	jit     *jitClient // optional: annotate services with the jitd approval that granted them
}

type listServicesInput struct{}

type listServicesOutput struct {
	Source        string    `json:"source" jsonschema:"where this data came from"`
	DaemonVersion string    `json:"daemon_version" jsonschema:"version reported by the local tailscaled"`
	Node          nodeInfo  `json:"node" jsonschema:"the local node the services are visible to"`
	ServiceCount  int       `json:"service_count"`
	Services      []service `json:"services" jsonschema:"services sorted by name"`
	Notes         []string  `json:"notes" jsonschema:"caveats about what this data does and does not tell you"`
}

type nodeInfo struct {
	HostName string `json:"host_name,omitempty"`
	DNSName  string `json:"dns_name,omitempty"`
	Tailnet  string `json:"tailnet,omitempty"`
}

type service struct {
	Name        string     `json:"name" jsonschema:"canonical service name, of the form svc:<dns-label>"`
	DisplayName string     `json:"display_name,omitempty" jsonschema:"optional human-readable label; omitted when control did not set one"`
	Hostname    string     `json:"hostname,omitempty" jsonschema:"MagicDNS name <name>.<tailnet MagicDNS suffix>, built the same way as 'tailscale service list'"`
	Addresses   []string   `json:"addresses" jsonschema:"service VIP addresses, IPv4 first"`
	Ports       []port     `json:"ports" jsonschema:"protocol/port ranges the service accepts"`
	Actions     []action   `json:"actions,omitempty" jsonschema:"optional hints from control on how a client may interact with a port"`
	Access      *jitAccess `json:"access,omitempty" jsonschema:"the approved jitd access request that makes this service visible, if any; absent means standing access or jitd could not be asked"`
}

type jitAccess struct {
	RequestID    string `json:"request_id"`
	WorkflowName string `json:"workflow_name" jsonschema:"approval flow, e.g. Database access (read-only); the policy's PAM permissions decide what you may do"`
	Attribute    string `json:"attribute" jsonschema:"the posture attribute that unlocks it"`
	Description  string `json:"description,omitempty" jsonschema:"the admin's description of this service in the flow"`
	ExpiresAt    string `json:"expires_at"`
	URL          string `json:"url"`
}

type port struct {
	Protocol string `json:"protocol" jsonschema:"IP protocol name, or 'any' for TCP+UDP+ICMP"`
	Ports    string `json:"ports" jsonschema:"single port, first-last range, or *"`
}

type action struct {
	Type        string         `json:"type" jsonschema:"action type slug, e.g. ssh, postgresql, http"`
	KnownType   bool           `json:"known_type" jsonschema:"whether this client library recognizes the type"`
	Port        uint16         `json:"port" jsonschema:"target TCP port"`
	DisplayName string         `json:"display_name,omitempty"`
	Attributes  map[string]any `json:"attributes,omitempty" jsonschema:"raw attribute values as sent by control"`
	Connect     string         `json:"connect,omitempty" jsonschema:"suggested client command for this action type, built from the service address and port; connect without credentials"`
}

const credentialsNote = "Connecting: use the address and port above. Tailscale PAM injects the real credentials at its connector, " +
	"so connect without a username or password; if a client insists on them, any placeholder works (for SSH, skip-username means the username is ignored). " +
	"Never hunt for, guess or brute-force real credentials; if a service still rejects you, stop and ask the user."

var notes = []string{
	credentialsNote,
	"These are the Services the control plane has made visible to this node (services/* node capabilities in the local netmap). Reaching a service is not permission for every port, action or operation on it; the PAM permissions in the policy grant still apply.",
	"The API has no field that marks a service as PAM/privileged-access-managed. Do not infer that from the name, type, or attributes.",
	"Only data present in the response is reported; missing display names, actions, or attributes were not set by control.",
}

func registerTools(s *mcp.Server, d *discoverer) {
	mcp.AddTool(s, &mcp.Tool{
		Name:  "list_services",
		Title: "List Tailscale Services",
		Description: "Use this first whenever you need to connect to infrastructure over Tailscale: SSH hosts, databases " +
			"(MySQL, PostgreSQL, MongoDB, MS SQL, CockroachDB, Elasticsearch), Kubernetes, RDP, VNC, HTTP, TCP or AWS S3. " +
			"Lists the Tailscale Services visible to this machine's Tailscale node, " +
			"as reported by the local tailscaled. Returns each service's name, display name, " +
			"VIP addresses, ports, any connection hints (actions/attributes) the control plane provided, a suggested client command per action, " +
			"and which approved jitd access request (if any) made it visible and until when. " +
			"Tailscale PAM injects credentials: connect without a username or password (any placeholder if a client insists); never hunt for real credentials. " +
			"If what you need is not listed, use list_requestable and request_access. " +
			"Read-only; does not connect to any service.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:   true,
			IdempotentHint: true,
			OpenWorldHint:  new(false),
		},
	}, d.listServices)
}

func (d *discoverer) listServices(ctx context.Context, _ *mcp.CallToolRequest, _ listServicesInput) (*mcp.CallToolResult, listServicesOutput, error) {
	out, err := d.discover(ctx)
	if err != nil {
		d.log.Warn("list_services failed", "err", err)
		return nil, listServicesOutput{}, err
	}
	d.log.Info("list_services ok", "count", out.ServiceCount)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: summarize(out)}},
	}, out, nil
}

func (d *discoverer) discover(ctx context.Context) (listServicesOutput, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	st, err := d.src.StatusWithoutPeers(ctx)
	if err != nil {
		return listServicesOutput{}, classify(err, d.timeout)
	}
	if st.BackendState != "Running" {
		return listServicesOutput{}, fmt.Errorf("tailscale_not_running: tailscaled is reachable but its state is %q, not \"Running\"; "+
			"run `tailscale up` (or log in) and try again", st.BackendState)
	}
	if major, minor, ok := parseVersion(st.Version); ok && !versionAtLeast(major, minor) {
		return listServicesOutput{}, unsupported(st.Version)
	}

	raw, err := d.src.GetServices(ctx)
	if err != nil {
		if strings.HasPrefix(err.Error(), "404 ") {
			return listServicesOutput{}, unsupported(st.Version)
		}
		return listServicesOutput{}, classify(err, d.timeout)
	}

	out := listServicesOutput{
		Source:        apiSource,
		DaemonVersion: st.Version,
		Services:      convert(raw, magicDNSSuffix(st)),
		Notes:         notes,
	}
	out.ServiceCount = len(out.Services)
	if st.Self != nil {
		out.Node.HostName = st.Self.HostName
		out.Node.DNSName = strings.TrimSuffix(st.Self.DNSName, ".")
	}
	if st.CurrentTailnet != nil {
		out.Node.Tailnet = st.CurrentTailnet.Name
	}
	if d.jit != nil && st.Self != nil && len(out.Services) > 0 {
		if err := d.annotateGrants(ctx, string(st.Self.ID), out.Services); err != nil {
			d.log.Warn("could not ask jitd which approvals granted these services", "err", err)
			out.Notes = append(slices.Clone(out.Notes), "Could not ask jitd which approved requests granted these services: "+err.Error())
		}
	}
	return out, nil
}

// annotateGrants sets Access on services covered by an approved, unexpired
// jitd request targeting this node. The latest expiry wins.
func (d *discoverer) annotateGrants(ctx context.Context, selfID string, svcs []service) error {
	var resp struct {
		Requests []accessRequest `json:"requests"`
	}
	if err := d.jit.do(ctx, http.MethodGet, "/v1/requests?scope=mine&status=approved", nil, &resp); err != nil {
		return err
	}
	now := time.Now()
	for i := range svcs {
		var latest time.Time
		for _, r := range resp.Requests {
			exp, err := time.Parse(time.RFC3339Nano, r.ExpiresAt)
			if r.TargetDeviceID != selfID || err != nil || !exp.After(now) || !slices.Contains(r.services(), svcs[i].Name) {
				continue
			}
			if exp.After(latest) {
				latest = exp
				desc := ""
				if idx := slices.IndexFunc(r.Resources, func(x resource) bool { return x.Name == svcs[i].Name }); idx >= 0 {
					if d := r.Resources[idx].Description; d != "" {
						desc = quoted(d) // written by an admin: data, not instructions
					}
				}
				svcs[i].Access = &jitAccess{RequestID: r.ID, WorkflowName: oneLine(r.WorkflowName), Attribute: r.Attribute,
					Description: desc, ExpiresAt: r.ExpiresAt, URL: r.URL}
			}
		}
	}
	return nil
}

func unsupported(v string) error {
	return fmt.Errorf("unsupported_daemon_version: tailscaled %s does not provide the services LocalAPI (requires >= %d.%d); upgrade Tailscale",
		v, minDaemonVersion[0], minDaemonVersion[1])
}

// classify turns LocalAPI client errors into short, actionable messages.
func classify(err error, timeout time.Duration) error {
	var opErr *net.OpError
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("timeout: no response from tailscaled within %s (it may be hung, or not running and the client retried the socket during startup): %w", timeout, err)
	case local.IsAccessDeniedError(err), errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("permission_denied: not allowed to read from tailscaled's LocalAPI as this user: %w", err)
	case errors.As(err, &opErr) && opErr.Op == "dial":
		return fmt.Errorf("daemon_unavailable: could not connect to tailscaled; is Tailscale installed and running? %w", err)
	case strings.HasPrefix(err.Error(), "503 "):
		return fmt.Errorf("not_ready: tailscaled has no network map yet (still starting or not logged in): %w", err)
	}
	return fmt.Errorf("tailscaled_error: %w", err)
}

// magicDNSSuffix is the tailnet's MagicDNS suffix, or "" if unknown.
func magicDNSSuffix(st *ipnstate.Status) string {
	if st.CurrentTailnet == nil {
		return ""
	}
	return strings.Trim(st.CurrentTailnet.MagicDNSSuffix, ".")
}

// convert builds the sorted output. suffix is the tailnet's MagicDNS suffix;
// hostnames are "<name>.<suffix>", as 'tailscale service list' shows them.
func convert(raw map[tailcfg.ServiceName]tailcfg.ServiceDetails, suffix string) []service {
	out := make([]service, 0, len(raw))
	for key, sd := range raw {
		name := string(sd.Name)
		if name == "" {
			name = string(key)
		}
		s := service{Name: name, DisplayName: sd.DisplayName, Addresses: []string{}, Ports: []port{}}
		if bare := tailcfg.ServiceName(name).WithoutPrefix(); bare != "" && suffix != "" {
			s.Hostname = bare + "." + suffix
		}

		addrs := slices.Clone(sd.Addrs)
		slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
		for _, a := range addrs {
			s.Addresses = append(s.Addresses, a.String())
		}

		ports := slices.Clone(sd.Ports)
		slices.SortFunc(ports, func(a, b tailcfg.ProtoPortRange) int {
			return cmp.Or(cmp.Compare(a.Proto, b.Proto), cmp.Compare(a.Ports.First, b.Ports.First), cmp.Compare(a.Ports.Last, b.Ports.Last))
		})
		for _, p := range ports {
			proto := "any"
			if p.Proto != 0 {
				b, _ := ipproto.Proto(p.Proto).MarshalText()
				proto = string(b)
			}
			s.Ports = append(s.Ports, port{Protocol: proto, Ports: p.Ports.String()})
		}

		for _, a := range sd.Actions {
			act := action{Type: string(a.Type), KnownType: a.Type.Valid(), Port: a.Port, DisplayName: a.DisplayName}
			for k, v := range a.Attributes {
				if act.Attributes == nil {
					act.Attributes = map[string]any{}
				}
				var decoded any
				if err := json.Unmarshal([]byte(v), &decoded); err != nil {
					decoded = string(v) // keep malformed values verbatim rather than dropping them
				}
				act.Attributes[string(k)] = decoded
			}
			if len(s.Addresses) > 0 {
				act.Connect = connectHint(act, s.Addresses[0], s.Hostname)
			}
			s.Actions = append(s.Actions, act)
		}
		slices.SortFunc(s.Actions, func(a, b action) int {
			return cmp.Or(cmp.Compare(a.Port, b.Port), cmp.Compare(a.Type, b.Type), cmp.Compare(a.DisplayName, b.DisplayName))
		})

		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b service) int { return cmp.Compare(a.Name, b.Name) })
	return out
}

// kubeHint is how to reach a Kubernetes API server exposed as a Tailscale
// Service: a one-off kubectl call, or a kubeconfig context from the
// tailscale CLI. PAM supplies the identity, so no credentials are needed
// (the CLI writes the placeholder token "unused"). Plain HTTP needs --http,
// and flags must come before the name.
func kubeHint(port uint16, host string) string {
	scheme := "http"
	if port == 443 {
		scheme = "https"
	}
	server := scheme + "://" + host
	if port != 80 && port != 443 {
		server += ":" + strconv.Itoa(int(port))
	}
	var cfg string
	switch port {
	case 80:
		cfg = "tailscale configure kubeconfig --http " + host
	case 443:
		cfg = "tailscale configure kubeconfig " + host
	default:
		cfg = "tailscale configure kubeconfig " + server
	}
	return "KUBECONFIG=/dev/null kubectl --server " + server + " get namespaces   (no credentials; /dev/null keeps the user's kubeconfig and its credentials out of it), " +
		"or for a kubectl context: " + cfg + "   (adds a context named after the host and makes it current; tell the user)"
}

// connectHint suggests a client command for an action, using only the
// service address and the action's type and port. Credentials are omitted or
// placeholders: Tailscale PAM injects the real ones. Unknown types get none.
func connectHint(a action, addr, hostname string) string {
	p := strconv.Itoa(int(a.Port))
	hp := addr + ":" + p
	switch a.Type {
	case "mysql":
		return "mysql -h " + addr + " -P " + p + "   (no -u/-p)"
	case "postgresql", "cockroach":
		return "psql -h " + addr + " -p " + p + "   (no password)"
	case "mongodb":
		return "mongosh mongodb://" + hp + "/"
	case "mssql":
		return "sqlcmd -S " + addr + "," + p + " -U any -P any   (placeholders; the connector injects the real login)"
	case "ssh":
		if a.Port == 22 {
			return "ssh " + addr
		}
		return "ssh -p " + p + " " + addr
	case "elasticsearch", "http":
		return "curl http://" + hp + "/"
	case "kubernetes":
		return kubeHint(a.Port, cmp.Or(hostname, addr))
	case "rdp":
		return "RDP client to " + hp + ", or the web-client-url"
	case "vnc":
		return "VNC client to " + hp
	case "aws-s3":
		return "aws s3 ls --endpoint-url http://" + hp + "   (any placeholder AWS keys)"
	case "tcp":
		return "TCP to " + hp
	}
	return ""
}

func summarize(o listServicesOutput) string {
	var b strings.Builder
	node := cmp.Or(o.Node.DNSName, o.Node.HostName, "this node")
	if o.ServiceCount == 0 {
		fmt.Fprintf(&b, "No Tailscale Services are visible to %s (tailscaled %s). "+
			"The daemon answered successfully with an empty list: none are granted to this node, or none are defined in the tailnet.\n", node, o.DaemonVersion)
	} else {
		fmt.Fprintf(&b, "%d Tailscale Service(s) visible to %s (tailscaled %s):\n", o.ServiceCount, node, o.DaemonVersion)
	}
	for _, s := range o.Services {
		fmt.Fprintf(&b, "\n- %s", s.Name)
		if s.DisplayName != "" {
			fmt.Fprintf(&b, " (%q)", s.DisplayName)
		}
		b.WriteString("\n")
		if s.Hostname != "" {
			fmt.Fprintf(&b, "  hostname: %s\n", s.Hostname)
		}
		fmt.Fprintf(&b, "  addresses: %s\n", joinOrNone(s.Addresses))
		ps := make([]string, len(s.Ports))
		for i, p := range s.Ports {
			ps[i] = p.Protocol + ":" + p.Ports
		}
		fmt.Fprintf(&b, "  ports: %s\n", joinOrNone(ps))
		for _, a := range s.Actions {
			fmt.Fprintf(&b, "  action: %s on tcp:%s", a.Type, strconv.Itoa(int(a.Port)))
			if a.DisplayName != "" {
				fmt.Fprintf(&b, " (%q)", a.DisplayName)
			}
			if len(a.Attributes) > 0 {
				var attrs strings.Builder
				enc := json.NewEncoder(&attrs)
				enc.SetEscapeHTML(false) // keep '&' in URLs readable
				enc.Encode(a.Attributes)
				fmt.Fprintf(&b, " attributes=%s", strings.TrimSpace(attrs.String()))
			}
			b.WriteString("\n")
			if a.Connect != "" {
				fmt.Fprintf(&b, "  connect: %s\n", a.Connect)
			}
		}
		if g := s.Access; g != nil {
			fmt.Fprintf(&b, "  access: approved request %s via %q until %s\n", g.RequestID, g.WorkflowName, g.ExpiresAt)
		}
	}
	b.WriteString("\nNotes:\n")
	for _, n := range o.Notes {
		fmt.Fprintf(&b, "- %s\n", n)
	}
	return b.String()
}

func joinOrNone(s []string) string {
	if len(s) == 0 {
		return "(none reported)"
	}
	return strings.Join(s, ", ")
}

// parseVersion extracts major.minor from versions like "1.102.2-t6cac91817-g6ff0ddc72".
func parseVersion(v string) (major, minor int, ok bool) {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(strings.SplitN(parts[1], "-", 2)[0])
	return major, minor, err1 == nil && err2 == nil
}

func versionAtLeast(major, minor int) bool {
	return major > minDaemonVersion[0] || (major == minDaemonVersion[0] && minor >= minDaemonVersion[1])
}

package slackbot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
	"github.com/atoonk/tailscale-jit/jitd/internal/slack"
)

// Action IDs on the request message's buttons.
const (
	actionApprove = "jit_approve"
	actionDecline = "jit_decline"
	actionOpen    = "jit_open"
	// actionRequestForm is the Request button in /jit's command list.
	actionRequestForm = "jit_request_form"
	declineView       = "jit_decline"
	reasonBlock       = "reason"
	reasonInput       = "reason"
)

// renderInput is what a request message is made of.
type renderInput struct {
	R       *jit.AccessRequest
	W       *jit.Workflow // nil if the flow is gone
	URL     string        // the request's page
	Mention string        // the requester's Slack user ID, if known
	Counted int           // valid votes so far
	Buttons bool          // Approve and Decline, for a pending request
}

// render builds the Slack message for a request. It is the same in the
// channel and in direct messages, and it is rebuilt from the request every
// time, so it always shows where the request is now.
func render(in renderInput) slack.Message {
	r := in.R
	who := esc(r.Requester.Actor())
	if r.Requester.DisplayName != "" && !r.Requester.Tagged() {
		who = esc(r.Requester.DisplayName) + " (" + esc(r.Requester.Login) + ")"
	}
	if in.Mention != "" {
		who += " <@" + in.Mention + ">"
	}
	device := r.Requester.DeviceName
	if device == "" {
		device = r.TargetDeviceID
	}

	var blocks []slack.Block
	blocks = append(blocks, slack.Section(slack.Mrkdwn(fmt.Sprintf("%s *Access request · <%s|%s>*\n%s asks for *%s* of access from `%s`.",
		statusEmoji(r), in.URL, esc(r.WorkflowName), who, r.Duration.Human(), esc(device)))))
	blocks = append(blocks, slack.Section(slack.Mrkdwn(quote(r.Reason))))

	var fields []slack.Text
	if len(r.Resources) > 0 {
		var names []string
		for _, res := range r.Resources {
			names = append(names, "`"+esc(res.Name)+"`")
		}
		fields = append(fields, slack.Mrkdwn("*Gives access to*\n"+strings.Join(names, ", ")))
	}
	fields = append(fields, slack.Mrkdwn("*Status*\n"+statusLine(r, in.Counted)))
	blocks = append(blocks, slack.Fields(fields...))

	ctx := []slack.Text{slack.Mrkdwn(fmt.Sprintf("`%s` · requested %s", r.ID, slackTime(r.CreatedAt)))}
	if r.Status == jit.StatusPending && in.W != nil && in.W.Slack != nil && in.W.Slack.BrowserOnly {
		ctx = append(ctx, slack.Mrkdwn("This flow is approved in the browser only."))
	}
	blocks = append(blocks, slack.Context(ctx...))

	open := slack.LinkButton(actionOpen, "Open", in.URL)
	if in.Buttons && r.Status == jit.StatusPending {
		blocks = append(blocks, slack.Actions("jit_actions",
			slack.Button(actionApprove, "Approve", r.ID, "primary"),
			slack.Button(actionDecline, "Decline", r.ID, "danger"),
			open))
	} else {
		blocks = append(blocks, slack.Actions("jit_actions", open))
	}
	return slack.Message{
		Text:   fmt.Sprintf("Access request from %s: %s (%s)", r.Requester.Actor(), r.WorkflowName, r.Status),
		Blocks: blocks,
	}
}

// buttonsFor says whether a request's message gets Approve and Decline.
func buttonsFor(w *jit.Workflow) bool {
	return w != nil && !w.Disabled && (w.Slack == nil || !w.Slack.BrowserOnly)
}

func statusEmoji(r *jit.AccessRequest) string {
	switch r.Status {
	case jit.StatusPending:
		return ":hourglass_flowing_sand:"
	case jit.StatusApproved:
		return ":white_check_mark:"
	case jit.StatusDeclined:
		return ":x:"
	case jit.StatusRevoked:
		return ":no_entry:"
	default:
		return ":black_circle_for_record:"
	}
}

// statusLine says where the request is, who decided and when.
func statusLine(r *jit.AccessRequest, counted int) string {
	by := func(types ...string) string {
		for i := len(r.Timeline) - 1; i >= 0; i-- {
			e := r.Timeline[i]
			for _, t := range types {
				if e.Type == t {
					s := "*" + esc(e.Actor) + "*"
					if e.Via == jit.ViaSlack {
						s += " via Slack"
					}
					return s
				}
			}
		}
		return ""
	}
	note := func(t string) string {
		for i := len(r.Timeline) - 1; i >= 0; i-- {
			if r.Timeline[i].Type == t && r.Timeline[i].Note != "" {
				return r.Timeline[i].Note
			}
		}
		return ""
	}
	switch r.Status {
	case jit.StatusPending:
		s := "Waiting for approval"
		if r.ApprovalsRequired > 1 {
			s += fmt.Sprintf(" (%d of %d)", counted, r.ApprovalsRequired)
		}
		if r.LastError != "" {
			s += "\n:warning: the last approval failed: " + esc(r.LastError)
		}
		return s
	case jit.StatusApproved:
		s := "Approved by " + by("approved")
		if r.ExpiresAt != nil {
			s += ", until " + slackTime(*r.ExpiresAt)
		}
		if r.Enforcement.ConfirmedAt != nil {
			s += "\nConfirmed on the device"
		} else {
			s += "\nNot yet confirmed on the device"
		}
		return s
	case jit.StatusDeclined:
		s := "Declined by " + by("declined")
		if n := note("declined"); n != "" {
			s += ": " + esc(n)
		}
		return s
	case jit.StatusCancelled:
		return "Withdrawn by the requester"
	case jit.StatusRevoked:
		s := "Ended early by " + by("revoked")
		if r.Enforcement.RemovedAt != nil {
			s += "\nAccess confirmed gone from the device"
		}
		return s
	case jit.StatusExpired:
		if len(r.Attributes) == 0 {
			return "Expired without a decision"
		}
		s := "Access ended"
		if r.ExpiresAt != nil {
			s += " " + slackTime(*r.ExpiresAt)
		}
		if r.Enforcement.RemovedAt != nil {
			s += "\nAccess confirmed gone from the device"
		}
		return s
	}
	return string(r.Status)
}

// slackTime shows t in the reader's own time zone, with a UTC fallback.
func slackTime(t time.Time) string {
	return fmt.Sprintf("<!date^%d^{date_short_pretty} {time}|%s>", t.Unix(), t.UTC().Format("2006-01-02 15:04 UTC"))
}

// esc escapes text for Slack's mrkdwn: &, < and > are its control
// characters (links, mentions). It also keeps people from pinging @here.
func esc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// quote renders a reason as a block quote, one "> " per line.
func quote(s string) string {
	lines := strings.Split(esc(s), "\n")
	for i, l := range lines {
		lines[i] = "> " + l
	}
	out := strings.Join(lines, "\n")
	if len(out) > 2900 { // a section's text is capped at 3000
		out = out[:2900] + "…"
	}
	return out
}

// digest is a short hash of a message, to skip updates that change nothing.
func digest(m slack.Message) string {
	b, _ := json.Marshal(m)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

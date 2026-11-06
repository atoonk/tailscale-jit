package slackbot

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
	"github.com/atoonk/tailscale-jit/jitd/internal/slack"
)

// handle serves one Socket Mode envelope (see slack.Handler).
func (b *Bot) handle(ctx context.Context, env slack.Envelope) any {
	api := b.client()
	if api == nil {
		return nil
	}
	switch env.Type {
	case "interactive":
		var in slack.Interaction
		if err := json.Unmarshal(env.Payload, &in); err != nil {
			b.log().Warn("slack: bad interaction", "err", err)
			return nil
		}
		switch in.Type {
		case "block_actions":
			b.onAction(ctx, api, &in)
		case "view_submission":
			return b.onSubmit(ctx, api, &in)
		}
	case "slash_commands":
		var cmd slack.SlashCommand
		if err := json.Unmarshal(env.Payload, &cmd); err != nil {
			return nil
		}
		word, _, _ := strings.Cut(strings.TrimSpace(cmd.Text), " ")
		switch strings.ToLower(word) {
		case "request":
			if m, ok := b.openRequestForm(ctx, api, cmd.TriggerID, cmd.UserID); !ok {
				return slack.Ephemeral(m)
			}
			return nil // the form is open; nothing to say in the channel
		case "help":
			return slack.Ephemeral(slack.Message{Text: "JIT access commands", Blocks: b.commandList()})
		case "", "status":
			// Answering takes a Slack and maybe a Tailscale call and the
			// service's data: do it after the ack, through response_url,
			// so the socket's reader is not held up.
			go func() {
				ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), slowCall)
				defer cancel()
				m := b.onCommand(ctx, api, &cmd)
				<-slack.Acked(ctx)
				if err := api.Respond(ctx, cmd.ResponseURL, m); err != nil {
					b.log().Warn("slack: answering /jit", "err", err)
				}
			}()
			return nil
		}
		blocks := append([]slack.Block{slack.Section(slack.Mrkdwn(fmt.Sprintf("`/jit %s` isn't a JIT access command. These are:", esc(word))))}, b.commandList()...)
		return slack.Ephemeral(slack.Message{Text: "JIT access commands", Blocks: blocks})
	}
	return nil
}

// onAction handles a button click on a request message.
func (b *Bot) onAction(ctx context.Context, api slack.API, in *slack.Interaction) {
	if len(in.Actions) == 0 {
		return
	}
	a := in.Actions[0]
	if a.ActionID == actionRequestForm {
		if m, ok := b.openRequestForm(ctx, api, in.TriggerID, in.User.ID); !ok {
			b.reply(ctx, api, in, m)
		}
		return
	}
	if a.ActionID != actionApprove && a.ActionID != actionDecline {
		return // Open is a link; Slack still reports the click
	}
	channel := in.Container.ChannelID
	if channel == "" {
		channel = in.Channel.ID
	}
	say := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		if err := api.PostEphemeral(ctx, channel, in.User.ID, slack.Message{Text: msg, Blocks: []slack.Block{slack.Section(slack.Mrkdwn(msg))}}); err != nil {
			b.log().Warn("slack: ephemeral reply", "err", err)
		}
	}
	reqID := a.Value
	link := b.requestLink(reqID)
	if a.ActionID == actionDecline {
		// The form has to open within three seconds of the click; checking
		// who the clicker is can take longer, so open it first.
		viewID, err := api.OpenView(ctx, in.TriggerID, notice("Decline request", ":hourglass_flowing_sand: Checking…"))
		if err != nil {
			b.log().Warn("slack: opening the decline form", "err", err)
			say("Couldn't open the decline form (%s). Decline in the browser: %s", esc(err.Error()), link)
			return
		}
		v := b.declineForm(ctx, api, in.User.ID, reqID)
		if err := api.UpdateView(ctx, viewID, v); err != nil {
			b.log().Warn("slack: filling the decline form", "err", err)
		}
		return
	}
	id, err := b.resolve(ctx, api, in.User.ID)
	if err != nil {
		say(":no_entry: You can't act on this request from Slack: %s. You can still decide in the browser: %s", esc(err.Error()), link)
		return
	}
	r, err := b.Svc.GetRequest(ctx, id, reqID)
	if err != nil {
		say(":no_entry: You can't act on this request: Slack matched you to *%s*, who isn't an approver for it.", esc(id.Login))
		return
	}
	w, err := b.Svc.GetWorkflow(r.WorkflowID)
	if err == nil && !buttonsFor(w) {
		say("This approval flow is decided in the browser only: %s", link)
		b.RequestChanged(r, jit.Event{}) // the buttons should not be there; redraw
		return
	}
	if _, err := b.Svc.Approve(ctx, id, reqID, ""); err != nil {
		say(":no_entry: Couldn't approve: %s (Slack matched you to *%s*.)", esc(jit.AsError(err).Message), esc(id.Login))
		return
	}
	// The message updates itself through the notifier.
	b.log().Info("slack: approved", "id", reqID, "login", id.Login, "slack_user", id.SlackUser)
}

// declineForm is the decline form for reqID, or a notice saying why userID
// can't decline it.
func (b *Bot) declineForm(ctx context.Context, api slack.API, userID, reqID string) slack.View {
	link := b.requestLink(reqID)
	title := "Decline request"
	id, err := b.resolve(ctx, api, userID)
	if err != nil {
		return notice(title, fmt.Sprintf(":no_entry: You can't act on this request from Slack: %s. You can still decide in the browser: %s", esc(err.Error()), link))
	}
	r, err := b.Svc.GetRequest(ctx, id, reqID)
	if err != nil {
		return notice(title, fmt.Sprintf(":no_entry: You can't act on this request: Slack matched you to *%s*, who isn't an approver for it.", esc(id.Login)))
	}
	if w, err := b.Svc.GetWorkflow(r.WorkflowID); err == nil && !buttonsFor(w) {
		return notice(title, "This approval flow is decided in the browser only: "+link)
	}
	if can := b.Svc.Permissions(ctx, id, r); !can.Decline {
		why := "you can't decline it"
		if r.Status != jit.StatusPending {
			why = "it is " + string(r.Status)
		} else if strings.EqualFold(r.Requester.Login, id.Login) {
			why = "it is your own request; withdraw it in the browser instead"
		}
		return notice(title, ":no_entry: Couldn't decline: "+why+".")
	}
	return slack.View{
		Type: "modal", CallbackID: declineView, PrivateMetadata: reqID,
		Title: slack.Plain(title), Submit: slack.Plain("Decline"), Close: slack.Plain("Cancel"),
		Blocks: []slack.Block{
			slack.Section(slack.Mrkdwn(fmt.Sprintf("*%s* for %s, %s:\n%s", esc(r.WorkflowName), esc(r.Requester.Actor()), r.Duration.Human(), quote(r.Reason)))),
			slack.Input(reasonBlock, reasonInput, "Why are you declining?", "The requester sees this", true),
		},
	}
}

// onSubmit handles the decline and request forms. Its return value is the
// ack: errors keep the form open, an update replaces it. It runs before the
// ack, inside the socket's reader, so only quick checks happen here; the
// decision itself runs after the ack and then shows its outcome in the form.
func (b *Bot) onSubmit(ctx context.Context, api slack.API, in *slack.Interaction) any {
	if in.View.CallbackID == requestView {
		return b.onRequestSubmit(ctx, api, in)
	}
	if in.View.CallbackID != declineView {
		return nil
	}
	reason := strings.TrimSpace(in.InputValue(reasonBlock, reasonInput))
	if reason == "" {
		return slack.ViewErrors(map[string]string{reasonBlock: "A reason is required to decline."})
	}
	reqID, viewID, userID := in.View.PrivateMetadata, in.View.ID, in.User.ID
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), slowCall)
		defer cancel()
		v := b.decline(ctx, api, userID, reqID, reason)
		<-slack.Acked(ctx)
		if err := api.UpdateView(ctx, viewID, v); err != nil {
			b.log().Warn("slack: showing the decline outcome", "err", err)
		}
	}()
	return slack.UpdateView(notice("Decline request", ":hourglass_flowing_sand: Declining…"))
}

// decline declines reqID for the Slack user and says how it went.
func (b *Bot) decline(ctx context.Context, api slack.API, userID, reqID, reason string) slack.View {
	id, err := b.resolve(ctx, api, userID)
	if err != nil {
		return notice("Not declined", ":no_entry: "+esc(err.Error())+".")
	}
	r, err := b.Svc.Decline(ctx, id, reqID, reason)
	if err != nil {
		return notice("Not declined", fmt.Sprintf(":no_entry: %s.\n<%s|Open the request>", esc(jit.AsError(err).Message), b.requestLink(reqID)))
	}
	b.log().Info("slack: declined", "id", reqID, "login", id.Login, "slack_user", id.SlackUser)
	return notice("Declined", fmt.Sprintf(":x: You declined *%s* for %s.", esc(r.WorkflowName), esc(r.Requester.Actor())))
}

// onCommand answers /jit: what is waiting for the caller and where their
// own requests are.
func (b *Bot) onCommand(ctx context.Context, api slack.API, cmd *slack.SlashCommand) slack.Message {
	base := strings.TrimSuffix(b.BaseURL, "/")
	id, err := b.resolve(ctx, api, cmd.UserID)
	if err != nil {
		var ie *IdentityError
		if !errors.As(err, &ie) {
			err = errors.New("Slack could not be asked who you are; try again")
		}
		return text(fmt.Sprintf("JIT access can't tell who you are: %s.\nOpen <%s|JIT access> on a device on the tailnet instead.", esc(err.Error()), base))
	}
	now := b.now()
	waiting := b.Svc.ListRequests(ctx, jit.ListFilter{Viewer: id, Scope: jit.ScopeApprovals, Status: jit.StatusPending})
	var mine []*jit.AccessRequest
	for _, r := range b.Svc.ListRequests(ctx, jit.ListFilter{Viewer: id, Scope: jit.ScopeMine}) {
		if r.Status == jit.StatusPending || (r.Status == jit.StatusApproved && r.ExpiresAt != nil && r.ExpiresAt.After(now)) {
			mine = append(mine, r)
		}
	}
	blocks := []slack.Block{
		slack.Header("JIT access"),
		slack.Context(slack.Mrkdwn(fmt.Sprintf("You are *%s* (from your Slack email). <%s|Open JIT access> on the tailnet.", esc(id.Login), base))),
		slack.Section(slack.Mrkdwn(fmt.Sprintf("*:inbox_tray: Waiting for your approval (%d)*", len(waiting)))),
	}
	if len(waiting) == 0 {
		blocks = append(blocks, slack.Context(slack.Mrkdwn("Nothing right now.")))
	}
	for i, r := range waiting {
		if i == 8 {
			blocks = append(blocks, slack.Context(slack.Mrkdwn(fmt.Sprintf("…and %d more: <%s/requests?scope=approvals&status=pending|see all>", len(waiting)-8, base))))
			break
		}
		blocks = append(blocks, slack.SectionButton(slack.Mrkdwn(fmt.Sprintf("*%s* · %s for %s, on `%s`\n> %s",
			esc(r.WorkflowName), esc(r.Requester.Actor()), r.Duration.Human(), esc(r.Requester.DeviceName), esc(oneLine(r.Reason, 120)))),
			slack.LinkButton(actionOpen+"_"+r.ID, "Review", b.requestLink(r.ID))))
	}
	blocks = append(blocks, slack.Section(slack.Mrkdwn(fmt.Sprintf("*:key: Your requests (%d)*", len(mine)))))
	if len(mine) == 0 {
		blocks = append(blocks, slack.Context(slack.Mrkdwn("No pending or active requests.")))
	}
	for i, r := range mine {
		if i == 8 {
			blocks = append(blocks, slack.Context(slack.Mrkdwn(fmt.Sprintf("…and %d more: <%s/requests|see all>", len(mine)-8, base))))
			break
		}
		state := ":hourglass_flowing_sand: waiting for approval"
		if r.Status == jit.StatusApproved {
			state = ":white_check_mark: active until " + slackTime(*r.ExpiresAt)
		}
		blocks = append(blocks, slack.SectionButton(slack.Mrkdwn(fmt.Sprintf("*%s* on `%s`\n%s", esc(r.WorkflowName), esc(r.Requester.DeviceName), state)),
			slack.LinkButton(actionOpen+"_"+r.ID, "Open", b.requestLink(r.ID))))
	}
	blocks = append(blocks, b.commandList()...)
	return slack.Message{Text: fmt.Sprintf("JIT access: %d waiting for your approval, %d of your own requests", len(waiting), len(mine)), Blocks: blocks}
}

// commandList lists what /jit understands, with a button for each action.
func (b *Bot) commandList() []slack.Block {
	return []slack.Block{
		slack.Divider(),
		slack.Section(slack.Mrkdwn("*Commands*")),
		slack.SectionButton(slack.Mrkdwn("• `/jit request`: ask for access for one of your devices"), slack.Button(actionRequestForm, "Request", "", "")),
		slack.Section(slack.Mrkdwn("• `/jit`: what is waiting for your approval, and your own requests")),
		slack.Section(slack.Mrkdwn("• `/jit help`: this list")),
	}
}

// reply answers an interaction with a message only the clicker sees.
func (b *Bot) reply(ctx context.Context, api slack.API, in *slack.Interaction, m slack.Message) {
	channel := cmp.Or(in.Container.ChannelID, in.Channel.ID)
	if err := api.PostEphemeral(ctx, channel, in.User.ID, m); err != nil {
		b.log().Warn("slack: ephemeral reply", "err", err)
	}
}

func text(s string) slack.Message {
	return slack.Message{Text: s, Blocks: []slack.Block{slack.Section(slack.Mrkdwn(s))}}
}

func (b *Bot) requestLink(id string) string {
	return strings.TrimSuffix(b.BaseURL, "/") + "/requests/" + id
}

func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// ---- checks for the admin page ----

// ApproverCheck is whether one approver can act from Slack.
type ApproverCheck struct {
	Login     string `json:"login"`
	SlackUser string `json:"slack_user,omitempty"` // their Slack handle, if found
	Problem   string `json:"problem,omitempty"`
}

// FlowCheck is a flow's Slack setup as Slack sees it.
type FlowCheck struct {
	WorkflowID   string          `json:"workflow_id"`
	WorkflowName string          `json:"workflow_name"`
	Channel      string          `json:"channel,omitempty"`
	ChannelName  string          `json:"channel_name,omitempty"`
	ChannelIssue string          `json:"channel_issue,omitempty"`
	DMApprovers  bool            `json:"dm_approvers"`
	BrowserOnly  bool            `json:"browser_only"`
	Approvers    []ApproverCheck `json:"approvers"`
	// ApproverIssue says why the list of approvers may be incomplete
	// (group: approvers whose members could not be read).
	ApproverIssue string `json:"approver_issue,omitempty"`
	// Members is set when autogroup:member approves: any tailnet member,
	// from Slack too if their Slack email is their Tailscale login.
	Members bool `json:"members,omitempty"`
	// OtherApprovers are tag: approvers: devices, which decide in the
	// browser or through the API only.
	OtherApprovers []string `json:"other_approvers,omitempty"`
}

// Check looks at every flow: can the bot post to its channel, and which of
// its approvers Slack can match to their Tailscale login.
func (b *Bot) Check(ctx context.Context) ([]FlowCheck, error) {
	api := b.client()
	if api == nil {
		return nil, errNotConnected
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// Slack users must own a device on the tailnet (see resolve); one device
	// list serves every approver.
	owners, err := b.Svc.DeviceOwners(ctx)
	if err != nil {
		b.log().Warn("slack: checking approvers' devices", "err", err)
	}
	var out []FlowCheck
	for _, w := range b.Svc.ListWorkflows() {
		fc := FlowCheck{WorkflowID: w.ID, WorkflowName: w.Name, Approvers: []ApproverCheck{}}
		if w.Slack != nil {
			fc.Channel, fc.ChannelName, fc.DMApprovers, fc.BrowserOnly = w.Slack.Channel, w.Slack.ChannelName, w.Slack.DMApprovers, w.Slack.BrowserOnly
		}
		if fc.Channel != "" {
			c, err := api.ChannelInfo(ctx, fc.Channel)
			switch {
			case err != nil:
				fc.ChannelIssue = explainPostError(err)
			case c.IsArchived:
				fc.ChannelIssue = "the channel is archived"
			case c.IsPrivate && !c.IsMember:
				fc.ChannelIssue = "the bot is not in this private channel: /invite @" + AppName
			default:
				fc.ChannelName = c.Name
			}
		}
		for _, p := range w.Approvers {
			switch {
			case p == jit.AutogroupMember:
				fc.Members = true
			case !p.IsLogin() && !strings.HasPrefix(string(p), "group:"):
				fc.OtherApprovers = append(fc.OtherApprovers, string(p))
			}
		}
		logins, err := b.Svc.ApproverLogins(ctx, w)
		if err != nil {
			fc.ApproverIssue = err.Error()
		}
		for _, login := range logins {
			ac := ApproverCheck{Login: login}
			u, err := b.slackUser(ctx, api, login)
			switch {
			case slack.ErrorCode(err) == "users_not_found":
				ac.Problem = "no Slack account with this email"
			case err != nil:
				ac.Problem = err.Error()
			default:
				ac.SlackUser = "@" + u.Name
				ac.Problem = b.userProblem(u)
				if ac.Problem == "" && owners != nil && !owners[login] {
					ac.Problem = "no device on the tailnet, so Slack can't act as this login"
				}
			}
			fc.Approvers = append(fc.Approvers, ac)
		}
		out = append(out, fc)
	}
	return out, nil
}

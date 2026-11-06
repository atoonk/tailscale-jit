package slackbot

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
	"github.com/atoonk/tailscale-jit/jitd/internal/slack"
	"github.com/atoonk/tailscale-jit/jitd/internal/tsapi"
)

// The request form (/jit request).
const (
	requestView   = "jit_request"
	flowBlock     = "flow"
	deviceBlock   = "device"
	durationBlock = "duration"
)

// durationChoices are the durations the form offers. A flow's maximum still
// applies; Submit rejects anything longer.
var durationChoices = []string{"15m", "30m", "1h", "2h", "4h", "8h", "1d"}

// slowCall bounds the Slack and Tailscale calls made after the form is
// open, when Slack's 3-second deadline no longer applies.
const slowCall = 20 * time.Second

// openRequestForm opens the request form for the caller. In a browser jitd
// knows the device from the connection; from Slack it does not, so the
// caller picks one of their own devices, as Tailscale lists them. Listing
// them can take longer than Slack allows before the command's trigger
// expires, so the form opens with a placeholder and fills in afterwards.
// ok is false when no form was opened, with m saying why.
func (b *Bot) openRequestForm(ctx context.Context, api slack.API, triggerID, userID string) (m slack.Message, ok bool) {
	viewID, err := api.OpenView(ctx, triggerID, notice("Request access", ":hourglass_flowing_sand: Loading your approval flows and devices…"))
	if err != nil {
		b.log().Warn("slack: opening the request form", "err", err)
		return text(fmt.Sprintf("Couldn't open the request form (%s). Request access on the device instead: <%s/requests/new|Request access>",
			esc(err.Error()), strings.TrimSuffix(b.BaseURL, "/"))), false
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), slowCall)
		defer cancel()
		v := b.requestForm(ctx, api, userID)
		if err := api.UpdateView(ctx, viewID, v); err != nil {
			b.log().Warn("slack: filling the request form", "err", err)
		}
	}()
	return slack.Message{}, true
}

// requestForm is the form for userID, or a notice saying why there is none.
func (b *Bot) requestForm(ctx context.Context, api slack.API, userID string) slack.View {
	base := strings.TrimSuffix(b.BaseURL, "/")
	id, err := b.resolve(ctx, api, userID)
	if err != nil {
		return notice("Request access", fmt.Sprintf("JIT access can't tell who you are: %s.", esc(err.Error())))
	}
	flows := b.Svc.Requestable(ctx, id)
	if len(flows) == 0 {
		return notice("Request access", fmt.Sprintf("There is no approval flow *%s* can request access through.", esc(id.Login)))
	}
	devices, err := b.Svc.UserDevices(ctx, id.Login)
	if err != nil {
		b.log().Warn("slack: listing devices", "login", id.Login, "err", err)
		return notice("Request access", fmt.Sprintf("Couldn't get your devices from Tailscale (%s).\nTry again, or request access on the device: <%s/requests/new|Request access>", esc(err.Error()), base))
	}
	if len(devices) == 0 {
		return notice("Request access", fmt.Sprintf("Tailscale has no devices for *%s*. Access is given to a device, so log in to Tailscale as %s on the device that needs it, then try again.", esc(id.Login), esc(id.Login)))
	}

	var flowOpts []slack.Text
	for _, f := range flows {
		flowOpts = append(flowOpts, slack.Option(fmt.Sprintf("%s (up to %s)", f.WorkflowName, f.MaxDuration.Human()), f.WorkflowID))
	}
	var devOpts []slack.Text
	for _, d := range devices {
		devOpts = append(devOpts, slack.Option(deviceLabel(d), d.NodeID))
	}
	var durOpts []slack.Text
	for _, d := range durationChoices {
		v, _ := jit.ParseDuration(d)
		durOpts = append(durOpts, slack.Option(jit.Duration(v).Human(), d))
	}
	var firstFlow slack.Text
	if len(flowOpts) == 1 {
		firstFlow = flowOpts[0]
	}
	return slack.View{
		Type: "modal", CallbackID: requestView,
		Title: slack.Plain("Request access"), Submit: slack.Plain("Request"), Close: slack.Plain("Cancel"),
		Blocks: []slack.Block{
			slack.Section(slack.Mrkdwn(fmt.Sprintf("Requesting as *%s*. Access is given to the device you pick, once an approver says yes.", esc(id.Login)))),
			slack.InputBlock(flowBlock, "Approval flow", slack.Select(flowBlock, "Pick a flow", flowOpts, firstFlow), false, ""),
			slack.InputBlock(deviceBlock, "Device", slack.Select(deviceBlock, "Pick a device", devOpts, devOpts[0]), false, "Your own devices, most recently seen first."),
			slack.InputBlock(durationBlock, "For how long", slack.Select(durationBlock, "The flow's default", durOpts, nil), true, "Leave empty for the flow's default. Each flow has a maximum."),
			slack.InputBlock(reasonBlock, "Reason", slack.TextInput(reasonInput, "What do you need it for?", true), false, "Approvers see this."),
		},
	}
}

// onRequestSubmit files the request from the form. What can be checked
// quickly is checked before the ack, so mistakes keep the form open. The
// rest (the device must still be the caller's own, untagged device, which
// takes a Tailscale call) runs after it, and the form then shows the
// outcome.
func (b *Bot) onRequestSubmit(ctx context.Context, api slack.API, in *slack.Interaction) any {
	reason := strings.TrimSpace(in.InputValue(reasonBlock, reasonInput))
	if reason == "" {
		return slack.ViewErrors(map[string]string{reasonBlock: "A reason is required."})
	}
	w, err := b.Svc.GetWorkflow(in.InputValue(flowBlock, flowBlock))
	if err != nil {
		return slack.ViewErrors(map[string]string{flowBlock: "That approval flow is gone. Pick another."})
	}
	var dur jit.Duration
	if s := in.InputValue(durationBlock, durationBlock); s != "" {
		v, err := jit.ParseDuration(s)
		if err != nil {
			return slack.ViewErrors(map[string]string{durationBlock: err.Error()})
		}
		dur = jit.Duration(v)
	}
	if dur > w.MaxDuration {
		return slack.ViewErrors(map[string]string{durationBlock: "This flow allows up to " + w.MaxDuration.Human() + "."})
	}
	deviceID := in.InputValue(deviceBlock, deviceBlock)
	if deviceID == "" {
		return slack.ViewErrors(map[string]string{deviceBlock: "Pick a device."})
	}
	viewID := in.View.ID
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), slowCall)
		defer cancel()
		v := b.fileRequest(ctx, api, in.User.ID, jit.NewRequest{WorkflowID: w.ID, Duration: dur, Reason: reason}, deviceID)
		<-slack.Acked(ctx) // the ack shows "Filing…"; this goes after it
		if err := api.UpdateView(ctx, viewID, v); err != nil {
			b.log().Warn("slack: showing the request outcome", "err", err)
		}
	}()
	return slack.UpdateView(notice("Request access", ":hourglass_flowing_sand: Filing your request…"))
}

// fileRequest checks the device and submits; it returns the view that says
// how it went.
func (b *Bot) fileRequest(ctx context.Context, api slack.API, userID string, nr jit.NewRequest, deviceID string) slack.View {
	again := "\nType `/jit request` to try again."
	id, err := b.resolve(ctx, api, userID)
	if err != nil {
		return notice("Not filed", fmt.Sprintf(":no_entry: JIT access can't tell who you are: %s.", esc(err.Error())))
	}
	devices, err := b.Svc.UserDevices(ctx, id.Login)
	if err != nil {
		return notice("Not filed", fmt.Sprintf(":no_entry: Couldn't check your devices with Tailscale: %s.%s", esc(err.Error()), again))
	}
	var dev *tsapi.Device
	for i := range devices {
		if devices[i].NodeID == deviceID {
			dev = &devices[i]
		}
	}
	if dev == nil {
		return notice("Not filed", ":no_entry: That device is not one of yours (any more)."+again)
	}
	id.DeviceID, id.DeviceName = dev.NodeID, dev.ShortName()
	r, err := b.Svc.Submit(ctx, id, nr)
	if err != nil {
		e := jit.AsError(err)
		msg := ":no_entry: " + esc(e.Message) + "."
		if e.RequestID != "" {
			msg += fmt.Sprintf("\n<%s|Open that request>", b.requestLink(e.RequestID))
		} else {
			msg += again
		}
		return notice("Not filed", msg)
	}
	b.log().Info("slack: request filed", "id", r.ID, "by", id.Login, "device", dev.ShortName())
	return notice("Request filed", fmt.Sprintf(":hourglass_flowing_sand: *%s* for `%s`, %s.\nIt's waiting for approval: <%s|open the request>.",
		esc(r.WorkflowName), esc(dev.ShortName()), r.Duration.Human(), b.requestLink(r.ID)))
}

// notice is a modal holding one message and a Close button.
func notice(title, msg string) slack.View {
	return slack.View{Type: "modal", CallbackID: requestView + "_notice", Title: slack.Plain(title), Close: slack.Plain("Close"),
		Blocks: []slack.Block{slack.Section(slack.Mrkdwn(msg))}}
}

// deviceLabel names a device in the picker: name, OS, and when it was last
// online.
func deviceLabel(d tsapi.Device) string {
	s := d.ShortName()
	if d.OS != "" {
		s += " · " + d.OS
	}
	if d.ConnectedToControl {
		s += " · online"
	} else if !d.LastSeen.IsZero() {
		s += " · seen " + d.LastSeen.Format("Jan 2")
	}
	return s
}

package slack

import "encoding/json"

// Message is what jitd posts: a plain-text fallback plus Block Kit blocks.
type Message struct {
	Text   string
	Blocks []Block
}

func (m Message) body(channel string) map[string]any {
	b := map[string]any{"channel": channel, "text": m.Text}
	if len(m.Blocks) > 0 {
		b["blocks"] = m.Blocks
	}
	return b
}

// Block is one Block Kit block; the constructors below build the few kinds
// jitd uses.
type Block map[string]any

// Text is a text object.
type Text map[string]any

// Mrkdwn is a Slack-markdown text object.
func Mrkdwn(s string) Text { return Text{"type": "mrkdwn", "text": s} }

// Plain is a plain-text text object.
func Plain(s string) Text { return Text{"type": "plain_text", "text": s, "emoji": true} }

// Section is a paragraph.
func Section(t Text) Block { return Block{"type": "section", "text": t} }

// SectionButton is a paragraph with a button on its right.
func SectionButton(t Text, button Element) Block {
	return Block{"type": "section", "text": t, "accessory": button}
}

// Fields is a section of short label/value pairs, laid out in two columns.
func Fields(ts ...Text) Block { return Block{"type": "section", "fields": ts} }

// Context is a line of small grey text.
func Context(ts ...Text) Block { return Block{"type": "context", "elements": ts} }

// Divider is a rule.
func Divider() Block { return Block{"type": "divider"} }

// Header is a bold title (plain text only).
func Header(s string) Block { return Block{"type": "header", "text": Plain(s)} }

// Actions is a row of buttons.
func Actions(blockID string, buttons ...Element) Block {
	return Block{"type": "actions", "block_id": blockID, "elements": buttons}
}

// Element is an interactive element (a button, an input).
type Element map[string]any

// Button is a button that sends a block_actions interaction with actionID
// and value.
func Button(actionID, label, value, style string) Element {
	e := Element{"type": "button", "action_id": actionID, "text": Plain(label)}
	if value != "" {
		e["value"] = value // Slack rejects an empty value
	}
	if style != "" {
		e["style"] = style // "primary" or "danger"
	}
	return e
}

// LinkButton is a button that opens a URL in the browser.
func LinkButton(actionID, label, url string) Element {
	return Element{"type": "button", "action_id": actionID, "text": Plain(label), "url": url}
}

// View is a modal.
type View struct {
	Type            string  `json:"type"`
	CallbackID      string  `json:"callback_id"`
	PrivateMetadata string  `json:"private_metadata,omitempty"`
	Title           Text    `json:"title"`
	Submit          Text    `json:"submit,omitempty"`
	Close           Text    `json:"close,omitempty"`
	Blocks          []Block `json:"blocks"`
}

// Input is an input block holding one element; multiline makes it a
// text area.
func Input(blockID, actionID, label, placeholder string, multiline bool) Block {
	return Block{"type": "input", "block_id": blockID, "label": Plain(label), "element": Element{
		"type": "plain_text_input", "action_id": actionID, "multiline": multiline, "placeholder": Plain(placeholder),
	}}
}

// InputBlock is an input block around any element. hint is small text
// under it.
func InputBlock(blockID, label string, el Element, optional bool, hint string) Block {
	b := Block{"type": "input", "block_id": blockID, "label": Plain(label), "element": el, "optional": optional}
	if hint != "" {
		b["hint"] = Plain(hint)
	}
	return b
}

// Option is one choice of a select menu. Slack caps its text at 75
// characters.
func Option(text, value string) Text {
	if r := []rune(text); len(r) > 75 {
		text = string(r[:74]) + "…"
	}
	return Text{"text": Plain(text), "value": value}
}

// Select is a single-choice menu; initial may be nil.
func Select(actionID, placeholder string, options []Text, initial Text) Element {
	e := Element{"type": "static_select", "action_id": actionID, "placeholder": Plain(placeholder), "options": options}
	if initial != nil {
		e["initial_option"] = initial
	}
	return e
}

// TextInput is a plain text field.
func TextInput(actionID, placeholder string, multiline bool) Element {
	return Element{"type": "plain_text_input", "action_id": actionID, "multiline": multiline, "placeholder": Plain(placeholder)}
}

// UpdateView is a modal's ack that replaces it with v.
func UpdateView(v View) map[string]any {
	return map[string]any{"response_action": "update", "view": v}
}

// Envelope is one Socket Mode message from Slack.
type Envelope struct {
	EnvelopeID string          `json:"envelope_id"`
	Type       string          `json:"type"` // hello, disconnect, events_api, interactive, slash_commands
	Payload    json.RawMessage `json:"payload"`
	Reason     string          `json:"reason"` // with disconnect
	// AcceptsResponsePayload says the ack may carry a payload (a slash
	// command's reply, a modal's validation errors).
	AcceptsResponsePayload bool `json:"accepts_response_payload"`
}

// Interaction is the payload of an interactive envelope: a button click
// (block_actions) or a submitted modal (view_submission).
type Interaction struct {
	Type      string `json:"type"`
	TriggerID string `json:"trigger_id"`
	User      struct {
		ID string `json:"id"`
	} `json:"user"`
	Channel struct {
		ID string `json:"id"`
	} `json:"channel"`
	Container struct {
		ChannelID string `json:"channel_id"`
		MessageTS string `json:"message_ts"`
	} `json:"container"`
	Actions []struct {
		ActionID string `json:"action_id"`
		BlockID  string `json:"block_id"`
		Value    string `json:"value"`
	} `json:"actions"`
	View struct {
		ID              string `json:"id"`
		CallbackID      string `json:"callback_id"`
		PrivateMetadata string `json:"private_metadata"`
		State           struct {
			Values map[string]map[string]struct {
				Type           string `json:"type"`
				Value          string `json:"value"`
				SelectedOption *struct {
					Value string `json:"value"`
				} `json:"selected_option"`
			} `json:"values"`
		} `json:"state"`
	} `json:"view"`
}

// InputValue returns what was typed or picked in the input block blockID /
// actionID of a submitted modal.
func (i *Interaction) InputValue(blockID, actionID string) string {
	v := i.View.State.Values[blockID][actionID]
	if v.SelectedOption != nil {
		return v.SelectedOption.Value
	}
	return v.Value
}

// SlashCommand is the payload of a slash_commands envelope.
type SlashCommand struct {
	Command     string `json:"command"`
	Text        string `json:"text"`
	UserID      string `json:"user_id"`
	ChannelID   string `json:"channel_id"`
	TriggerID   string `json:"trigger_id"`
	ResponseURL string `json:"response_url"`
}

// Ephemeral is a slash command's reply, seen by the caller only.
func Ephemeral(m Message) map[string]any {
	out := map[string]any{"response_type": "ephemeral", "text": m.Text}
	if len(m.Blocks) > 0 {
		out["blocks"] = m.Blocks
	}
	return out
}

// ViewErrors is a modal's ack that keeps it open and shows an error under
// the named input blocks.
func ViewErrors(errs map[string]string) map[string]any {
	return map[string]any{"response_action": "errors", "errors": errs}
}

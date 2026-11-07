package jitmcp

import (
	"context"
	_ "embed"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// MCP Apps (https://modelcontextprotocol.io/extensions/apps/overview): a tool
// can name an HTML resource that the host renders in a sandboxed iframe and
// hands the tool's result. Hosts that don't know the extension ignore the
// metadata and show the text.

const (
	appURI  = "ui://jit/app"
	appMIME = "text/html;profile=mcp-app"
)

//go:embed app.html
var appHTML string

// appMeta marks a tool as rendered by the app. The flat "ui/resourceUri"
// key is the pre-GA spelling; the reference SDK sends both, and hosts
// built against the earlier drafts only read that one.
func appMeta() mcp.Meta {
	return mcp.Meta{"ui": map[string]any{"resourceUri": appURI}, "ui/resourceUri": appURI}
}

// resourceMeta is the view's rendering preferences: no external origins
// (the page is self-contained), a border around it.
func resourceMeta() mcp.Meta {
	return mcp.Meta{"ui": map[string]any{"prefersBorder": true}}
}

// addApp registers the view. It is one self-contained page: no external
// scripts, styles or requests, so the host's default CSP suits it.
func addApp(srv *mcp.Server) {
	srv.AddResource(&mcp.Resource{
		URI:         appURI,
		Name:        "jit_app",
		Title:       "JIT access",
		Description: "Shows an access request as it is approved, and lets the user pick a flow and request access.",
		MIMEType:    appMIME,
		Meta:        resourceMeta(),
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
			URI:      appURI,
			MIMEType: appMIME,
			Text:     appHTML,
			Meta:     resourceMeta(),
		}}}, nil
	})
}

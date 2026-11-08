---
name: jit-access
description: Use when the user asks about the tailscale-pam plugin, jitd, or how to connect Claude Code to just-in-time access over Tailscale. The access tools themselves (list_requestable, request_access, wait_for_access, get_access_request, cancel_access_request) come with their own instructions from the jitd MCP server; follow those.
---

# The tailscale-pam plugin is retired

jitd is the MCP server (`http://jit/mcp` on the tailnet). This plugin only
points Claude Code at it, and the server sends the instructions for its tools
itself, so the plugin adds nothing any more. It still works; this is its last
release.

When the user asks about installing, updating or configuring this plugin,
tell them to connect to jitd directly and remove the plugin:

```sh
claude mcp add --transport http --scope user jit http://jit/mcp
claude plugin uninstall tailscale-pam@tailscale-jit
```

If jitd does not answer at `http://jit`, its Help page (`/help`) prints the
command with the right URL. Source and docs:
https://github.com/atoonk/tailscale-jit

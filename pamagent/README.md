# pamagent: the small local helper

The MCP server for just-in-time access is [jitd](../jitd/README.md) itself,
at `http://jit/mcp` on the tailnet. Claude Code and any other host that
speaks Streamable HTTP talk to it directly; jitd identifies them by their
Tailscale connection, so nothing is installed or logged into.

pamagent is what is left for the agent's own machine:

| Command | |
|---|---|
| `pamagent wait <request_id>` | waits until a request is decided and the granted Tailscale Services are visible to this node; for shells and background jobs |
| `pamagent bridge` (or just `pamagent`) | an MCP server on stdin/stdout that forwards every message to jitd's `/mcp`, for hosts that only run local servers, such as Claude Desktop |

It does not create a Tailscale identity, call the Tailscale admin API, or
connect to any service itself. The plugin ships prebuilt binaries (see the
[main README](../README.md)); build your own with
`go build -o bin/pamagent ./pamagent`.

## Waiting for a decision

The agent usually calls jitd's `wait_for_access` tool. This command does the
same from a shell, and can run in the background while the agent works on
something else:

```sh
pamagent wait [-service svc:server01] [-jit-url URL] [-timeout 5m] [-interval 30s] req_...   # flags go before the id
```

It checks every 3 seconds for the first two minutes, when someone is
probably approving right now; a check costs jitd next to nothing. After that
it checks every 20 seconds, then once a minute after 10 minutes, and by
default it stops after 5 minutes. `-interval` replaces this backoff with a
fixed interval. It prints one line per status change.

Once the request is approved, it waits (up to a minute) until this machine
can see the services: the ones named with `-service`, or without it, any of
the services the approval grants. Its last line lists what is visible and
what isn't yet. One host of a flow being offline doesn't hold it up.

| Exit code | Meaning |
|---|---|
| 0 | approved; the last line says what is visible to this node and what isn't yet |
| 1 | declined, cancelled, revoked or expired |
| 2 | error |
| 3 | still pending when it stopped; the agent repeats the link and offers to wait again |

`-socket` names the tailscaled LocalAPI socket when it is not at the
platform default.

## The bridge

Claude Desktop (and other hosts that only start local, stdio MCP servers)
can use jitd through the bridge. In `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "tailscale-pam": {
      "command": "/path/to/pamagent",
      "args": ["bridge", "-jit-url", "http://jit"]
    }
  }
}
```

The bridge interprets nothing. Each message from the host becomes one HTTP
POST to `/mcp` (jitd's MCP server is stateless, so no session is kept), and
the reply, one JSON object, goes back out on stdout (an event stream would
be passed through too, should jitd ever send one). The host and jitd negotiate everything between
themselves, including the MCP Apps view, which the bridge passes through
like any other message. A host that can't reach jitd gets a JSON-RPC error
per request instead of a hang. Logs go to stderr.

## Tests

```sh
go test ./pamagent
```

`wait` is tested against a fake jitd (`httptest`) and a fake service list;
the bridge against a fake `/mcp` that answers with JSON, an event stream,
`202 Accepted` and an error.

After changing pamagent, bump the version in both
`plugins/tailscale-pam/.claude-plugin/plugin.json` and `var version` in
`main.go`, then rebuild the plugin's binaries with `scripts/build.sh`.

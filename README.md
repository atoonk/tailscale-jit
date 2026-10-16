# Just-in-time access for people and agents, over Tailscale

Your agent needs the production database. It shouldn't have a standing
password for it, and neither should you.

With this, Claude Code asks for access the way a colleague would:
*"read-only on orders, 30 minutes, to check last night's refunds."* It gives
you a link, and someone approves it in the browser. Claude then connects.
Tailscale PAM injects the credentials along the way, so the agent never
sees a secret. When the time is up, the access is gone, and every request
and approval is on the record.

It works with whatever Tailscale PAM can put in front of: SSH, databases
(MySQL, PostgreSQL, MongoDB, MS SQL, CockroachDB, Elasticsearch),
Kubernetes, RDP, VNC, HTTP, TCP and AWS S3.

> **Experimental.** This is a working proof of concept, tested on a real
> tailnet. Expect rough edges.
>
> **Not an official Tailscale project.** This is an independent project and
> is not affiliated with, endorsed by, or supported by Tailscale Inc. It
> uses Tailscale's public APIs and features.

## How it fits together

There are two parts:

| | What it is | Who sets it up |
|---|---|---|
| **[jitd](jitd/README.md)** | The approval desk: approval flows, a web page to ask and approve, and an API. It runs as its own machine on your tailnet, at `http://jit`. | A tailnet admin, once |
| **[The tailscale-pam plugin](plugins/tailscale-pam)** | A Claude Code plugin. Its MCP server, [pamagent](pamagent/README.md), lets Claude see what it can reach, see what it could ask for, ask, and wait for the answer. | Everyone who uses Claude Code |

People can use jitd from the browser without the plugin.

Under the hood, an approval sets a custom posture attribute (for example
`custom:jit_db_ro`) with an expiry on the requester's device. Your tailnet
policy decides what that attribute unlocks, including PAM permissions such
as read-only on a database. When the attribute expires, Tailscale removes
it and the access ends.

## Get started

### 1. Run jitd (an admin, once per tailnet)

Follow **[jitd/README.md](jitd/README.md)**. It takes you through it step by
step:

1. Let people reach `tag:jit` in the policy.
2. Create an auth key and an OAuth client.
3. Build and start jitd.
4. Check that it works at http://jit/admin/setup.
5. Create an approval flow.
6. Paste the policy snippet jitd gives you.

### 2. Install the plugin (everyone using Claude Code)

You need:

- Tailscale **1.98 or newer**, running and logged in on the machine where
  Claude Code runs. (Claude Code on the web can't use it: the tools need a
  device on the tailnet.)
- jitd running at `http://jit` on your tailnet.
- Linux or macOS, on amd64 or arm64. The plugin ships prebuilt binaries, so
  there is nothing to build. macOS hasn't been tested yet, and there is no
  Windows build.

In Claude Code:

```
/plugin marketplace add atoonk/tailscale-jit
/plugin install tailscale-pam@tailscale-jit
```

Or from a shell:

```sh
claude plugin marketplace add atoonk/tailscale-jit
claude plugin install tailscale-pam@tailscale-jit
```

Then run `/mcp`. You should see `tailscale-pam` connected, with five tools:
`list_services`, `list_requestable`, `request_access`, `get_access_request`
and `cancel_access_request`.

Try asking: *"What's in the orders database? I don't think I have access
yet."*

A few tips:

- **jitd lives somewhere other than `http://jit`?** Clone the repository
  (`git clone https://github.com/atoonk/tailscale-jit`), change `-jit-url`
  in `plugins/tailscale-pam/.mcp.json`, and install from the checkout:
  `/plugin marketplace add ./tailscale-jit`.
- **Registered pamagent by hand before?** Remove that entry so the tools
  don't show up twice: `claude mcp remove pamagent` (add `-s user` if you
  added it with that scope).
- **Curious what this machine can reach?** Run `tailscale service list`
  (add `--json`). It shows the same services Claude sees.

## Good to know

- **Reaching a service isn't permission to do everything on it.** The PAM
  permissions in the policy grant still apply: a read-only grant refuses
  writes.
- **Access is per device.** The attribute goes on the device that asked, so
  everyone and everything on that device has the access while it lasts.
- **Agents ask; people approve.** The plugin has no approve button.
  However, the agent runs as you. On a flow that lets people approve their
  own requests, only its instructions stop it from approving with `curl`.
  Keep self-approval off for anything that matters.

## Working on it

Both programs live in one Go module. You need Go 1.26.6 or newer:

```sh
go test ./...
go build -o bin/jitd ./jitd
go run ./jitd/preview       # the jitd UI with made-up people, no tailnet needed
```

The plugin runs prebuilt binaries, not the source. After changing
`pamagent/`, bump the version in both
`plugins/tailscale-pam/.claude-plugin/plugin.json` and `pamagent/main.go`,
then run `scripts/build.sh` to rebuild them.

## License

[Apache License 2.0](LICENSE).

Tailscale is a trademark of Tailscale Inc. This project is not affiliated
with or endorsed by Tailscale Inc.

# tailscale-pam: the Claude Code plugin

This plugin lets Claude Code connect to infrastructure through Tailscale PAM,
and request just-in-time access through [jitd](../../jitd/README.md) when it
doesn't have access yet.

```
/plugin marketplace add atoonk/tailscale-jit
/plugin install tailscale-pam@tailscale-jit
```

Requirements and tips are in the [main README](../../README.md#2-install-the-plugin-everyone-using-claude-code). It needs a
[jitd](../../jitd/README.md) on your tailnet to request access through.

| File | |
|---|---|
| `.claude-plugin/plugin.json` | manifest and version |
| `.mcp.json` | starts the MCP server: `bin/pamagent -jit-url http://jit` (change the URL here) |
| `bin/pamagent` | picks the prebuilt binary for this OS and CPU |
| `libexec/<os>-<arch>/pamagent` | prebuilt [pamagent](../../pamagent/README.md) binaries, built by `scripts/build.sh` |
| `skills/jit-access/SKILL.md` | tells Claude how to use the tools: request the narrowest access, show the approval link, wait, connect without credentials |

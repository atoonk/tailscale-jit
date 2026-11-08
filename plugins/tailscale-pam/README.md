# tailscale-pam: the retired Claude Code plugin

jitd is an MCP server at `http://jit/mcp`, and it tells Claude how to use its
tools itself, so Claude Code needs no plugin to use it. Connect with one
command, once per machine:

```sh
claude mcp add --transport http --scope user jit http://jit/mcp
```

See the [main README](../../README.md#2-connect-claude-code-everyone-once-per-machine).

This plugin was the earlier way to do that. Version 0.7.0 is its last
release: a pointer to the same server (`.mcp.json`, with the jitd URL as a
setting) and a skill that tells people to switch. It is kept so existing
installs keep working. If you have it installed, run the command above and
then `claude plugin uninstall tailscale-pam@tailscale-jit`.

Earlier versions shipped `pamagent`, a local helper with a shell `wait`
command and a stdio bridge for Claude Desktop. Both are gone: `wait_for_access`
waits from any MCP client, and [mcp-remote](https://github.com/geelen/mcp-remote)
bridges Claude Desktop.

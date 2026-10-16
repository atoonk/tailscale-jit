# jitd: the approval desk

jitd is the small service that says yes or no. Someone asks for
time-limited access, or their agent asks for them. Another person approves
it in the browser. When the time is up, the access switches itself off.

It runs as its own machine on your tailnet, at `http://jit`. Nothing is
exposed to the internet, and nobody logs in: Tailscale already knows who is
asking. You install it once per tailnet.

**How it works, in one line:** an approval puts a temporary marker on the
requester's device, and your tailnet policy says what that marker unlocks.
The marker is a custom posture attribute, such as `custom:jit_db_ro`, with
an expiry.

```
requester (or Claude Code) ──request──▶ jitd ◀──approve── approver (browser)
                                          │
                                          ▼ Tailscale API
                       custom:jit_db_ro = true on the requester's device, expires in 1h
                                          │
                                          ▼ tailnet policy
                  grant { srcPosture: posture:jit_db_ro, dst: svc:mysql-prod, ... }
```

When the attribute expires, Tailscale removes it and the grant stops
applying. jitd doesn't have to be up for access to end.

It's a proof of concept: one process, one SQLite database, no high availability.

## Before you start

You need:

- **Tailscale PAM already working**, with at least one service you can
  reach today (for example `svc:mysql-prod`). jitd puts a gate in front of
  access; it doesn't set up PAM.
- **MagicDNS** turned on, so `http://jit` resolves.
- A tailnet on the **Premium or Enterprise** plan. Posture attributes with
  an expiry need it.
- Admin access to the policy file and the admin console.
- A Linux or macOS host that stays up, with **Go 1.26.6** or newer. It doesn't
  need Tailscale installed, because jitd brings its own node. It does need
  outbound internet access to reach Tailscale.

## Install

### 1. Let people reach jitd

In the admin console, open **Access controls**. Add an owner for `tag:jit`
and a grant that lets everyone reach it:

```jsonc
"tagOwners": {
  "tag:jit": ["autogroup:admin"]
},
"grants": [
  // Everyone may open the jitd UI and API.
  { "src": ["autogroup:member"], "dst": ["tag:jit"], "ip": ["tcp:80"] }
]
```

If you'll run with `-https`, allow `tcp:443` too.

### 2. Create the credentials

jitd needs two things from the admin console.

**An auth key for its node.** Go to Settings → Keys → **Generate auth key**.
Make it **one-off** (not reusable) and give it the tag `tag:jit`. jitd uses
it only on its first start.

**An OAuth client for the Tailscale API.** Go to Settings → OAuth clients →
**Generate OAuth client** and give it two scopes:

- **Devices → Posture attributes: Write**, so it can set and remove the
  attributes. This is how an approval turns access on and off.
- **Policy file: Read**, so it can resolve `group:` approvers, check each
  flow against the policy, and tell you what to add to it.

Copy the client ID and the secret. The secret is shown only once.

### 3. Build it

```sh
git clone https://github.com/atoonk/tailscale-jit
cd tailscale-jit
go build -o bin/jitd ./jitd
```

Or run `go install github.com/atoonk/tailscale-jit/jitd@latest`, which puts
`jitd` in `~/go/bin`.

### 4. Run it

The quickest way to try it is from your own shell. Put the OAuth client in
a file that only you can read:

```sh
mkdir -p ~/.config/jitd
cat > ~/.config/jitd/env <<'EOF'
TS_OAUTH_CLIENT_ID=...
TS_OAUTH_CLIENT_SECRET=tskey-client-...
EOF
chmod 600 ~/.config/jitd/env
```

On macOS, the default location is
`~/Library/Application Support/jitd/env`. Pass `-env-file ~/.config/jitd/env`
to use the path above.

Then start jitd. Pass the auth key just this once, and name yourself as an
admin:

```sh
TS_AUTHKEY=tskey-auth-... bin/jitd -admins you@example.com
```

When the log says `serving url=http://jit.<your-tailnet>.ts.net/`, open
**http://jit/** from any device on the tailnet.

Things to know:

- **`-admins`** decides who may manage approval flows and see every request.
  It takes logins, `group:` and `tag:`, separated by commas. Include at
  least one login: groups are looked up through the Tailscale API, so with a
  broken credential only a login can still get in to fix it. With no
  admins, nobody can create flows.
- **Keep two things:** the node's identity in `./tsnet-state` (`-state-dir`)
  and the flows and requests in the SQLite database `./jit.db` (`-data`).
  Lose the state directory and jitd joins the tailnet as a new machine.
- **Upgrading from a jitd that kept its data in `jit-data.json`?** With the
  default `-data`, there's nothing to do: on its first start, jitd finds
  `jit-data.json` next to the new `jit.db` and imports every flow and the
  whole request history. If you passed `-data some/path.json`, leave the
  flag as it is: jitd fills `some/path.db` from it once and uses that from
  then on. Either way the JSON file is left as it was; keep it as a backup.
  The log says `imported the old JSON data file`.
- **The name is taken?** If a machine called `jit` already exists, the new
  node becomes `jit-1`. Remove the old machine in the admin console, or pick
  another name with `-hostname`.
- **No auth key?** Then jitd logs a login URL instead. Open it and approve
  the machine, then tag it `tag:jit` in the admin console.

To keep jitd running, use a service. For example, on Linux with systemd:

```sh
sudo useradd --system --home-dir /var/lib/jitd --create-home jitd
sudo install bin/jitd /usr/local/bin/
sudo install -d -o jitd -m 700 /etc/jitd
sudo install -o jitd -m 600 ~/.config/jitd/env /etc/jitd/env
```

```ini
# /etc/systemd/system/jitd.service
[Unit]
Description=jitd: just-in-time access for Tailscale
After=network-online.target
Wants=network-online.target

[Service]
User=jitd
WorkingDirectory=/var/lib/jitd
ExecStart=/usr/local/bin/jitd -admins you@example.com -env-file /etc/jitd/env
# Only for the first start; see below. The "-" means it may be missing.
EnvironmentFile=-/etc/jitd/authkey
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/jitd
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

For the first start, put the auth key in a file of its own, start jitd,
and delete the file once the machine shows up in the admin console:

```sh
sudo sh -c 'umask 077; echo TS_AUTHKEY=tskey-auth-... > /etc/jitd/authkey'
sudo systemctl enable --now jitd
sudo rm /etc/jitd/authkey
```

If you already started jitd by hand, skip the key: move its `tsnet-state`
directory and its data (`jit.db`, or an older `jit-data.json`) into
`/var/lib/jitd` instead, owned by `jitd`.

### 5. Check the setup

As an admin, open **http://jit/admin/setup**. It tests the credential the
same way an approval will use it:

1. It reads the policy file.
2. It reads jitd's own device attributes.
3. It writes a throwaway attribute (`custom:jit_selfcheck`) on jitd's own
   node, and deletes it again.

If something fails, the page says what to fix and where. It never shows the
credential. Fix the file, then click **Check again**. No restart needed.

### 6. Create an approval flow

Go to **Manage → Approval flows → New flow**. A flow is one kind of access
people can ask for. For example:

> **Database (read-only).** Posture attribute `db_ro`. Gives access to
> `svc:mysql-prod`, "Orders and customers". Anyone in the tailnet can
> request it; `group:dba` approves; one approval; up to 4 hours.

The fields:

- **Posture attribute:** the one thing an approval sets, `custom:jit_<name>`.
  Each flow has its own.
- **Gives access to** (optional): one row per target, with a description.
  People and agents read this when they choose what to ask for. It grants
  nothing by itself; the policy does that.
- **Who can request** and **who can approve**: logins, `group:`, `tag:`, or
  `autogroup:member` for everyone.
- **How many approvals**, whether people may **approve their own** requests,
  the **default and maximum duration**, and how long a request may wait for
  a decision.

### 7. Add the flow to the policy

jitd never edits your policy; you paste in what it suggests. Open
**Manage → Policy snippet** (or run `bin/jitd -policy-snippet`). For each
flow it gives one posture and one grant. The page marks every part
"already in your policy" or "NEW", and *Only what is missing* hides the
rest.

For the read-only database flow above, the finished grant looks like this.
The PAM block is the part you add yourself:

```jsonc
"postures": {
  "posture:jit_db_ro": ["custom:jit_db_ro == true"]
},
"grants": [
  {
    "src":        ["autogroup:member"],          // the flow's requesters
    "dst":        ["svc:mysql-prod"],
    "ip":         ["*"],
    "srcPosture": ["posture:jit_db_ro"],         // only with an approval
    "app": {
      "tailscale.com/cap/pam": [{
        "version": "v1",
        "permissions": {
          "database": {
            "allowed_databases": [{ "database": "*", "allowed_query_types": ["ReadOnly"] }]
          }
        }
      }]
    }
  }
]
```

For a read-write flow, use `"permissions": {"database": {}}` instead. Both
were tested live against MySQL: the read-only grant refused `UPDATE`.

Two things that quietly undo the gate:

> **Remove any standing grant** that gives the same people the same
> service. Grants add up: if people can already reach it, the approval
> changes nothing, and a leftover read-write grant widens a read-only one.
>
> **Don't grant members a PAM connector's tag** (for example
> `tag:pam-connector`). That makes every service behind the connector
> reachable, with no approval at all.

Back on the flow's page, the **policy check** now confirms that the posture
is defined, shows which grants use it, and says whether they match
"Gives access to". If no grant uses the flow, the page says so, because
approving it would unlock nothing.

### 8. Try it

1. On your laptop, open http://jit/.
2. Pick the flow and ask for 15 minutes.
3. Have someone else approve it, or approve it yourself if the flow allows
   that.

The request page should say **Active · confirmed on the device**, and the
service shows up in `tailscale service list` within a few seconds. In 15
minutes it disappears again.

To try it with Claude Code, install the plugin (see the
[main README](../README.md)) and ask Claude for something that needs the
access.

## Day to day

- **Overview** (`/`): what you have access to now, what's waiting for
  approval, and what happened recently.
- **New request:** pick a flow, a duration and a reason. You get a link to
  send to an approver.
- **My requests:** cancel a pending request, or end your access early.
- **Approvals** show up on the overview: approve, or decline with a reason.
- **Manage** (admins): every request, the approval flows, the policy
  snippet, Setup, and the API docs.
- **Help** (`/help`) explains all of this inside the app.

Pages update on their own when something changes.

### Backups and digging into the history

Everything jitd remembers is in its SQLite database, `jit.db`: the flows,
and every request with its full timeline. Each row keeps the whole object as
JSON in `data`, so the `sqlite3` command line (the `sqlite3` package) can
answer questions the UI doesn't.

Run it as the user jitd runs as, since only that user can read the
database. With the systemd setup above:

```sh
cd /var/lib/jitd

# A consistent copy, safe while jitd runs. umask keeps it private:
# it holds every login, device and reason.
sudo -u jitd sh -c 'umask 077; sqlite3 -readonly jit.db ".backup jit-backup.db"'

# Who asked for what
sudo -u jitd sqlite3 -readonly jit.db \
  "SELECT requester, status, count(*) FROM requests GROUP BY 1, 2"

# The last ten reasons for one flow
sudo -u jitd sqlite3 -readonly jit.db \
  "SELECT id, json_extract(data, '$.reason') FROM requests
   WHERE workflow_id = 'wf_...' ORDER BY created_at DESC LIMIT 10"
```

Two things to know:

- **Look, don't touch.** jitd reads the database when it starts and keeps
  it in memory, so it won't see a change you make while it runs, and may
  overwrite it. Use `-readonly`, and only edit with jitd stopped.
- **Copying the file?** Use `.backup` as above. If you copy files by hand,
  stop jitd first and copy `jit.db-wal` along with `jit.db` if it's there:
  after a crash, the latest changes are still in it.

---

# Reference

## Rules

- Access is always for **the device you're on**. Nobody can request access
  for someone else's machine.
- **One open request per flow and device.** Asking again points you at the
  request you already have.
- **Approvals follow the flow as it is now.** Edit a flow and its pending
  requests follow:
  - a removed approver's vote no longer counts;
  - a new maximum shortens the access when it's granted (the timeline says
    so);
  - a new number of approvals applies (if you lower it, the next click on
    Approve grants it);
  - a changed posture attribute ends its pending requests.

  Access that is already approved keeps running until it ends; revoke it
  if it shouldn't.
- **Up to 10 approvals** can be required, from different people. Nothing is
  granted until the last one.
- **No dead ends:** a request that nobody else could ever approve is refused
  straight away. That happens when you are the only approver and the flow
  doesn't allow approving your own requests.
- Only the requester can cancel a pending request. Approvers and admins
  decline it instead, and nobody can decline their own.
- A pending request nobody decides on expires after the flow's approval
  timeout (24 hours by default). Reasons and notes are limited to 2,000
  characters.
- Admins see everything. Everyone else sees their own requests and the ones
  they can approve.
- jitd only answers to its own name and addresses, and refuses form
  submissions from other websites. This protects approvers from malicious
  pages; curl and the MCP client are unaffected.

**Checking the device.** After an approval, jitd reads the device's
attributes back and shows "confirmed on the device". After access ends, it
keeps checking until the attribute is really gone. Tailscale removes an
expired attribute about a minute after the expiry time (we measured about
75 seconds).

## Flags

| Flag | Default | |
|---|---|---|
| `-admins` | none | who may manage flows and see every request: logins, `group:`, `tag:` |
| `-state-dir` | `tsnet-state` | the node's identity; keep it |
| `-data` | `jit.db` | the SQLite database with the approval flows and access requests. Name an older jitd's `.json` file and jitd uses the `.db` of the same name, filled from the `.json` the first time |
| `-env-file` | `~/.config/jitd/env` (Linux), `~/Library/Application Support/jitd/env` (macOS) | Tailscale API credentials: `TS_OAUTH_CLIENT_ID` and `TS_OAUTH_CLIENT_SECRET`, or `TS_API_KEY` |
| `-hostname` | `jit` | the machine name on the tailnet |
| `-tag` | `tag:jit` | the tag jitd runs as, used in the policy snippet |
| `-https` | off | serve :443 with a Tailscale certificate and redirect :80; needs HTTPS turned on for the tailnet (admin console → DNS) |
| `-expiry-interval` | `30s` | how often to mark requests past their end time as expired |
| `-policy-snippet` | | print the policy snippet for the current flows and exit |
| `-ts-api` | `https://api.tailscale.com` | Tailscale API base URL, for testing |
| `-verbose` | off | log the tsnet backend and every HTTP request |

Environment variables fill in whatever the env file doesn't set, which is
handy in a container. `TS_AUTHKEY` is only needed on the first start. An API
access token (`TS_API_KEY=tskey-api-...`) works instead of an OAuth client,
but it expires within 90 days.

## API

JSON over HTTP on the tailnet. jitd knows who is calling from Tailscale, so
there are no tokens. Admins get interactive docs at **http://jit/api/docs**
(Swagger UI, loaded from cdnjs), for the spec at `http://jit/api/openapi.json`.
In the API, an approval flow is called a *workflow*.

| | |
|---|---|
| `GET /v1/me` | who the caller is |
| `GET /v1/requestable` | flows the caller may request, with any open request and what the policy grants |
| `GET/POST /v1/workflows`, `GET/PUT/DELETE /v1/workflows/{id}` | approval flows (admins) |
| `GET /v1/requests?scope=mine\|approvals\|all&status=` | requests the caller may see |
| `POST /v1/requests` | submit `{workflow_id, duration, reason}`; durations like `90m`, `2h`, `3d`, `1d12h`; leave `duration` out for the flow's default |
| `GET /v1/requests/{id}` | status and timeline |
| `POST /v1/requests/{id}/approve` · `decline` · `cancel` · `revoke` | `{note}`; declining needs one |
| `GET /v1/changes` | a change counter, for polling |
| `GET /v1/setup`, `POST /v1/setup/check` | the setup check's result, and run it again (admins) |
| `GET /v1/policy-snippet?missing=1` | the policy snippet (admins) |
| `GET /v1/devices/{id}/attributes` | a device's posture attributes (admins) |

Errors look like `{"error": {"code": "...", "message": "..."}}`. Some carry
`request_id` and `url`, for example when you ask twice and jitd points you
at the request you already have.

## Development

```sh
go test ./...            # from the repository root
go run ./jitd/preview    # the UI with made-up people; no tailnet needed
```

The preview serves the UI at http://127.0.0.1:8099/as/bob, with a fake
Tailscale API and some flows. Swap `bob` for alice, carol, dave, or root
(the admin) to see it as someone else. `-demo` switches to the cast from the
screenshots: Maya, Sam, Priya, and Leo as the admin, with two weeks of
history.

To try the MCP tools against the preview, without a jitd on your tailnet:

```sh
go run ./jitd/preview -demo -default maya &
go build -o bin/pamagent ./pamagent
claude mcp add --transport stdio pamagent-preview -- "$PWD/bin/pamagent" -jit-url http://127.0.0.1:8099
```

Claude's requests then count as Maya's, and you approve them in the browser
at http://127.0.0.1:8099/as/sam. `list_services` still asks the local
tailscaled, so it shows your real tailnet (or an error without one).

Code layout:

```
jitd/main.go             flags, the tsnet node, startup
jitd/internal/jit        the model and the rules: flows, requests, approvals, policy check and snippet, SQLite store
jitd/internal/jithttp    HTTP API, web UI (templates/, static/), OpenAPI spec
jitd/internal/tsapi      Tailscale API client: posture attributes, policy file
jitd/internal/setup      the credential check behind /admin/setup
jitd/preview             the UI preview
```

The tests use a fake Tailscale API, a fake WhoIs on a unix socket (through
the real Tailscale client), and a test resolver for the HTTP layer. One
test fails if a `/v1` route is missing from the OpenAPI spec.

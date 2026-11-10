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
- **A host to run it on**: your Mac, to try it out, or a small always-on
  Linux machine, to keep it. The host doesn't need Tailscale installed,
  because jitd brings its own node. It does need outbound internet access
  to reach Tailscale.

## Install

Steps 1 and 2 happen in the admin console and are the same either way.
Step 3 is where the two paths split:

| | |
|---|---|
| **[A. On a Mac, to try it out](#a-on-a-mac-to-try-it-out)** | One terminal, a few minutes; jitd stops when you press Ctrl-C. For seeing what it does before you give it a machine. |
| **[B. On an EC2 instance](#b-on-an-ec2-instance-recommended)** | Recommended. A small always-on instance with jitd as a systemd service, so it starts at boot and comes back after a reboot. This is the one to keep. |

Starting with A costs nothing: the same two credentials work on EC2, and
you can carry jitd's state over when you move.

### 1. Let people reach jitd

In the admin console, open **Access controls**. Add a group for the people
who will run jitd, an owner for `tag:jit`, and a grant that lets everyone
reach it:

```jsonc
"groups": {
  // jitd admins: they manage approval flows and see every request.
  "group:jit-admins": ["you@example.com"]
},
"tagOwners": {
  "tag:jit": ["autogroup:admin"]
},
"grants": [
  // Everyone may open the jitd UI and API.
  { "src": ["autogroup:member"], "dst": ["tag:jit"], "ip": ["tcp:80"] }
]
```

If you'll run with `-https`, allow `tcp:443` too.

Use a group of logins for the admins: jitd can't use `autogroup:admin` (it
can't see Tailscale roles), and a group can't contain an autogroup. Adding or
removing a jitd admin is then a policy edit, with no restart; jitd picks it up
within a minute.

### 2. Create the credentials

jitd needs two things from the admin console, and you make both now: an
**auth key**, which it uses once to join the tailnet, and an **OAuth
client**, which it uses from then on to set and remove posture
attributes. Both are shown only once, so paste them somewhere safe as you
go; step 3 asks for them. You need an Owner, Admin, IT admin or Network
admin role to create them.

**An auth key, for jitd's own node.**

1. Open **Settings → Keys**
   ([direct link](https://console.tailscale.com/admin/settings/keys)) and
   click **Generate auth key**.
2. Give it a description such as `jitd`, and leave **Reusable** off: jitd
   needs it only on its first start.
3. Turn **Tags** on and pick **`tag:jit`** from the list. This is the
   part to get right: jitd's node is tagged rather than owned by a
   person, the policy in step 1 lets people reach `tag:jit`, and a node
   can only be tagged by the key that creates it. A key with no tag, or
   another tag, gives you a jitd nobody can open.
   - **`tag:jit` not in the list?** Then step 1 isn't saved yet, or your
     account doesn't own the tag. Go back to **Access controls**, check
     that `tagOwners` has `"tag:jit": ["autogroup:admin"]`, save, and
     reload the Keys page.
4. Click **Generate key** and copy it. It looks like `tskey-auth-...`.

   If you'd rather not make a key at all, you can skip it: jitd then logs
   a login URL on its first start. Open it, approve the machine, and tag
   it `tag:jit` yourself in the admin console.

**An OAuth client, for the Tailscale API.**

1. Open **Settings → Trust credentials → New credential**
   ([direct link](https://console.tailscale.com/admin/settings/trust-credentials/add))
   and pick **OAuth**.
2. Add a description such as `jitd`.
3. On the **Scopes** step, give it these three:

   - **Devices → Posture attributes: Write**, so it can set and remove the
     attributes. This is how an approval turns access on and off.
   - **Devices → Core: Read**, so it can list a person's devices when they
     request access from Slack (`/jit request`), where it can't tell which
     device they are on.
   - **Policy file: Read**, so it can resolve `group:` approvers, check each
     flow against the policy, and tell you what to add to it.

4. Create the client, then copy the **client ID** and the **secret**
   (`tskey-client-...`). The secret is shown only once.

An API access token (`TS_API_KEY=tskey-api-...`) works in place of the
OAuth client, but it expires within 90 days and then jitd stops being able
to grant anything. Use the OAuth client.

### 3. Run it

Pick one: **A** on your Mac to try it out, or **B** on an EC2 instance to
keep it. The two paths end in the same place, with jitd on the tailnet at
`http://jit/`.

#### A. On a Mac, to try it out

**Get the binary.** jitd is a single self-contained file, with the web UI
built into it: you don't need the repository, Go, or anything else
installed. Every tagged release on
[GitHub](https://github.com/atoonk/tailscale-jit/releases) has `jitd` for
macOS and Linux, amd64 and arm64, with a `SHA256SUMS` file. Download one
into an empty directory of its own, which is where jitd will keep its
state:

```sh
mkdir -p ~/jitd && cd ~/jitd
# Apple silicon; on an Intel Mac use jitd-darwin-amd64
curl -fsSLO https://github.com/atoonk/tailscale-jit/releases/latest/download/jitd-darwin-arm64
curl -fsSLO https://github.com/atoonk/tailscale-jit/releases/latest/download/SHA256SUMS
grep jitd-darwin-arm64 SHA256SUMS | shasum -a 256 -c -   # must say: OK
install -m 755 jitd-darwin-arm64 jitd
```

`latest/download` is whatever the newest release is. To pin a version, put
`download/v0.7.0` in place of `latest/download` in both URLs.

If you download it in a browser instead, macOS quarantines it: run
`xattr -d com.apple.quarantine jitd` before starting it.

Building it yourself is for working on jitd, not for running it. If you
want to anyway, you need **Go 1.26.6** or newer and roughly 2 GB of free
memory to compile: `go install github.com/atoonk/tailscale-jit/jitd@latest`
puts `jitd` in `~/go/bin` without a clone, or clone the repository and run
`go build -o jitd ./jitd`.

**Put the OAuth client in a file** that only you can read, with the client
ID and secret from step 2 in place of the `...`. On macOS jitd reads
`~/Library/Application Support/jitd/env` unless you pass `-env-file`:

```sh
mkdir -p ~/Library/Application\ Support/jitd
cat > ~/Library/Application\ Support/jitd/env <<'EOF'
TS_OAUTH_CLIENT_ID=...
TS_OAUTH_CLIENT_SECRET=tskey-client-...
EOF
chmod 600 ~/Library/Application\ Support/jitd/env
```

**Start it.** Pass the auth key from step 2 (just this once: later starts
don't need it), and make the `group:jit-admins` group the admins, plus
your own login as a fallback. Put your key and your login in place of
`tskey-auth-...` and `you@example.com`:

```sh
TS_AUTHKEY=tskey-auth-... ./jitd -admins group:jit-admins,you@example.com
```

When the log says `serving url=http://jit.<your-tailnet>.ts.net/`, open
**http://jit/** from any device on the tailnet and carry on with step 4.

While you're trying it out:

- jitd runs in that terminal and stops with Ctrl-C. Everything it needs
  lands in the directory you started it from (`tsnet-state` and `jit.db`),
  so starting it there again is the same machine with the same flows, and
  no auth key.
- Your Mac has to be awake and online for people to request or approve.
  Access already granted keeps working while jitd is down, and still ends
  on time, because the expiry lives in the attribute Tailscale holds.
- When you're done, either move to EC2 as below, or remove the `jit`
  machine in the admin console.

#### B. On an EC2 instance (recommended)

jitd is one small process with one SQLite file, so the smallest instance
will do: a `t4g.small` running Amazon Linux 2023 or Ubuntu is plenty. Any
always-on Linux host with systemd works the same way; only the first step
is specific to EC2.

**1. Launch the instance.** Nothing has to reach it from outside the
tailnet:

- **No inbound rules** in the security group for jitd itself — people
  reach it over Tailscale. Open only what you use to administer the box,
  or nothing at all with SSM Session Manager.
- **Outbound internet access**, for the Tailscale connection (and Slack,
  if you connect it): a public subnet with a public IP, or a private
  subnet behind a NAT gateway.
- **Don't install Tailscale on the host.** jitd brings its own node and
  joins as `tag:jit`.
- Leave the root volume in place: jitd's identity and database live on it,
  in `/var/lib/jitd`. Stopping and starting the instance is fine; the node
  comes back as the same machine.

**2. Install the binary.** Nothing to clone and no Go on the instance:
jitd is one self-contained file with the web UI built into it, and
compiling it needs roughly 2 GB of free memory, more than the smallest
instances have. There is one release file per architecture, and the wrong
one fails only later, when systemd tries to run it (`Exec format error`), so
let the instance pick: `uname -m` says `aarch64` on Graviton (`t4g`), which
is `arm64` in the file name, or `x86_64` on `t3`, which is `amd64`.

```sh
ARCH=$(uname -m | sed 's/aarch64/arm64/; s/x86_64/amd64/')
echo "$ARCH"     # arm64 or amd64; anything else means this isn't a 64-bit Linux instance

curl -fsSLO https://github.com/atoonk/tailscale-jit/releases/latest/download/jitd-linux-$ARCH
curl -fsSLO https://github.com/atoonk/tailscale-jit/releases/latest/download/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS   # must say: jitd-linux-$ARCH: OK
sudo install -m 755 jitd-linux-$ARCH /usr/local/bin/jitd
```

The checksum only says the download is intact; `uname -m` is what makes it
the right file for this machine.

`latest/download` is whatever the newest release is. To pin a version, put
`download/v0.7.0` in place of `latest/download` in both URLs. Later, to
move to a new release, see
[Upgrading to a new release](#upgrading-to-a-new-release).

**3. Make a user and give it the OAuth client.** jitd needs no privileges
of its own. Fill in the client ID and secret from step 2 in place of the
`...` before you run this; the file ends up readable only by the `jitd`
user:

```sh
sudo useradd --system --home-dir /var/lib/jitd --create-home jitd
sudo install -d -o jitd -m 700 /etc/jitd
sudo -u jitd sh -c 'umask 077; cat > /etc/jitd/env' <<'EOF'
TS_OAUTH_CLIENT_ID=...
TS_OAUTH_CLIENT_SECRET=tskey-client-...
EOF
```

(Or write the same two lines with `sudo -u jitd vi /etc/jitd/env`, then
`sudo chmod 600 /etc/jitd/env`.)

**4. Write the service.** Open an empty unit file:

```sh
sudo vi /etc/systemd/system/jitd.service
```

Press `i` to start typing, paste the block below, and change
`you@example.com` in the `ExecStart` line to your own Tailscale login
(keep `group:jit-admins` from step 1, and keep the comma between them).
Then press `Esc`, type `:wq` and press Enter to save and close.

```ini
# /etc/systemd/system/jitd.service
[Unit]
Description=jitd: just-in-time access for Tailscale
After=network-online.target
Wants=network-online.target

[Service]
User=jitd
WorkingDirectory=/var/lib/jitd
ExecStart=/usr/local/bin/jitd -admins group:jit-admins,you@example.com -env-file /etc/jitd/env
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

**5. Start it.** The auth key from step 2 goes in a file of its own, which
you delete once the machine shows up in the admin console. Put your own
key in place of `tskey-auth-...`:

```sh
sudo sh -c 'umask 077; echo TS_AUTHKEY=tskey-auth-... > /etc/jitd/authkey'
sudo systemctl daemon-reload
sudo systemctl enable --now jitd
sudo journalctl -u jitd -f   # wait for: serving url=http://jit...  (Ctrl-C to stop watching)
sudo rm /etc/jitd/authkey
sudo systemctl status jitd
```

Open **http://jit/** from any device on the tailnet and carry on with
step 4. If the log shows an error instead, fix it and
`sudo systemctl restart jitd`.

**Coming from path A?** Then skip the auth key. Stop jitd on the Mac, copy
its `tsnet-state` directory and `jit.db` (and `jit.db-wal`, if it's there)
into `/var/lib/jitd`, run `sudo chown -R jitd /var/lib/jitd`, and
start the service. It comes back as the same machine, with the same flows
and history.

**One instance is enough**, and jitd doesn't have to run where the
services are. While it is down nobody can request or approve, but access
already granted keeps working and still ends on time. Don't run two
instances against the same database file.

#### Either way

Things to know:

- **`-admins`** decides who may manage approval flows and see every request.
  It takes logins, `group:` and `tag:`, separated by commas; `group:jit-admins`
  from step 1 is the usual choice. Include at least one login as well:
  groups are looked up through the Tailscale API, so with a broken
  credential only a login can still get in to fix it. With no admins, nobody
  can create flows.
- **Keep two things:** the node's identity in `tsnet-state` (`-state-dir`)
  and the flows and requests in the SQLite database `jit.db` (`-data`).
  Both sit in the directory jitd runs from: where you started it in path
  A, `/var/lib/jitd` in path B. Lose the state directory and jitd joins
  the tailnet as a new machine, with a new auth key.
- **A later release?** Replacing the binary and restarting is the whole
  upgrade: see [Upgrading to a new release](#upgrading-to-a-new-release).
- **Upgrading from a jitd that kept its data in `jit-data.json`?** With the
  default `-data`, there's nothing to do: on its first start, jitd finds
  `jit-data.json` next to the new `jit.db` and imports every flow and the
  whole request history. If you passed `-data some/path.json`, leave the
  flag as it is: jitd fills `some/path.db` from it once and uses that from
  then on. Either way the JSON file is left as it was; keep it as a backup.
  The log says `imported the old JSON data file`.
- **The name is taken?** If a machine called `jit` already exists, the new
  node becomes `jit-1`. Remove the old machine in the admin console and
  rename the node to `jit`, or keep the other name (or pick one with
  `-hostname`). People then connect their MCP client to that name instead
  of `http://jit`; jitd's Help page prints the exact command.
- **No auth key?** Then jitd logs a login URL instead (path B: find it
  with `sudo journalctl -u jitd`). Open it, approve the machine, and tag it
  `tag:jit` in the admin console.
- **Wrong credential, or none?** jitd still starts and serves the UI; it
  just can't grant anything. Step 4 says what's wrong, and a fixed env
  file needs no restart.

### 4. Check the setup

As an admin, open **http://jit/admin/setup**. It tests the credential the
same way an approval will use it:

1. It reads the policy file.
2. It reads jitd's own device attributes.
3. It writes a throwaway attribute (`custom:jit_selfcheck`) on jitd's own
   node, and deletes it again.

If something fails, the page says what to fix and where. It never shows the
credential. Fix the file, then click **Check again**. No restart needed.

### 5. Create an approval flow

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

Make a flow per *kind* of access, not per service. A flow is one posture
attribute and one grant, and a grant can list as many destinations as you
like, so "read-only databases", "read-write databases" and "SSH to the ops
hosts" are three flows, however many databases and hosts there are. Fewer
flows means fewer attributes to add to the policy, and gives people and
agents a short list of clearly different things to choose between.

### 6. Add the flow to the policy

jitd never edits your policy; you paste in what it suggests. Open
**Manage → Policy snippet** (or run `jitd -policy-snippet` in the
directory that holds its database). For each flow it gives one posture
and one grant. The page marks every part "already in your policy" or
"NEW", and *Only what is missing* hides the rest.

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

A posture can also be written as an object, `{"assertions": [...],
"onFailure": {...}}`, where `onFailure` badges or warns devices that fail
it; the admin console's editor may write your postures that way. jitd reads
both forms and its snippet uses the list. Don't add `onFailure` to a JIT
posture: every device without a current approval fails it by design, and
Tailscale warns every device that a grant requiring the posture targets, so
every member would carry a permanent warning.

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

### 7. Try it

1. On your laptop, open http://jit/.
2. Pick the flow and ask for 15 minutes.
3. Have someone else approve it, or approve it yourself if the flow allows
   that.

The request page should say **Active · confirmed on the device**, and the
service shows up in `tailscale service list` within a few seconds. In 15
minutes it disappears again.

To try it with Claude Code, run
`claude mcp add --transport http --scope user jit http://jit/mcp` (see the
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
  snippet, Setup, Slack, and the API docs.
- **Help** (`/help`) explains all of this inside the app.

Pages update on their own when something changes.

### Slack

jitd can post access requests to Slack and let approvers approve or decline
from the message. Set it up on **Manage → Slack**; it takes about two
minutes and no restart:

1. **Create the Slack app.** The button opens Slack's "create app" page
   already filled in (the bot, Socket Mode, the `/jit` command and the
   permissions). Pick your workspace and click Create.
2. **Install it** (Install App → Install to *your workspace*; if it says
   Request to Install, a workspace admin approves it first), then copy the
   **Bot User OAuth Token** (`xoxb-…`, under OAuth & Permissions).
3. **Generate an app-level token** with the `connections:write` scope
   (`xapp-…`, under Basic Information → App-Level Tokens).
4. **Paste both** on the Slack page, with the email domains your people use
   in Slack, and click Connect.

Then pick a channel on each approval flow's page, and optionally have jitd
send each approver a direct message.

- **Nothing new to expose.** jitd connects out to Slack (Socket Mode) over
  the host's internet connection, like its Tailscale API calls. Slack never
  connects to jitd, which stays tailnet-only. The "Open" button on a message
  links to the request page, which only works on the tailnet.
- **Same rules.** Approve and Decline in Slack go through the same checks as
  the browser. Revoking stays in the browser. `/jit` lists what is waiting
  for you and your own requests.
- **Requesting from Slack.** `/jit request` opens a form: approval flow,
  device, duration and reason. In the browser the device is the one you are
  on; Slack can't know that, so the form lists your own devices (untagged,
  owned by your login) from the Tailscale API, and jitd checks again on
  submit that the device is still yours. This uses the API's device list,
  which needs the **Devices → Core: Read** scope.
- **Identity is the one difference.** In the browser, Tailscale says who you
  are. In Slack, jitd takes the clicker's Slack email and uses it as their
  Tailscale login. Only full members of the connected workspace (no guests,
  no one from a shared channel's other company) with a confirmed email in an
  allowed domain are matched, and only if that login owns a device on the
  tailnet: someone who is in Slack but not (or no longer) on the tailnet
  can't act, even on flows that `autogroup:member` approves. Every decision
  made this way shows **via Slack** on the request, with the Slack account
  that made it. Someone whose Tailscale login is not their Slack email can't
  decide from Slack; the Slack page lists every approver and whether they
  match. For flows where that trust is not enough, turn on **Decide in the
  browser only**: their messages carry no buttons, and jitd refuses any
  decision from Slack on them.
- **The tokens** are kept in the database and never shown again; Disconnect
  revokes the bot token in Slack. To keep them out of the database, set
  `SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN` and `SLACK_ALLOWED_DOMAINS` in the env
  file instead and restart jitd; they then win over the page.
- If Slack is down or jitd was, nothing is lost: requests and approvals work
  in the browser as always, and jitd posts what it missed when it is back.

### Backups and digging into the history

Everything jitd remembers is in its SQLite database, `jit.db`: the flows,
and every request with its full timeline. Each row keeps the whole object as
JSON in `data`, so the `sqlite3` command line (the `sqlite3` package) can
answer questions the UI doesn't.

Run it as the user jitd runs as, since only that user can read the
database: your own shell can't even `cd` into `/var/lib/jitd`, so give the
paths in full as below. Neither image ships the CLI, so install it first if
`sqlite3` says `command not found` — `sudo apt-get install -y sqlite3` on
Ubuntu or Debian, `sudo dnf install -y sqlite` on Amazon Linux. With path
B's systemd setup:

```sh
# A consistent copy, safe while jitd runs. umask keeps it private:
# it holds every login, device and reason, and the Slack tokens if Slack
# was connected on the page.
sudo -u jitd sh -c 'umask 077; sqlite3 -readonly /var/lib/jitd/jit.db ".backup /var/lib/jitd/jit-backup.db"'

# Who asked for what
sudo -u jitd sqlite3 -readonly /var/lib/jitd/jit.db \
  "SELECT requester, status, count(*) FROM requests GROUP BY 1, 2"

# The last ten reasons for one flow
sudo -u jitd sqlite3 -readonly /var/lib/jitd/jit.db \
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

### Upgrading to a new release

Moving to a newer jitd is three things: download the binary from the
release, put it in place of the old one, restart. jitd is one
self-contained file, so no repository, no Go and no rebuild come into it,
and nothing around it changes: the node's identity in `tsnet-state`, the
flows and history in `jit.db`, the credentials in the env file and your
tailnet policy all stay as they are. You don't need a new auth key either;
that is only for a node's very first start.

What each release changed is on the
[releases page](https://github.com/atoonk/tailscale-jit/releases).

Two things to know before you start:

- **jitd is down for the few seconds of the restart**, so nobody can
  request or approve in that window. Access already granted keeps working
  and still ends on time, because Tailscale holds the expiry, not jitd.
- **The database upgrade is one-way.** A newer jitd brings `jit.db` up to
  its own schema on its first start, in a single transaction. An older
  jitd then refuses that database and says so, so going back to the old
  binary can mean restoring the backup from step 1. Take it.

#### Path B: the systemd service

1. **Back up the database,** so you can get back to today's state:

   ```sh
   sudo -u jitd sh -c 'umask 077; sqlite3 -readonly /var/lib/jitd/jit.db ".backup /var/lib/jitd/jit-upgrade-backup.db"'
   ```

   Run it from wherever you are, with the paths as written: `/var/lib/jitd`
   belongs to the `jitd` user, so your own shell can't even `cd` into it.
   jitd keeps serving while this runs.

   **`sqlite3: command not found`?** The CLI doesn't come with either
   image. Install it (`sudo apt-get install -y sqlite3` on Ubuntu or
   Debian, `sudo dnf install -y sqlite` on Amazon Linux), or skip it and
   copy the file across the restart instead:

   ```sh
   sudo systemctl stop jitd
   sudo -u jitd cp -a /var/lib/jitd/jit.db /var/lib/jitd/jit-upgrade-backup.db
   ```

   Stopping jitd closes the database cleanly, which folds `jit.db-wal` back
   into `jit.db`, so the copy is a whole backup; if a `jit.db-wal` is still
   there afterwards, copy it to `jit-upgrade-backup.db-wal` as well. Leave
   jitd down and carry on with step 2 — step 4 starts it again.

2. **Download the new binary** into a scratch directory, not over the one
   that is running, and check it against the release's checksums. Let
   `uname -m` choose the architecture rather than going by the instance
   type: the wrong file installs happily and fails only at the restart, as
   `Exec format error`. For a specific version, put `download/v0.7.0` in
   place of `latest/download`.

   ```sh
   cd /tmp
   ARCH=$(uname -m | sed 's/aarch64/arm64/; s/x86_64/amd64/')
   echo "$ARCH"     # arm64 or amd64

   curl -fsSLO https://github.com/atoonk/tailscale-jit/releases/latest/download/jitd-linux-$ARCH
   curl -fsSLO https://github.com/atoonk/tailscale-jit/releases/latest/download/SHA256SUMS
   sha256sum --ignore-missing -c SHA256SUMS
   ```

   It has to say `jitd-linux-$ARCH: OK`. If it doesn't, stop here: what you
   downloaded isn't what was released. A passing checksum says the file is
   intact, not that it's for this machine — `uname -m` is what says that.
   Stay in this shell for step 4, which uses `$ARCH` again.

3. **Keep the binary you are running now,** so a rollback is one command:

   ```sh
   sudo cp /usr/local/bin/jitd /usr/local/bin/jitd.prev
   ```

   Once only, and not again on a second attempt: if step 4 or 5 goes wrong
   and you come back to step 3, this copies the *broken* binary over your
   one good one and the rollback is gone. `jitd.prev` is worth keeping only
   as long as it holds the version that was serving.

4. **Put the new one in place and restart:**

   ```sh
   sudo install -m 755 /tmp/jitd-linux-$ARCH /usr/local/bin/jitd
   sudo systemctl reset-failed jitd    # no-op unless an earlier try crash-looped
   sudo systemctl restart jitd
   ```

   `install` replaces the file instead of writing into it, so it works
   while jitd is running, where `cp` would fail with "Text file busy". The
   running jitd keeps serving the old code until the restart. In a new
   shell since step 2, set `ARCH` again first — an empty `$ARCH` makes this
   `install` fail with "No such file", which is the harmless way round.

5. **Watch it come back:**

   ```sh
   sudo journalctl -u jitd -f   # wait for: serving url=http://jit...  (Ctrl-C to stop watching)
   ```

   If jitd stops instead of serving, the log says why, and *Going back*
   below returns you to the version you were running. Two to recognise:

   - **`Failed to execute /usr/local/bin/jitd: Exec format error`** is the
     binary for the other architecture. Nothing ran, so the database is
     untouched: go back, then start again from step 2 with what `uname -m`
     says.
   - **`Start request repeated too quickly`** is systemd giving up after
     five failed starts. It then refuses to start the service even once
     the binary is fixed, until `sudo systemctl reset-failed jitd`.

6. **Check it.** Open **http://jit/**: your flows, requests and history
   should all be there, and anything granted is still running. Then open
   **http://jit/admin/setup**, which tests the credential the same way an
   approval does.

**Going back.** If the new version misbehaves:

```sh
sudo install -m 755 /usr/local/bin/jitd.prev /usr/local/bin/jitd
sudo systemctl reset-failed jitd   # only needed after repeated failed starts
sudo systemctl start jitd
```

If it then complains that the database was written by a newer jitd, that is
the one-way schema upgrade. Restore the backup from step 1 over it, with
jitd stopped:

```sh
sudo systemctl stop jitd
sudo -u jitd sh -c 'cd /var/lib/jitd && rm -f jit.db jit.db-wal jit.db-shm && cp -a jit-upgrade-backup.db jit.db'
sudo systemctl start jitd
```

Anything decided between the backup and the rollback is then gone from the
history; access granted in that window still ends on time, because its
expiry lives on the device.

#### Path A: the Mac

Press Ctrl-C to stop jitd, then, in the directory you run it from:

```sh
cp jitd jitd.prev    # to go back to
curl -fsSLO https://github.com/atoonk/tailscale-jit/releases/latest/download/jitd-darwin-arm64
curl -fsSLO https://github.com/atoonk/tailscale-jit/releases/latest/download/SHA256SUMS
grep jitd-darwin-arm64 SHA256SUMS | shasum -a 256 -c -   # must say: OK
install -m 755 jitd-darwin-arm64 jitd
./jitd -admins group:jit-admins,you@example.com
```

No `TS_AUTHKEY`: `tsnet-state` and `jit.db` are in that directory already,
so jitd comes back as the same machine with the same flows. To go back, run
`install -m 755 jitd.prev jitd` and start it again.

---

# Reference

## Rules

- Access is always for **one of your own devices**: the one you're on in the
  browser or from an agent, or one you pick with `/jit request` in Slack
  (only your own untagged devices are offered, and jitd checks again when
  you submit). Nobody can request access for someone else's machine.
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
| `-admins` | none | who may manage flows and see every request: logins, `group:`, `tag:` (not `autogroup:admin`; use a group such as `group:jit-admins`). With a group, adding an admin is a policy edit that takes effect within a minute, no restart |
| `-state-dir` | `tsnet-state` | the node's identity; keep it |
| `-data` | `jit.db` | the SQLite database with the approval flows and access requests. Name an older jitd's `.json` file and jitd uses the `.db` of the same name, filled from the `.json` the first time |
| `-env-file` | `~/.config/jitd/env` (Linux), `~/Library/Application Support/jitd/env` (macOS) | Tailscale API credentials: `TS_OAUTH_CLIENT_ID` and `TS_OAUTH_CLIENT_SECRET`, or `TS_API_KEY`. Optionally `SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN` and `SLACK_ALLOWED_DOMAINS` (see Slack) |
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

## MCP

jitd is an MCP server at `http://jit/mcp` (Streamable HTTP). Any MCP client
on the tailnet can use it, with no login: jitd knows who is calling from the
Tailscale connection, as for every other request, and the tools act as that
person on that device. The tools are `list_requestable`, `request_access`,
`wait_for_access`, `get_access_request` and `cancel_access_request`; there is
no approve tool, on purpose. After `request_access`, the agent shows the
approval link and ends its turn; it waits (`wait_for_access`, up to 50
seconds a call) once you say the request is approved or ask it to wait. The
first `wait_for_access` for a pending request returns at once, so an agent
that skips the link still has to show it before anything blocks: hosts such
as Claude Code show nothing while a tool call runs. A request through a flow the tailnet policy
does not use yet is refused with a message to pass on to the user, since
approving it would unlock nothing. The server's instructions tell the agent
how to use the tools and how to connect to a service once it is granted, so
there is nothing to install on the client side: Claude Code connects with
`claude mcp add --transport http --scope user jit http://jit/mcp`.

Hosts that render [MCP Apps](https://modelcontextprotocol.io/extensions/apps/overview)
get a view with the tools: a card that shows the request and follows the
approval, and a form to pick a flow, a duration and a reason. So far that is
verified only with the preview's own test host (`go run ./jitd/preview`,
then `/mcp-host`), not yet in VS Code, Goose or Claude Desktop. Hosts that
don't render it get the same information as text. Claude Desktop only starts
local servers; [mcp-remote](https://github.com/geelen/mcp-remote) bridges its
stdio to `/mcp` (the main README has the config line).

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
| `GET /v1/slack`, `POST /v1/slack/connect` · `disconnect` · `test`, `PUT /v1/slack/domains`, `GET /v1/slack/channels` · `check` | the Slack connection (admins); tokens are never returned |

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
claude mcp add --transport http jitd-preview http://127.0.0.1:8099/mcp
```

Claude's requests then count as Maya's, and you approve them in the browser
at http://127.0.0.1:8099/as/sam. To see the MCP Apps view, point an
MCP Apps host (for example `ext-apps/examples/basic-host`) at the same URL.

Code layout:

```
jitd/main.go             flags, the tsnet node, startup
jitd/internal/jit        the model and the rules: flows, requests, approvals, policy check and snippet, SQLite store
jitd/internal/jithttp    HTTP API, web UI (templates/, static/), OpenAPI spec
jitd/internal/jitmcp     the MCP server at /mcp: the request tools and the MCP Apps view (app.html)
jitd/internal/tsapi      Tailscale API client: posture attributes, policy file, device list
jitd/internal/setup      the credential check behind /admin/setup
jitd/internal/slack      Slack Web API and Socket Mode client, Block Kit helpers, slack.Fake
jitd/internal/slackbot   the Slack integration: request messages, Approve/Decline, /jit, identity by email
jitd/preview             the UI preview
```

The tests use a fake Tailscale API, a fake WhoIs on a unix socket (through
the real Tailscale client), a test resolver for the HTTP layer, and
`slack.Fake` (an in-memory Slack with a Socket Mode connection the test
drives) for the Slack integration. One
test fails if a `/v1` route is missing from the OpenAPI spec.

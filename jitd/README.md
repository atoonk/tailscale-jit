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

Steps 1 and 2 happen in the admin console and are the same whichever way
you run jitd. Step 3 is where the paths split:

| | |
|---|---|
| **[A. On a Mac, to try it out](#a-on-a-mac-to-try-it-out)** | One terminal, a few minutes; jitd stops when you press Ctrl-C. For seeing what it does before you give it a machine. |
| **[B. On an EC2 instance](#b-on-an-ec2-instance-recommended)** | Recommended. A small always-on instance with jitd as a systemd service, so it starts at boot and comes back after a reboot. This is the one to keep. |
| **[C. On Kubernetes](#c-on-kubernetes)** | If you already run a cluster: the Helm chart in [`charts/jitd`](../charts/jitd) runs jitd as one pod with a persistent volume. |

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
  { "src": ["autogroup:member"], "dst": ["tag:jit"], "ip": ["tcp:80", "tcp:443"] }
]
```

Port 80 is what jitd serves by default; 443 is for `-https`, so allowing
both now means the policy still fits if you turn HTTPS on later.

Use a group of logins for the admins: jitd can't use `autogroup:admin` (it
can't see Tailscale roles), and a group can't contain an autogroup. Adding or
removing a jitd admin is then a policy edit, with no restart; jitd picks it up
within a minute.

### 2. Create an auth key

jitd joins the tailnet as a machine of its own, and an **auth key** is what
lets it in. It is used once, on the first start. You need an Owner, Admin,
IT admin or Network admin role to create one. (The credential for the
Tailscale API comes later, in step 4, from jitd's own page.)

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

### 3. Run it

Pick one: **A** on your Mac to try it out, **B** on an EC2 instance to
keep it, or **C** on a Kubernetes cluster you already run. They all end in
the same place, with jitd on the tailnet at `http://jit/`.

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
`download/v0.8.0` in place of `latest/download` in both URLs.

If you download it in a browser instead, macOS quarantines it: run
`xattr -d com.apple.quarantine jitd` before starting it.

Building it yourself is for working on jitd, not for running it. If you
want to anyway, you need **Go 1.26.6** or newer and roughly 2 GB of free
memory to compile: `go install github.com/atoonk/tailscale-jit/jitd@latest`
puts `jitd` in `~/go/bin` without a clone, or clone the repository and run
`go build -o jitd ./jitd`.

**Start it.** Pass the auth key from step 2 (just this once: later starts
don't need it), and make the `group:jit-admins` group the admins, plus
your own login as a fallback. Put your key and your login in place of
`tskey-auth-...` and `you@example.com`:

```sh
TS_AUTHKEY=tskey-auth-... ./jitd -admins group:jit-admins,you@example.com
```

When the log says `serving url=http://jit.<your-tailnet>.ts.net/`, open
**http://jit/** from any device on the tailnet and carry on with step 4, which connects it to the Tailscale API.

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
`download/v0.8.0` in place of `latest/download` in both URLs. Later, to
move to a new release, see
[Upgrading to a new release](#upgrading-to-a-new-release).

**3. Make a user.** jitd needs no privileges of its own:

```sh
sudo useradd --system --home-dir /var/lib/jitd --create-home jitd
sudo install -d -o jitd -m 700 /etc/jitd
```

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

#### C. On Kubernetes

The Helm chart in [`charts/jitd`](../charts/jitd) runs jitd as one pod.
An init container downloads the release binary and checks its checksum,
and a persistent volume keeps the node identity and the database. Put the
auth key from step 2 in a Secret, then install the chart from a checkout
of this repository. (The same Secret can hold the OAuth client from step
4, which then never touches the database.)

```sh
helm install jitd ./charts/jitd -n jitd \
  --set credentials.existingSecret=jitd-credentials \
  --set 'admins={you@example.com,group:jit-admins}'
```

The [chart's README](../charts/jitd/README.md) covers the Secret, the
values and upgrades.

#### Either way

Things to know:

- **`-admins`** decides who may manage approval flows and see every request.
  It takes logins, `group:`, `tag:` and (with Okta connected) `okta:`,
  separated by commas; `group:jit-admins`
  from step 1 is the usual choice. Include at least one login as well:
  groups are looked up through the Tailscale API, so with a broken
  credential only a login can still get in to fix it. With no admins, nobody
  can create flows.
- **Keep two things:** the node's identity in `tsnet-state` (`-state-dir`)
  and the flows and requests in the SQLite database `jit.db` (`-data`).
  Both sit in the directory jitd runs from: where you started it in path
  A, `/var/lib/jitd` in path B, and the data volume (`/data`) in path C.
  Lose the state directory and jitd joins the tailnet as a new machine,
  with a new auth key.
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
  with `sudo journalctl -u jitd`; path C: `kubectl -n jitd logs deploy/jitd`).
  Open it, approve the machine, and tag it `tag:jit` in the admin console.
- **No API credential yet?** jitd still starts and serves the UI; it just
  can't grant anything until step 4 is done.

### 4. Connect it to the Tailscale API

As an admin, open **http://jit/admin/integrations**. The first tab,
**Tailscale**, has the steps and a form. jitd needs an **OAuth client** to
set and remove posture attributes, which is how an approval turns access
on and off:

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
5. Paste both into the form on the page and click **Test and save**.

jitd tries the credential before it keeps it, the same way an approval
will use it:

1. It reads the policy file.
2. It reads jitd's own device attributes.
3. It writes a throwaway attribute (`custom:jit_selfcheck`) on jitd's own
   node, and deletes it again.

If something fails, the page says what to fix and nothing is saved. When
everything passes, the client is stored in jitd's database and used from
then on, with no restart. The secret is never shown again, on the page or
in the API. **Replace** takes a new client the same way, and **Remove**
forgets it.

An API access token (`tskey-api-...`) works in place of the OAuth client
(the page takes one too), but it expires within 90 days and then jitd
stops being able to grant anything. Use the OAuth client.

**Rather keep the secret out of the database?** Put it in jitd's env file
(`-env-file`; `/etc/jitd/env` in path B) or in its environment (the
Secret in path C) instead:

```sh
TS_OAUTH_CLIENT_ID=...
TS_OAUTH_CLIENT_SECRET=tskey-client-...
```

A credential set there wins over one saved on the page, and the page then
shows the check without the form. A changed file needs no restart: click
**Check again**.

**Rather store no secret at all?** Where jitd's platform issues it an OIDC
identity token (a Kubernetes service account token, a cloud workload
identity), use a **federated identity** instead of the OAuth client:
[workload identity federation](https://tailscale.com/kb/1581/workload-identity-federation).
Create it under **Settings → Trust credentials → New credential → OpenID
Connect**, with the issuer and subject of jitd's token and the same scopes
as the OAuth client above. Then set:

```sh
TS_OAUTH_CLIENT_ID=<the federated identity's client ID>
TS_ID_TOKEN=file:/path/to/token
```

`TS_ID_TOKEN` is the token itself, or `file:` and a path to read it from.
jitd exchanges it for a short-lived Tailscale API token and exchanges again
before that one expires, reading the file each time, so a token the platform
rotates (as Kubernetes does with projected service account tokens) keeps
working. On Kubernetes the chart sets this up with `federatedIdentity.*` (see
its README). If `TS_OAUTH_CLIENT_SECRET` is also set, the OAuth client is
used.

The other tabs under Integrations (Slack, Okta, Google Groups) are optional and work the
same way: steps, a form, and a test before anything is saved.

### 5. Create an approval flow

Go to **Manage → Approval flows → New flow**. A flow is one kind of access
people can ask for. For example:

> **Database (read-only).** Posture attribute `db_ro`. Gives access to
> `svc:mysql-prod`, "Orders and customers". Anyone in the tailnet can
> request it; `group:dba` approves; one approval; up to 4 hours.

The fields:

- **What an approval grants:** pick one. Most flows grant one thing; **Add
  another** puts more on the same flow, and an approval then grants all of
  them or none.
  - **Tailscale access:** a posture attribute, `custom:jit_<name>`, set on
    the requester's device. Each flow has its own.
  - **Okta groups** and **Google groups:** the requester is added to the
    groups until the access ends. Each can be picked once that integration
    is connected; see [Okta groups](#okta-groups) and
    [Google groups](#google-groups).
- **Gives access to** (optional): one row per target, with a description.
  People and agents read this when they choose what to ask for, and
  approvers when they decide. It grants nothing by itself; the policy and
  the groups do that. For Tailscale access, use the name as it appears in
  the policy grant (`svc:mysql-prod`, `tag:bastion`), so the policy check
  can compare the two.
- **Who can request** and **who can approve**: logins, `group:`, `tag:`, or
  `autogroup:member` for everyone.
- **How many approvals**, whether people may **approve their own** requests,
  the **default and maximum duration**, and how long a request may wait for
  a decision.
- **Approve requests automatically** (optional): every request is granted
  as soon as it is made, with no approver. Use it for low-risk access that
  should still be time-limited and recorded: the request, its reason and
  its expiry are kept, and the requester, an approver or an admin can revoke
  it. Approvers are optional on such a flow; any you list can revoke. If the
  grant fails (an Okta or Tailscale API error), the request is cancelled
  with the error in its timeline, and the requester can submit it again.
  Things to know about such a flow:
  - Making a flow automatic is the approval of every request that follows,
    so jitd keeps who did it and when with the flow, shows it on the flows
    page and names them in each grant's timeline. An admin who later
    changes who may request it, what it grants or for how long takes that
    over. Every flow change is logged with who made it.
  - Revoking ends that one grant. The requester can ask again and is
    granted again; to keep someone out, take them out of the flow's
    requesters or disable the flow.
  - It cannot hand out an Okta group whose members are approvers of a flow
    or jitd admins through an `okta:` principal: anyone who may request it
    could then give themselves that role. jitd refuses to save either side,
    going by the group's Okta ID, not its name. The same holds for a flow
    where one approval is enough and people may approve their own request.
    Requesters are not covered: if another flow lists that group as
    `okta:` requesters, whoever may request this flow can request that one
    too. Neither is an Okta group that reaches Tailscale through directory
    sync and is used as a `group:` principal: jitd cannot tell it is the
    same group, so keep such groups out of these flows yourself.
  - With **Decide in the browser only** set, it cannot be requested from
    Slack, since the request is the decision. The API and agents (MCP) can
    still request it.
  - In Slack the channel gets one message when the access is granted, with
    no buttons, and approvers get no direct message.

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
- **New request:** pick a flow, a duration and a reason, and optionally a
  start time to schedule it for later. You get a link to send to an
  approver.
- **My requests:** cancel a pending request, or end your access early.
- **Approvals** show up on the overview: approve, or decline with a reason.
- **Manage** (admins): every request, the approval flows, the policy
  snippet, Integrations (Tailscale, Slack, Okta, Google Groups), and the API
  docs.
- **Help** (`/help`) explains all of this inside the app.

Pages update on their own when something changes.

### Scheduling access

A request can start later instead of on approval: for a maintenance window
tonight, or a change planned for next week. In the request form, choose
**Starting at** and a time (up to 30 days ahead); through the API or MCP,
pass `start_at` as an RFC 3339 time.

- **Approve ahead.** Approvers decide any time before the start. An
  approved request is **scheduled**: nothing is granted yet, and it shows
  when it starts and ends.
- **jitd starts it.** On its expiry tick (`-expiry-interval`, 30 seconds by
  default), jitd sets the posture attribute and adds the Okta memberships
  once the start has come, and the access ends at the start plus the
  duration. Like Okta removals, this needs jitd running: if it is down at
  the start, access begins when it is back, and still ends on time.
- **A window, not a duration.** The access covers the window that was
  asked for. Approved after the start, it begins at once and still ends
  with the window.
- **Approvers have until the window ends.** The flow's approval timeout
  applies only to requests that start on approval; a request scheduled
  days ahead stays open for a decision until its window ends, and then
  expires if nobody decided.
- **If starting fails** (an API error), the request stays scheduled with
  the error shown, and jitd tries again on every tick until the window
  ends. If the flow is disabled, deleted or changed to grant something
  else before the start, jitd calls the request off instead.
- **Calling it off.** The requester, an approver or an admin can revoke a
  scheduled request before it starts; nothing was granted, so there is
  nothing to remove.
- **One at a time, per window.** A device can have one live request per
  flow at a time, but a scheduled request only counts for its own window:
  access today and a window next week can both be requested.
- **Automatic approval** works the same way: a flow that approves
  automatically schedules the request at once.

### Okta groups

A flow can also grant time-limited membership in **Okta groups**, with or
without a posture attribute. That reaches whatever Okta gates: AWS or GCP
roles through SSO, admin roles in SaaS apps, anything assigned by group.
An approval adds the requester's Okta user to each of the flow's groups;
when the access expires or is revoked, jitd takes them out again.

**Set it up.** As an admin, open **Integrations → Okta** in jitd. The page
walks through the steps below, takes the credentials in a form, and signs
in to Okta with them before it saves anything; if Okta refuses, it says
which step to look at again. Afterwards the page shows whether Okta still
accepts the credentials, the groups jitd may use and how many memberships
it holds, and **Test a group** tells you whether a flow could use a group.
Nothing needs a restart.

Credentials saved on the page are kept in jitd's database (like the Slack
tokens) and are never shown again, on the page or in the API. To keep them
out of the database, set them in the env file or the environment instead
(below). Credentials set there win over the saved ones, and the page then
shows the status and the test only.

jitd signs in to Okta in one of two ways.

*As an API service app* (recommended). The app has its own identity in
the Okta system log, only the scopes you grant it, and its own admin role,
and its key can be rotated without touching anyone's account. In the Okta
admin console:

1. **Applications → Create App Integration → API Services**, named, say,
   `jitd`.
2. Under **Client Credentials**, choose **Public key / Private key** and
   **Add key → Generate new key**; copy the **PEM** private key (and the key
   ID if the app will have more than one key).
3. Turn off **Require Demonstrating Proof of Possession (DPoP) header in
   token requests**: jitd does not send DPoP proofs.
4. **Okta API Scopes**: grant `okta.users.read` and `okta.groups.manage`.
5. **Admin roles**: assign the **Group Administrator** role (or a custom
   role with *Manage group membership*), limited to the groups jitd should
   manage. Scopes say what kind of call the app may make; the role says on
   which groups.

Then paste the Okta address, the client ID and the private key on the
Okta page. Or add them to jitd's env file:

```sh
OKTA_ORG_URL=https://example.okta.com
OKTA_CLIENT_ID=0oa...
OKTA_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----"
# Optional: the key's kid, when the app has more than one key.
# OKTA_PRIVATE_KEY_ID=...
# Optional: scopes to ask for, instead of okta.users.read okta.groups.manage.
# OKTA_SCOPES=...
```

The key can be RSA (2048 bits or more) or EC, in PKCS#8, PKCS#1 or SEC 1
PEM; in a one-line env file, write its line breaks as `\n`. Set from the
environment (a Kubernetes Secret, say), real line breaks work too.

*With an API token.* Create one under **Security → API → Tokens**, ideally
while signed in as a dedicated service account that holds the **Group
Administrator** role limited to the groups jitd should manage: the token
can do whatever that account can. Then paste it under **Use an API token
instead** on the Okta page, or set:

```sh
OKTA_ORG_URL=https://example.okta.com
OKTA_API_TOKEN=00a...
```

Set one or the other, not both. jitd re-reads the file on use, so no
restart is needed; at startup it logs which one it uses and where it came
from, or why the credentials it found are unusable. On the flow form,
**Okta groups** can then be picked under *What an approval grants*: group
names or IDs (`00g…`), separated by commas. jitd looks each one up when
you save, and stores its ID.

How it behaves:

- **Who.** The requester's Tailscale login is looked up as an Okta login,
  then as a primary email. A tagged device has no Okta user, so it cannot
  request through a flow with Okta groups.
- **Only Okta-mastered groups.** Groups whose members come from Active
  Directory, an app or a rule (`APP_GROUP`) cannot be changed through the
  API; jitd refuses them when the flow is saved.
- **Standing membership is left alone.** If the person was already in the
  group when access was approved, jitd records that and never removes them.
- **Shared membership.** If two live requests hold the same group for one
  person (two flows, or two devices), the membership comes off only when
  the last one ends. The request that ended first says the membership
  stayed because another running request held it; it never claims the
  membership was removed.
- **Removal needs jitd.** Okta memberships have no expiry, so unlike a
  posture attribute, jitd removes them itself, on its expiry tick
  (`-expiry-interval`, 30 seconds by default). If jitd is down when access
  ends, the membership stays until it is back. A removal that fails (a rate
  limit, a revoked token) is retried, and the request page says so. Each
  tick tries up to twenty, the ones that have waited longest first, so
  removals that keep failing do not hold up the others. After five minutes
  of failing, admins see a banner on every page, and those with a Slack
  account get one direct message, which turns into an all-clear when the
  removal goes through. If Okta says the group or the user no longer
  exists, jitd checks that its credential still works before it believes
  that there is nothing left to remove.
- **Turning Okta off.** Removing the Okta credentials stops new grants, not
  the clean-up: memberships jitd added are still its to remove. While any
  are in place the admins' banner says how many and that jitd cannot remove
  them until Okta is configured again, and it removes them as soon as it
  is. **Remove** on the Okta page says how many it holds and asks for a
  second click.
- **All or nothing.** If adding any group fails, jitd takes back what it
  already added (and the posture attribute) and the request stays pending,
  so the approver can try again.
- **Recorded first.** jitd writes down which memberships it is about to add
  before it adds the first one. If it stops halfway through an approval,
  or can't take a failed approval back, the next tick (the first thing a
  restarted jitd does) removes them; if that fails, admins see it in the
  banner.
- **Checked while it runs.** Every ten minutes jitd compares the
  memberships of running requests with Okta. If someone removed the user
  from a group in Okta, the request page says so; jitd does not add them
  back.
- **Token check.** jitd makes one cheap Okta call an hour, so a revoked or
  expired token shows in the admins' banner before a removal needs it.
- **Policy.** A flow with only Okta groups needs nothing in the tailnet
  policy file, and the policy snippet leaves it out.

**Okta groups as requesters and approvers.** With Okta configured, a
principal can also be `okta:<group>`, by exact group name or ID: for
example, requesters `okta:Engineering` and approvers
`okta:Eng-Leads`. It works anywhere a principal
does, including `-admins`, and for any flow, not only ones that grant Okta
groups.

- A person matches when their Okta user (Tailscale login, then email) is
  active and a member. A suspended or deactivated user matches nothing.
  Any group type counts, including groups pushed from a directory: jitd
  only reads them.
- Lookups are cached for a minute, so a membership change in Okta reaches
  jitd within about a minute. If Okta can't be read, `okta:` principals
  match nobody (and jitd logs why); logins and other principals still work.
  A failed lookup is not repeated for 30 seconds, so an Okta that is down
  does not slow every page.
- Saving a flow checks that each `okta:` group exists. Renaming the group
  in Okta later breaks the match; use its ID to avoid that. A name stands
  for exactly one group: if a second group gets the same name, the
  principal matches nobody until you use the ID.
- An `okta:` principal in `-admins` is checked when jitd starts, and jitd
  logs an error if it cannot be used.
- Tagged devices never match an `okta:` principal.
- The policy snippet can't name an Okta group in a grant's `src`, so it
  uses `autogroup:member` instead. The posture still gates access, since
  jitd sets it only for approved requesters.
- The token needs read access to users and groups (Read-Only Administrator
  is enough for this part).

**Limit which groups jitd uses.** Two optional allowlists in the env file
or the environment, re-read on use like the credentials. The Okta page
shows them but cannot change them, on purpose: they are how whoever runs
jitd limits what an admin in the browser can make it do.

```sh
# Groups a flow may add people to.
OKTA_GRANT_ALLOWLIST=jit.*,On-Call
# Groups an okta: principal may name.
OKTA_READ_ALLOWLIST=Team-*,On-Call
```

Entries are group names or IDs, separated by commas; `*` matches any run
of characters. A list that is left out means `*`, every group. A list that
is set but empty allows no group, and so does an env file jitd cannot read
when it starts (one that does not exist then is fine: it sets nothing). If
the file becomes unreadable later (a bad line, a permission) or goes away
(deleted, a volume that is no longer mounted), jitd carries on with the
Okta settings and lists it read last, and says so in the log and in the
admins' banner until the file is fixed or put back. To run without the
file from then on, restart jitd. jitd logs the lists in effect at startup.

- A flow that grants a group outside `OKTA_GRANT_ALLOWLIST` can't be
  saved, and each approval checks the list again before adding anyone, so
  removing a group from the list stops new grants through existing flows.
  Removal is never blocked: jitd can always take back what it gave.
- An `okta:` principal naming a group outside `OKTA_READ_ALLOWLIST` can't
  be saved, and if the list changes later it matches nobody.
- These limit what jitd does, not what its token can do. The real boundary
  is the Okta account behind the token: give it a custom admin role scoped
  to a resource set holding only these groups (manage members for the grant
  groups, read for the others), never Super Admin or Read-Only Admin.

### Google groups

A flow can grant time-limited membership in **Google groups** the same
way, with or without a posture attribute and next to Okta groups if you
use both. That reaches whatever Google gates by group: Google Cloud IAM
roles, apps people sign in to through Google, shared drives. An approval
adds the requester to each of the flow's groups; when the access expires
or is revoked, jitd takes them out again.

**Not for opening Tailscale access.** Tailscale reads Google groups only
every 40 minutes, so a group used in the tailnet policy would open access
late and close it late. Keep using the flow's posture attribute for that.

**Set it up.** As an admin, open **Integrations → Google Groups** in jitd.
The page walks through the steps, takes the key in a form (paste it or
choose the file) and signs in to Google with it before it saves anything;
if Google refuses, it says which step to look at again. Nothing needs a
restart. Google does not tell jitd whether the service account holds the
role of step 4, so finish with **Test a group** on the page: a group that
exists and is not found there means the role is missing. Once a flow names
a Google group, jitd looks for it every hour and tells the admins when it
cannot see it. In short:

1. In the Google Cloud console, pick or create a project and enable the
   **Cloud Identity API** in it.
2. **IAM & Admin → Service accounts → Create service account**. It needs
   no roles in the project.
3. On the service account: **Keys → Add key → Create new key → JSON**.
   Organisations created since May 2024 block this by default (the policy
   *Disable service account key creation*,
   `iam.disableServiceAccountKeyCreation`); an organisation policy
   administrator can turn it off for the one project.
4. In the Google Admin console, as a super admin: **Account → Admin roles
   → Groups Admin → Assign admin → Assign service accounts**, and add the
   service account's address. It can take a few minutes to apply.
5. Paste the key on the page, with the email domains jitd may add and the
   groups flows may grant.
6. **Test a group** on the page, to see that the role of step 4 is there.

jitd uses the Cloud Identity Groups API as that service account. There is
no domain-wide delegation, so the key reaches groups and nothing else: no
mail, no files, no user accounts. There is no API key for this; Google's
group APIs only take OAuth.

The key saved on the page is kept in jitd's database and is never shown
again, on the page or in the API. To keep it out of the database, put it
in the env file or the environment instead. The env file takes it on one
line (`jq -c . key.json` prints it that way); a key set there wins over
the saved one, and the page then shows the status and the test only.

```sh
GOOGLE_SERVICE_ACCOUNT_JSON={"type":"service_account","project_id":"…","private_key_id":"…","private_key":"-----BEGIN PRIVATE KEY-----\n…","client_email":"jitd@….iam.gserviceaccount.com",…}
# Optional. Both are normally set on the page; set here, they win and the
# page shows them read-only.
# GOOGLE_ALLOWED_DOMAINS=example.com
# GOOGLE_GRANT_ALLOWLIST=aws-*@example.com,gcp-*@example.com
```

On the flow form, **Google groups** can then be picked under *What an
approval grants*: group addresses, separated by commas. jitd looks each one
up when you save, and stores its ID. **Test a group** on the page tells you beforehand whether a flow could
use a group.

How it differs from Okta groups (everything else under "How it behaves"
above holds: standing and shared memberships, recorded first, all or
nothing, retries, the admins' banner and Slack message, the hourly check
of the key):

- **Who.** The requester's Tailscale login is used as their Google
  address; there is no lookup. If the two differ, Google refuses the add
  and the approval fails with Google's answer. A tagged device cannot
  request through a flow with Google groups.
- **Allowed domains.** jitd adds only logins in the email domains set on
  the page. Without that limit, someone who signs in to Tailscale from
  outside your Google account could be added as an external member
  wherever a group allows those. With no domain set, jitd adds nobody.
- **Groups a flow may grant.** The Groups Admin role reaches every group
  in the account, so the page has a list of the groups (addresses, `*` as
  a wildcard) flows may use. It is checked when a flow is saved and again
  at each approval. Removal is never blocked.
- **Dynamic groups** get their members from a query and cannot be changed;
  jitd refuses them when the flow is saved.
- **Removal needs jitd**, as with Okta. Google's own membership expiry
  exists only in some editions and jitd does not use it.
- **Both kinds on one flow.** The grant is all or nothing across Okta and
  Google: if one fails, jitd takes back what the other added. When the
  access ends each is removed on its own, with its own retries.
- **Going back to an older jitd.** A jitd from before Google groups does
  not know these fields and drops them when it next saves a request, which
  leaves people in the groups with nothing to take them out. End every
  request that holds a Google group before you roll back.

### Slack

jitd can post access requests to Slack and let approvers approve or decline
from the message. Set it up on **Integrations → Slack**; it takes about two
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
# it holds every login, device and reason, and every credential saved on
# the Integrations pages (Tailscale, Slack, Okta, Google).
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
flows and history in `jit.db`, the credentials (in `jit.db` too, or in the
env file) and your tailnet policy all stay as they are. You don't need a new auth key either;
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

On Kubernetes (path C), set `release.version` and the `release.sha256`
entries from the new release's `SHA256SUMS`, and run `helm upgrade`; the
[chart's README](../charts/jitd/README.md#upgrading-jitd) has the details.
Back up the database first, as in step 1 below.

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
   `Exec format error`. For a specific version, put `download/v0.8.0` in
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
   **http://jit/admin/integrations**, which tests the Tailscale API
   credential the same way an approval does.

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
- **One open request per flow and device for any one time.** Asking again
  points you at the request you already have. A scheduled request only
  blocks another whose time overlaps it.
- **Approvals follow the flow as it is now.** Edit a flow and its pending
  requests follow:
  - a removed approver's vote no longer counts;
  - a new maximum shortens the access when it's granted (the timeline says
    so);
  - a new number of approvals applies (if you lower it, the next click on
    Approve grants it);
  - a change to what the flow grants (the attribute or the groups) ends
    its pending requests.

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
| `-admins` | none | who may manage flows and see every request: logins, `group:`, `okta:`, `tag:` (not `autogroup:admin`; use a group such as `group:jit-admins`). With a group, adding an admin is a policy edit that takes effect within a minute, no restart |
| `-state-dir` | `tsnet-state` | the node's identity; keep it |
| `-data` | `jit.db` | the SQLite database with the approval flows and access requests. Name an older jitd's `.json` file and jitd uses the `.db` of the same name, filled from the `.json` the first time |
| `-env-file` | `~/.config/jitd/env` (Linux), `~/Library/Application Support/jitd/env` (macOS) | optional: credentials you would rather keep out of the database. They win over what is saved on the Integrations pages. Tailscale API: `TS_OAUTH_CLIENT_ID` with `TS_OAUTH_CLIENT_SECRET` (OAuth client) or `TS_ID_TOKEN` (federated identity), or `TS_API_KEY`. Also `SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN` and `SLACK_ALLOWED_DOMAINS` (see Slack), the `OKTA_*` settings (see Okta groups) and `GOOGLE_SERVICE_ACCOUNT_JSON` (see Google groups) |
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
approval link and ends its turn (`request_access` takes `start_at` to
schedule the access for later); it waits (`wait_for_access`, up to 50
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
| `POST /v1/requests` | submit `{workflow_id, duration, reason}`; durations like `90m`, `2h`, `3d`, `1d12h`; leave `duration` out for the flow's default; add `start_at` (an RFC 3339 time) to schedule it for later |
| `GET /v1/requests/{id}` | status and timeline |
| `POST /v1/requests/{id}/approve` · `decline` · `cancel` · `revoke` | `{note}`; declining needs one |
| `GET /v1/changes` | a change counter, for polling |
| `GET /v1/setup`, `POST /v1/setup/check` | the Tailscale API credential check: its result, and run it again (admins) |
| `PUT/DELETE /v1/setup/credentials` | save a Tailscale API credential (tested first; refused while the env file or environment sets one), or forget the saved one (admins); the secret is never returned |
| `GET /v1/policy-snippet?missing=1` | the policy snippet (admins) |
| `GET /v1/devices/{id}/attributes` | a device's posture attributes (admins) |
| `GET/PUT/DELETE /v1/okta`, `POST /v1/okta/check` | the Okta connection (admins): its status, save credentials (tested first), remove them, try them again or test a group; keys and tokens are never returned |
| `GET/PUT/DELETE /v1/google`, `POST /v1/google/check` | the Google connection (admins): its status, save the service account key and its limits (tested first), remove them, try them again or test a group; the key is never returned |
| `GET /v1/slack`, `POST /v1/slack/connect` · `disconnect` · `test`, `PUT /v1/slack/domains`, `GET /v1/slack/channels` · `check` | the Slack connection (admins); tokens are never returned |

Errors look like `{"error": {"code": "...", "message": "..."}}`. Some carry
`request_id` and `url`, for example when you ask twice and jitd points you
at the request you already have.

**Creating a flow from a script.** What an approval grants goes under
`grants`, one key per kind; leave out the ones you don't want. `resources`
is the form's "Gives access to". Run it from a device whose user is an
admin:

```sh
curl -X POST http://jit/v1/workflows -H 'Content-Type: application/json' -d '{
  "name": "Production on-call",
  "grants": {
    "tailscale": {"attribute": "custom:jit_prod_oncall"},
    "okta":      {"groups": [{"name": "AWS-Prod-Admin"}]},
    "google":    {"groups": [{"name": "gcp-prod-viewers@example.com"}]}
  },
  "resources": [{"name": "tag:prod", "description": "All production hosts"}],
  "requesters": ["group:sre"],
  "approvers": ["group:sre-leads"],
  "max_duration": "4h"
}'
```

The answer is the saved flow, with its `id` and the IDs of the groups.
`PUT /v1/workflows/{id}` replaces a flow and takes the same body. Name a
group by its `id` or its `name`; an `id` beside another group's name is
refused. Bodies written for an earlier release, with `attribute`,
`okta_groups` and `google_groups` at the top level, still work; answers
always use `grants`.

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
jitd/internal/setup      the Tailscale API credential and its check (Integrations → Tailscale)
jitd/internal/okta       Okta API client, okta.Fake
jitd/internal/oktasetup  the Okta credentials saved on Integrations → Okta
jitd/internal/google     Cloud Identity Groups API client (service account key), google.Fake
jitd/internal/googlesetup the Google key and limits saved on Integrations → Google Groups
jitd/internal/slack      Slack Web API and Socket Mode client, Block Kit helpers, slack.Fake
jitd/internal/slackbot   the Slack integration: request messages, Approve/Decline, /jit, identity by email
jitd/preview             the UI preview
```

The tests use a fake Tailscale API, a fake WhoIs on a unix socket (through
the real Tailscale client), a test resolver for the HTTP layer, and
`slack.Fake` (an in-memory Slack with a Socket Mode connection the test
drives) for the Slack integration. One
test fails if a `/v1` route is missing from the OpenAPI spec.

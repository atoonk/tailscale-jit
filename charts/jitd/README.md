# jitd Helm chart

Runs [jitd](../../jitd/README.md) on Kubernetes: one pod that joins your tailnet as its own machine, with its node identity and database on a persistent volume.

jitd has no container image. An init container downloads the release binary from GitHub, checks it against the release's `SHA256SUMS`, and the main container runs it. Both use a small Alpine image.

There is no Service or Ingress. jitd listens only on its tailnet address, so the pod needs outbound internet access and nothing inbound.

## Before you install

Do steps 1 and 2 of jitd's [Install](../../jitd/README.md#install) guide first:
1. In the policy file, add `tag:jit` and a grant that lets people reach it.
2. Create an OAuth client for the Tailscale API and, optionally, an auth key tagged `tag:jit`.

Then put the credentials in a Secret, using whatever you normally use for secrets (External Secrets, Sealed Secrets, SOPS, ...). For example:

```sh
kubectl create namespace jitd
kubectl -n jitd create secret generic jitd-credentials \
  --from-literal=TS_OAUTH_CLIENT_ID=... \
  --from-literal=TS_OAUTH_CLIENT_SECRET=tskey-client-... \
  --from-literal=TS_AUTHKEY=tskey-auth-...
```

The keys jitd reads:

| Key | For |
| :-- | :-- |
| `TS_OAUTH_CLIENT_ID`, `TS_OAUTH_CLIENT_SECRET` | The Tailscale API (or `TS_API_KEY`) |
| `TS_AUTHKEY` | Joining the tailnet on first start. Optional: without it, jitd logs a login URL. |
| `SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN` | Slack (optional) |
| `OKTA_API_TOKEN`, or `OKTA_CLIENT_ID` and `OKTA_PRIVATE_KEY` | Okta groups (optional) |

## Install

From a checkout of this repository:

```sh
helm install jitd ./charts/jitd -n jitd \
  --set credentials.existingSecret=jitd-credentials \
  --set 'admins={you@example.com,group:jit-admins}'
```

On ARM nodes, add `--set release.arch=arm64`.

Then follow the install notes:
- **With an auth key,** the node joins the tailnet by itself.
- **Without one,** get the login URL from `kubectl -n jitd logs deploy/jitd`, approve the machine, and tag it `tag:jit` in the admin console.

Either way, jitd is then at `http://jit/`; continue with step 4 of the install guide.

The auth key is used only on the first start, while the volume holds no node identity. You can remove it from the Secret afterwards.

## Values

The main ones, all in [values.yaml](values.yaml):

| Value | Default | What it does |
| :-- | :-- | :-- |
| `admins` | `[]` | Who manages approval flows and sees every request (`-admins`). Include at least one login. |
| `credentials.existingSecret` | `""` | Secret with the keys above, loaded as environment variables |
| `credentials.values` | `{}` | Or have the chart create the Secret from these values. Avoid in production. |
| `env` | `{}` | Plain environment variables, e.g. `OKTA_ORG_URL`, `OKTA_GRANT_ALLOWLIST` |
| `hostname` | `jit` | The node's tailnet name |
| `tag` | `tag:jit` | The node's tag, used in the policy snippet |
| `https` | `false` | Serve HTTPS with a Tailscale certificate |
| `release.version` | chart `appVersion` | Release tag to download |
| `release.arch` | `amd64` | `amd64` or `arm64`. Pods are pinned to nodes of this architecture. |
| `release.sha256.<arch>` | for `appVersion` | sha256 of `jitd-linux-<arch>`, from the release's `SHA256SUMS` |
| `release.repository` / `release.url` | `atoonk/tailscale-jit` / `""` | Where to download from: a fork, or a mirror URL |
| `persistence.*` | 1Gi, `ReadWriteOnce` | The data volume. `existingClaim` reuses one. |
| `extraArgs` | `[]` | More jitd [flags](../../jitd/README.md#flags) |

The credentials Secret and `env` are environment variables. jitd also reads the env file `/data/env` on the data volume, which its Setup page can write. Where a key is set in both, the file wins.

## Upgrading jitd

Set `release.version` and both `release.sha256` entries from the new release's `SHA256SUMS`, then run `helm upgrade`. A wrong checksum stops the init container before anything runs. The pod is replaced, not rolled, because only one jitd may use the database and node identity at a time.

## Things to know

- **One replica, always.** Two jitd processes must never share the database or the node identity. The chart fixes `replicas: 1` and uses the `Recreate` strategy.
- **Keep the volume.** It holds the node identity (`tsnet-state`) and every flow and request (`jit.db`). The claim is annotated `helm.sh/resource-policy: keep`, so `helm uninstall` leaves it. Lose it and jitd joins the tailnet as a new machine, with nothing in it. See [Backups](../../jitd/README.md#backups-and-digging-into-the-history).
- **No probes.** The kubelet can't reach jitd's tailnet-only listener. Its health shows in the admin console and on its Setup page.
- **Okta removals need jitd running.** If you use Okta groups, memberships are removed by jitd itself when access ends. Keep the pod running, and see the Okta section of jitd's README.
- **Hardened by default.** The pod runs as UID 65534 with a read-only root filesystem and no capabilities, and it mounts no service account token: jitd never calls the Kubernetes API.

#!/bin/sh
# Rebuild the plugin's prebuilt pamagent binaries from pamagent/.
#   scripts/build.sh
set -e
root=$(cd "$(dirname "$0")/.." && pwd)
out=$root/plugins/tailscale-pam/libexec
for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  os=${t%/*}
  arch=${t#*/}
  mkdir -p "$out/$os-$arch"
  (cd "$root" && CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -buildvcs=false -ldflags "-s -w" -o "$out/$os-$arch/pamagent" ./pamagent)
  echo "built $os-$arch"
done

#!/usr/bin/env bash
# Explicit owner execution only. No package install, CI access or production setup.
set -euo pipefail
export PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
if [[ $# != 2 || $1 != --confirm-dedicated-vm || $EUID != 0 ]]; then
  echo 'Usage: sudo bash run-vm-security.sh --confirm-dedicated-vm /root-owned/reviewed-bundle' >&2
  exit 2
fi
reviewed=$2
[[ $reviewed == /* && $reviewed != / && ! -L $reviewed ]]
check_ancestors() {
  local current=$1 mode owner
  while :; do
    [[ ! -L $current ]]
    owner=$(stat -c %u "$current")
    mode=$(stat -c %a "$current")
    [[ $owner == 0 ]]
    (( (8#$mode & 0022) == 0 ))
    [[ $current == / ]] && break
    current=$(dirname -- "$current")
  done
}
[[ ! -L ${BASH_SOURCE[0]} ]]
script_path=$(realpath -e -- "${BASH_SOURCE[0]}")
check_ancestors "$script_path"
check_ancestors "$reviewed"
[[ $(systemd-detect-virt --vm) == kvm || $(systemd-detect-virt --vm) == qemu ]]
[[ $(. /etc/os-release; printf '%s:%s' "$ID" "$VERSION_ID") == ubuntu:24.04 ]]
for artifact in acquisition.test rabiv-ingestor SHA256SUMS; do
  [[ -f $reviewed/$artifact && ! -L $reviewed/$artifact ]]
  check_ancestors "$reviewed/$artifact"
done
syft_binary=$(command -v syft)
check_ancestors "$syft_binary"
(
  cd -- "$reviewed"
  sha256sum --strict -c SHA256SUMS
)
export RABIV_PHASE3_VM_APPROVED=owner-approved
export RABIV_PHASE3_REVIEWED=$reviewed
export RABIV_PHASE3_SYFT=$syft_binary
# The tagged suite performs all mutation preflight before temporary accounts and
# directories. It reports actual failures, checks real credentials/mounts/cgroups,
# cleans only created principals, and retains a root-private review directory.
"$reviewed/acquisition.test" -test.v -test.timeout=10m -test.run='^TestVMPhase3$'

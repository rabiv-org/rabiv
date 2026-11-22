#!/usr/bin/env bash
# Explicit owner execution only. No package install, CI access or production setup.
set -euo pipefail
umask 077
export PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
if [[ $EUID != 0 || ( $# != 2 && $# != 3 ) || ( $1 != --confirm-dedicated-vm && $1 != --recover ) ]]; then
  echo 'Usage: sudo bash run-vm-security.sh --confirm-dedicated-vm BUNDLE | --recover BUNDLE CONTROL' >&2
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
for artifact in acquisition.test rabiv-ingestor vm_lab.py SHA256SUMS; do
  [[ -f $reviewed/$artifact && ! -L $reviewed/$artifact ]]
  check_ancestors "$reviewed/$artifact"
done
(
  cd -- "$reviewed"
  sha256sum --strict -c SHA256SUMS
)
export PYTHONDONTWRITEBYTECODE=1
if [[ $1 == --recover ]]; then
  [[ $# == 3 ]]
  exec /usr/bin/python3 "$reviewed/vm_lab.py" recover "$3"
fi
[[ $# == 2 ]]
syft_binary=$(command -v syft)
check_ancestors "$syft_binary"
exec /usr/bin/python3 "$reviewed/vm_lab.py" run "$reviewed" "$syft_binary"

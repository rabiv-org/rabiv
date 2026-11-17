#!/usr/bin/env bash
# Owner-reviewed, interactive-sudo entry point. Never run through Docker.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077

die() { printf 'PRECONDITION: %s\n' "$*" >&2; exit 77; }
[[ $# == 2 && $1 == --confirm-dedicated-vm ]] || die "usage: sudo bash run-vm-security.sh --confirm-dedicated-vm <reviewed-bundle-dir>"
[[ $EUID == 0 ]] || die "owner must invoke this script with interactive sudo on the Ubuntu VM"
[[ -r /etc/os-release ]] || die "OS metadata unavailable"
lab_os_id=$(python3 -c 'print(dict(line.strip().split("=",1) for line in open("/etc/os-release") if "=" in line).get("ID", "").strip(chr(34)))')
[[ $lab_os_id == ubuntu ]] || die "Ubuntu guest required; refusing host changes"
[[ $(systemd-detect-virt) == kvm ]] || die "dedicated KVM guest required"
for lab_tool in python3 stat setpriv setsid getent groupadd groupdel useradd userdel getfacl setfacl install mktemp id findmnt realpath grep cut sleep rm chmod sha256sum cat uname; do
    command -v "$lab_tool" >/dev/null || die "missing $lab_tool (owner may install acl for getfacl/setfacl in this VM)"
done
lab_bundle=$(realpath -e -- "$2")
for lab_file in handoff.test rabiv-verifier rabiv-publisher; do
    [[ -f $lab_bundle/$lab_file && ! -L $lab_bundle/$lab_file && -x $lab_bundle/$lab_file ]] || die "missing regular executable $lab_file"
done
for lab_parent in / /var /var/lib; do
    [[ ! -L $lab_parent && $(stat -c '%u:%g:%a' -- "$lab_parent") == 0:0:755 ]] || die "unsafe parent $lab_parent"
done
lab_base=/var/lib/rabiv-phase2-lab
if [[ -e $lab_base || -L $lab_base ]]; then
    [[ ! -L $lab_base && -d $lab_base && $(stat -c '%u:%g:%a' -- "$lab_base") == 0:0:755 ]] || die "unsafe existing lab base"
    lab_mount_target=$lab_base
else
    lab_mount_target=/var/lib
fi
lab_acl=$(getfacl -cp -- "$lab_mount_target") || die "cannot inspect lab-parent ACL"
if grep -Eq '^(default:|user:[^:]+:|group:[^:]+:)' <<< "$lab_acl"; then
    die "extra/default ACL on lab base; review instead of altering existing state"
fi
[[ $(findmnt -n -o FSTYPE -T "$lab_mount_target") == ext4 ]] || die "this acceptance run requires native guest ext4; no fallback"
# No filesystem, account, or service mutation occurs before the checks above.
if [[ ! -d $lab_base ]]; then install -d -o root -g root -m 0755 -- "$lab_base"; fi

lab_run=''
lab_test_pid=''
lab_created_users=()
lab_created_groups=()
cleanup() {
    lab_status=$?
    trap - EXIT INT TERM
    set +e
    lab_cleanup_failed=0
    # The test and its descendants use one newly created session/process group.
    if [[ -n $lab_test_pid ]]; then
        kill -TERM -- "-$lab_test_pid" 2>/dev/null
        sleep 0.2
        kill -KILL -- "-$lab_test_pid" 2>/dev/null
        wait "$lab_test_pid" 2>/dev/null
    fi
    if [[ -n $lab_run && ${lab_run%/*} == "$lab_base" && ${lab_run##*/} == run.* && ! -L $lab_run && -f $lab_run/AUTHORIZED ]]; then
        # GNU rm does not follow child symlinks. Never remove an arbitrary root.
        rm -rf -- "$lab_run/decisions" "$lab_run/actors"
        [[ $? == 0 ]] || lab_cleanup_failed=1
    fi
    for ((lab_i=${#lab_created_users[@]}-1; lab_i>=0; lab_i--)); do
        userdel -- "${lab_created_users[lab_i]}" || lab_cleanup_failed=1
    done
    for ((lab_i=${#lab_created_groups[@]}-1; lab_i>=0; lab_i--)); do
        groupdel -- "${lab_created_groups[lab_i]}" || lab_cleanup_failed=1
    done
    if [[ -n $lab_run && -f $lab_run/report.log ]]; then
        printf '\nTest exit=%s; cleanup_failed=%s\n' "$lab_status" "$lab_cleanup_failed" >> "$lab_run/report.log"
        chmod 0644 -- "$lab_run/report.log"
        printf 'Evidence retained: %s/report.log\n' "$lab_run"
    fi
    if [[ $lab_status == 0 && $lab_cleanup_failed != 0 ]]; then lab_status=1; fi
    exit "$lab_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

lab_run=$(mktemp -d "$lab_base/run.XXXXXXXX")
chmod 0755 -- "$lab_run"
lab_token=$(python3 -c 'import secrets; print(secrets.token_hex(4))')
lab_shared=rbp2s-$lab_token
lab_reader=rbp2r-$lab_token
lab_attacker_group=rbp2ag-$lab_token
for lab_group in "$lab_shared" "$lab_reader" "$lab_attacker_group"; do
    if getent group "$lab_group" >/dev/null; then die "lab group collision"; fi
    groupadd --system -- "$lab_group"
    lab_created_groups+=("$lab_group")
done
lab_verifier=rbp2v-$lab_token
lab_publisher=rbp2p-$lab_token
lab_attacker=rbp2a-$lab_token
lab_other=rbp2o-$lab_token
for lab_user in "$lab_verifier" "$lab_publisher" "$lab_attacker" "$lab_other"; do
    if getent passwd "$lab_user" >/dev/null; then die "lab account collision"; fi
    lab_primary=$lab_shared
    [[ $lab_user != "$lab_attacker" ]] || lab_primary=$lab_attacker_group
    useradd --system --no-create-home --no-user-group --gid "$lab_primary" --shell /usr/sbin/nologin -- "$lab_user"
    lab_created_users+=("$lab_user")
done
lab_verifier_uid=$(id -u "$lab_verifier")
lab_publisher_uid=$(id -u "$lab_publisher")
lab_attacker_uid=$(id -u "$lab_attacker")
lab_other_uid=$(id -u "$lab_other")
lab_shared_gid=$(getent group "$lab_shared" | cut -d: -f3)
lab_reader_gid=$(getent group "$lab_reader" | cut -d: -f3)
lab_attacker_gid=$(id -g "$lab_attacker")

install -d -o root -g root -m 0755 -- "$lab_run/bin" "$lab_run/decisions" "$lab_run/actors"
install -d -o "$lab_verifier_uid" -g "$lab_shared_gid" -m 0700 -- "$lab_run/decisions/staging"
install -d -o "$lab_verifier_uid" -g "$lab_reader_gid" -m 2750 -- "$lab_run/decisions/committed"
install -d -o "$lab_verifier_uid" -g "$lab_shared_gid" -m 0700 -- "$lab_run/actors/V"
install -d -o "$lab_publisher_uid" -g "$lab_shared_gid" -m 0700 -- "$lab_run/actors/P+"
install -d -o "$lab_attacker_uid" -g "$lab_attacker_gid" -m 0700 -- "$lab_run/actors/A"
install -d -o "$lab_other_uid" -g "$lab_shared_gid" -m 0700 -- "$lab_run/actors/O"
setfacl -b -k -- "$lab_run" "$lab_run/bin" "$lab_run/decisions" "$lab_run/decisions/staging" "$lab_run/decisions/committed" "$lab_run/actors" "$lab_run/actors/V" "$lab_run/actors/P+" "$lab_run/actors/A" "$lab_run/actors/O"
chmod 0755 -- "$lab_run" "$lab_run/bin" "$lab_run/decisions" "$lab_run/actors"
chmod 0700 -- "$lab_run/decisions/staging"
chmod 2750 -- "$lab_run/decisions/committed"
for lab_file in handoff.test rabiv-verifier rabiv-publisher; do
    install -o root -g root -m 0555 -- "$lab_bundle/$lab_file" "$lab_run/bin/$lab_file"
done
printf 'RABIV-PHASE2-LAB-V1\n' > "$lab_run/AUTHORIZED"
printf 'outside sentinel\n' > "$lab_run/outside-sentinel"
chmod 0644 -- "$lab_run/AUTHORIZED" "$lab_run/outside-sentinel"
python3 - "$lab_run" "$lab_verifier_uid" "$lab_publisher_uid" "$lab_shared_gid" "$lab_reader_gid" "$lab_attacker_uid" "$lab_attacker_gid" "$lab_other_uid" <<'PY'
import json, pathlib, sys
run, v, p, shared, reader, a, ag, other = sys.argv[1:]
cfg = {"store": {"RootDir": run + "/decisions", "VerifierUID": int(v), "PublisherUID": int(p), "VerifierPrimaryGID": int(shared), "PublisherPrimaryGID": int(shared), "ReaderGID": int(reader)}, "attacker_uid": int(a), "attacker_gid": int(ag), "other_uid": int(other)}
pathlib.Path(run, "config.json").write_text(json.dumps(cfg, indent=2) + "\n")
PY
chmod 0644 -- "$lab_run/config.json"

{
    printf 'Phase 2 isolated VM run: %s\n' "$lab_run"
    uname -a
    findmnt -T "$lab_run"
    getfacl -cp -- "$lab_run/decisions/staging" "$lab_run/decisions/committed"
    sha256sum -- "$lab_run/bin/handoff.test" "$lab_run/bin/rabiv-verifier" "$lab_run/bin/rabiv-publisher"
    printf 'Actual actor credentials are verified after exec by every helper.\n'
} > "$lab_run/report.log"
export RABIV_VMTEST_AUTHORIZED=1
export RABIV_VMTEST_RUN_DIR=$lab_run
# Only the test executable issues synthetic ALLOW; application binaries cannot.
setsid "$lab_run/bin/handoff.test" -test.run='^TestVMDecisionHandoff$' -test.v -test.timeout=2m >> "$lab_run/report.log" 2>&1 &
lab_test_pid=$!
if wait "$lab_test_pid"; then lab_result=0; else lab_result=$?; fi
cat -- "$lab_run/report.log"
exit "$lab_result"

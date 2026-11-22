#!/usr/bin/python3
"""Owner-run Phase 3 lab supervisor/recovery. Never imported by production code."""

import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

BASE = Path("/var/lib/rabiv-phase3-lab")
ROLES = ("fetch", "collector", "worker", "finalizer", "verifier", "attacker")
CHANNELS = (("fetch_collector", "fetch", "collector"),
            ("fetch_worker", "fetch", "worker"),
            ("fetch_finalizer", "fetch", "finalizer"),
            ("worker_finalizer", "worker", "finalizer"),
            ("collector_verifier", "collector", "verifier"),
            ("ingestor_verifier", "finalizer", "verifier"),
            ("capture_collector", "capture", "collector"))
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}


class LabError(Exception):
    pass


def command(args, timeout=10):
    return subprocess.run(args, env=ENV, capture_output=True, text=True,
                          timeout=timeout, check=False)


def save(control, state):
    """Private, durable replacement; no credential or process arguments stored."""
    fd, name = tempfile.mkstemp(prefix=".state-", dir=control)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(state, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, control / "state.json")
        fd = os.open(control, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def trusted(path, directory=False, private=False):
    p = Path(path)
    if not p.is_absolute() or str(p) != os.path.normpath(p):
        raise LabError("noncanonical administrative path")
    for parent in (p, *p.parents):
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise LabError("untrusted administrative path")
    mode = p.stat().st_mode
    if (directory and not stat.S_ISDIR(mode)) or (not directory and not stat.S_ISREG(mode)):
        raise LabError("unexpected administrative file type")
    if private and stat.S_IMODE(mode) != (0o700 if directory else 0o600):
        raise LabError("administrative state is not private")


def validate_state(state):
    owner = state["owner"]
    if state["version"] != 1 or not re.fullmatch(r"[a-f0-9]{32}", owner):
        raise LabError("invalid recovery state")
    root = Path(state["root"])
    if root.parent != BASE or not root.name.startswith("run."):
        raise LabError("invalid data root")
    names = {"r3" + role[:2] + owner[:12] for role in ROLES}
    groups = names | {"r3c" + str(n) + owner[:12] for n in range(7)}
    seen = set()
    for entry in state["identities"]:
        allowed = names if entry["kind"] == "user" else groups if entry["kind"] == "group" else set()
        key = (entry["kind"], entry["name"])
        if entry["name"] not in allowed or key in seen or entry["id"] is not None and (type(entry["id"]) is not int or entry["id"] <= 0):
            raise LabError("identity escapes this invocation")
        seen.add(key)
    if set(state["units"]) != {"probe", "worker"}:
        raise LabError("unexpected unit slots")
    for slot, unit in state["units"].items():
        if unit["name"] != "rabiv-worker-" + owner + "-" + slot or not re.fullmatch(r"[a-f0-9]{64}", unit["nonce"]):
            raise LabError("unit escapes this invocation")
        if unit["status"] not in ("planned", "pending", "rejected", "gone") or unit["invocation"] and not re.fullmatch(r"[a-f0-9]{32}", unit["invocation"]):
            raise LabError("invalid unit recovery status")
    supervisor = state["supervisor"]
    if type(supervisor["pid"]) is not int or supervisor["pid"] <= 0 or not str(supervisor["start"]).isdigit() or type(state["recovery_ready"]) is not bool:
        raise LabError("invalid supervisor identity")


@contextlib.contextmanager
def locked(control):
    trusted(control, directory=True, private=True)
    if control.parent != BASE or not control.name.startswith("control."):
        raise LabError("not a Phase 3 control directory")
    fd = os.open(control / "lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            raise LabError("invalid recovery lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        trusted(control / "state.json", private=True)
        state = json.loads((control / "state.json").read_text())
        validate_state(state)
        yield state
    finally:
        os.close(fd)


class Lab:
    """Only this fixed six-role/seven-channel lab, not a general resource API."""
    def __init__(self, control, state, run=None):
        self.control, self.state = Path(control), state
        self.run = command if run is None else run

    def persist(self):
        save(self.control, self.state)

    def lookup(self, kind, name):
        result = self.run(["getent", kind, name])
        if result.returncode == 2:
            return None
        if result.returncode != 0:
            raise LabError("identity lookup unavailable")
        lines = result.stdout.splitlines()
        if len(lines) != 1:
            raise LabError("ambiguous identity lookup")
        fields = lines[0].split(":")
        if len(fields) != (7 if kind == "passwd" else 4) or fields[0] != name:
            raise LabError("identity name changed")
        return fields

    def create(self, kind, name, gid=None, cancelled=lambda: False):
        if cancelled():
            raise LabError("cancelled before identity creation")
        database = "group" if kind == "group" else "passwd"
        if self.lookup(database, name) is not None:
            raise LabError("pre-existing lab identity; no creation attempted")
        if cancelled():
            raise LabError("cancelled after identity lookup")
        entry = {"kind": kind, "name": name, "id": None, "status": "pending"}
        self.state["identities"].append(entry)
        self.persist()
        if cancelled():
            entry["status"] = "gone"  # No creation command was issued.
            self.persist()
            raise LabError("cancelled before identity command")
        args = ["groupadd", "--system", name] if kind == "group" else [
            "useradd", "--system", "--gid", str(gid), "--no-create-home",
            "--shell", "/usr/sbin/nologin", "--comment", "RABIV-VM-" + self.state["owner"], name]
        result = self.run(args)
        if result.returncode != 0:
            # Do not adopt a possible collision or partial command outcome.
            entry["status"] = "uncertain"
            self.persist()
            raise LabError("identity creation not acknowledged; inspect private journal")
        current = self.lookup(database, name)
        if current is None:
            raise LabError("created identity unavailable")
        entry.update(id=int(current[2]), status="created")
        if kind == "user":
            entry["gid"] = gid
        self.persist()
        return entry["id"]

    def properties(self, unit):
        args = ["/usr/bin/systemctl", "show", unit, "--no-pager"]
        args += ["--property=" + p for p in ("LoadState", "ActiveState", "InvocationID", "SyslogIdentifier")]
        result = self.run(args)
        values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        if values.get("LoadState") == "not-found":
            return None
        if result.returncode != 0 or not values.get("LoadState"):
            raise LabError("unit identity lookup unavailable")
        return values

    def stop_unit(self, unit):
        if unit["status"] in ("planned", "rejected", "gone"):
            return
        current = self.properties(unit["name"])
        if current is None:
            unit["status"] = "gone"
            self.persist()
            return
        if current.get("SyslogIdentifier") != "rabiv-vm-" + unit["nonce"]:
            raise LabError("refusing unrelated unit: owner nonce mismatch")
        if current.get("ActiveState") in ("inactive", "failed"):
            return
        invocation = current.get("InvocationID", "")
        if not re.fullmatch(r"[a-f0-9]{32}", invocation) or invocation == "0" * 32:
            raise LabError("unit invocation identity unavailable")
        if unit["invocation"] and unit["invocation"] != invocation:
            raise LabError("unit invocation changed; no stop attempted")
        unit["invocation"] = invocation
        self.persist()
        # Recheck immediately before the stop, including the independent nonce.
        again = self.properties(unit["name"])
        if again is None:
            return
        if again.get("InvocationID") != invocation or again.get("SyslogIdentifier") != "rabiv-vm-" + unit["nonce"]:
            raise LabError("unit identity changed before stop")
        if self.run(["/usr/bin/systemctl", "stop", unit["name"]]).returncode != 0:
            raise LabError("owned unit stop failed")

    def cleanup(self):
        failures = []
        for unit in self.state["units"].values():
            try:
                self.stop_unit(unit)
            except (LabError, OSError, subprocess.SubprocessError):
                failures.append("unit cleanup requires review")
        users = [e for e in self.state["identities"] if e["kind"] == "user"]
        groups = [e for e in self.state["identities"] if e["kind"] == "group"]
        for entry in users + list(reversed(groups)):
            try:
                self.remove_identity(entry)
            except (LabError, OSError, subprocess.SubprocessError):
                failures.append("identity cleanup requires review: " + entry["name"])
        os.chmod(self.state["root"], 0o700)
        self.state["cleanup_errors"] = failures
        self.persist()
        if failures:
            raise LabError("cleanup incomplete; retain and inspect private state")

    def remove_identity(self, entry):
        if entry["status"] == "gone":
            return
        if entry["status"] != "created":
            raise LabError("unacknowledged creation; manual identity review required")
        kind, name = entry["kind"], entry["name"]
        current = self.lookup("passwd" if kind == "user" else "group", name)
        if current is None:
            entry["status"] = "gone"
            self.persist()
            return
        if int(current[2]) != entry["id"]:
            raise LabError("identity ID changed; refusing cleanup")
        if kind == "user":
            if int(current[3]) != entry["gid"] or current[4] != "RABIV-VM-" + self.state["owner"] or current[6] != "/usr/sbin/nologin":
                raise LabError("account ownership changed")
            if entry["id"] in self.state["baseline_uids"]:
                raise LabError("UID existed before lab; no process/account removal")
            self.run(["pkill", "-TERM", "-u", str(entry["id"])])
            time.sleep(0.05)
            self.run(["pkill", "-KILL", "-u", str(entry["id"])])
        result = self.run(["userdel" if kind == "user" else "groupdel", name])
        if result.returncode != 0:
            raise LabError("owned identity removal failed")
        entry["status"] = "gone"
        self.persist()


def private_json(path, value, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "w") as f:
        json.dump(value, f)
        f.flush()
        os.fsync(f.fileno())
        os.fchmod(f.fileno(), mode)


def baseline_uids():
    result = set()
    for p in Path("/proc").glob("[0-9]*/status"):
        try:
            for line in p.read_text().splitlines():
                if line.startswith("Uid:"):
                    result.update(map(int, line.split()[1:]))
        except OSError:
            continue
    return sorted(result)


def process_start(pid):
    try:
        # Only the kernel start counter, never argv or environment.
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
    except FileNotFoundError:
        return None


def begin_recovery(control):
    with locked(control) as state:
        state["recovery_ready"] = True
        save(control, state)


def verify_acl(root):
    result = command(["getfacl", "-cp", str(root)])
    if result.returncode != 0 or len([line for line in result.stdout.splitlines() if line.strip()]) != 3:
        raise LabError("extra/default ACLs are not supported")


def provision(lab, bundle, syft, cancelled):
    state = lab.state
    root = Path(state["root"])
    config = {"Root": str(root), "Binary": str(root / "acquisition.test"),
              "Ingestor": str(root / "rabiv-ingestor"), "Syft": syft, "Actors": {}, "Channels": {}}
    for name in ("acquisition.test", "rabiv-ingestor"):
        fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o555)
        with os.fdopen(fd, "wb") as f:
            f.write((bundle / name).read_bytes())
            os.fchmod(f.fileno(), 0o555)
    for role in ROLES:
        if cancelled():
            raise LabError("lab cancelled during provisioning")
        name = "r3" + role[:2] + state["owner"][:12]
        gid = lab.create("group", name, cancelled=cancelled)
        uid = lab.create("user", name, gid, cancelled=cancelled)
        if uid in state["baseline_uids"]:
            raise LabError("allocated UID is in use by an earlier process")
        config["Actors"][role] = {"UID": uid, "GID": gid, "Groups": []}
    config["Actors"]["capture"] = {"UID": 0, "GID": 0, "Groups": []}
    for n, (key, writer, reader) in enumerate(CHANNELS):
        if cancelled():
            raise LabError("lab cancelled during provisioning")
        gid = lab.create("group", "r3c" + str(n) + state["owner"][:12], cancelled=cancelled)
        w, r = config["Actors"][writer], config["Actors"][reader]
        w["Groups"].append(gid)
        r["Groups"].append(gid)
        directory = root / key
        directory.mkdir(mode=0o755)
        os.chmod(directory, 0o755)
        for child, group, mode in (("staging", w["GID"], 0o700), ("committed", gid, 0o2750)):
            path = directory / child
            path.mkdir(mode=0o700)
            os.chown(path, w["UID"], group)
            os.chmod(path, mode)
        channel = {"root_dir": str(directory), "writer_uid": w["UID"], "writer_gid": w["GID"],
                   "reader_uid": r["UID"], "reader_primary_gid": r["GID"], "reader_gid": gid}
        path = root / (key + ".json")
        private_json(path, channel, 0o444)
        config["Channels"][key] = str(path)
    private_json(root / "vm.json", config, 0o444)
    fd = os.open(root / "authorized", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    with os.fdopen(fd, "w") as f:
        f.write("RABIV_PHASE3_VM_ONLY\n")
        f.flush()
        os.fchmod(f.fileno(), 0o444)
    return config


def wait_child(child, cancelled, seconds):
    deadline = time.monotonic() + seconds
    result = None
    while True:
        # WNOWAIT keeps the session leader's PID reserved until descendants have
        # been terminated, even if the test exited/panicked before its children.
        if os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT):
            break
        if cancelled() or time.monotonic() >= deadline:
            result = cancelled() or 124
            break
        time.sleep(0.05)
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    end = time.monotonic() + 10
    while time.monotonic() < end and not os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT):
        time.sleep(0.05)
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    actual = child.wait(timeout=5)
    return actual if result is None else result


def run_lab(bundle, syft):
    try:
        BASE.mkdir(mode=0o755)
        os.chmod(BASE, 0o755)
    except FileExistsError:
        pass
    trusted(BASE, directory=True)
    if stat.S_IMODE(BASE.stat().st_mode) != 0o755:
        raise LabError("existing lab base mode mismatch; no repair")
    control = Path(tempfile.mkdtemp(prefix="control.", dir=BASE))
    root = Path(tempfile.mkdtemp(prefix="run.", dir=BASE))
    owner = secrets.token_hex(16)
    state = {"version": 1, "owner": owner, "root": str(root), "identities": [],
             "baseline_uids": baseline_uids(), "units": {}, "recovery_ready": False,
             "supervisor": {"pid": os.getpid(), "start": process_start(os.getpid())}}
    for slot in ("probe", "worker"):
        state["units"][slot] = {"name": "rabiv-worker-" + owner + "-" + slot,
                                "nonce": secrets.token_hex(32), "invocation": "", "status": "planned"}
    save(control, state)
    print("Private VM evidence/control directory:", control, flush=True)
    cancelled = [0]
    def interrupted(number, _frame):
        if not cancelled[0]:
            cancelled[0] = {signal.SIGINT: 130, signal.SIGTERM: 143, signal.SIGHUP: 129, signal.SIGALRM: 124}[number]
    previous = {s: signal.signal(s, interrupted) for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGALRM)}
    deadline = time.monotonic() + 480
    signal.setitimer(signal.ITIMER_REAL, 480)
    result = 1
    try:
        # Report and journal are private even if the test process dies immediately.
        with open(control / "report.txt", "xb") as report:
            os.chmod(control / "report.txt", 0o600)
            os.chmod(root, 0o755)  # Channel ancestors require this; control remains 0700.
            verify_acl(root)
            provision(Lab(control, state), bundle, syft, lambda: cancelled[0])
            if cancelled[0]:
                raise LabError("lab cancelled before test start")
            env = dict(ENV, RABIV_PHASE3_VM_APPROVED="owner-approved", RABIV_PHASE3_REVIEWED=str(bundle),
                       RABIV_PHASE3_VM_CONFIG=str(root / "vm.json"), RABIV_PHASE3_CONTROL=str(control), RABIV_PHASE3_SYFT=syft)
            child = subprocess.Popen([str(bundle / "acquisition.test"), "-test.v", "-test.timeout=10m", "-test.run=^TestVMPhase3$"],
                                     env=env, stdout=report, stderr=subprocess.STDOUT, start_new_session=True)
            result = wait_child(child, lambda: cancelled[0], max(0, deadline-time.monotonic()))
    finally:
        # Independent recovery process survives test panic/timeout. A hard kill of
        # THIS supervisor still requires the explicit, private-journal recovery.
        signal.setitimer(signal.ITIMER_REAL, 0)
        os.chmod(root, 0o700)
        for s in previous:
            signal.signal(s, signal.SIG_IGN)
        try:
            begin_recovery(control)
            if run_recovery(bundle, control) != 0:
                result = 1
        finally:
            for s, handler in previous.items():
                signal.signal(s, handler)
    return result


def run_recovery(bundle, control):
    # The cleanup process gets its own held session too. A stalled cleanup
    # command must not survive just because only its Python parent was killed.
    with open(control / "report.txt", "ab") as report:
        child = subprocess.Popen(["/usr/bin/python3", "-B", str(bundle / "vm_lab.py"), "recover", str(control)],
                                 env=ENV, stdin=subprocess.DEVNULL, stdout=report,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        return wait_child(child, lambda: 0, 75)


def launch_unit(control, slot, payload):
    if slot not in ("probe", "worker"):
        raise LabError("invalid unit slot")
    with locked(control) as state:
        lab = Lab(control, state)
        unit = state["units"][slot]
        if unit["status"] != "planned":
            raise LabError("unit slot already used")
        if lab.properties(unit["name"]) is not None:
            unit["status"] = "rejected"
            lab.persist()
            raise LabError("pre-existing unit; no start/stop attempted")
        argv = payload["argv"]
        if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv) or argv.count("--unit=" + unit["name"]) != 1:
            raise LabError("unit argument binding mismatch")
        if "--property=RuntimeMaxSec=180" not in argv or "--property=MemoryMax=2147483648" not in argv or "--property=CPUQuota=100%" not in argv or "--property=TasksMax=64" not in argv:
            raise LabError("lab unit limits changed")
        request = json.dumps(payload["request"]).encode()
        if len(request) > 256 << 10:
            raise LabError("worker request too large")
        argv.insert(argv.index("--"), "--property=SyslogIdentifier=rabiv-vm-" + unit["nonce"])
        unit["status"] = "pending"
        lab.persist()
        try:
            with tempfile.TemporaryFile(dir=control) as src, tempfile.TemporaryFile(dir=control) as output:
                src.write(request)
                src.seek(0)
                result = subprocess.run(["/usr/bin/systemd-run", *argv], stdin=src, stdout=output,
                                        stderr=subprocess.DEVNULL, env=ENV, timeout=195, check=False)
                output.seek(0)
                data = output.read((1 << 20) + 1)
                if result.returncode != 0 or len(data) > 1 << 20:
                    raise LabError("lab unit failed or output exceeded bound")
                sys.stdout.buffer.write(data)
        finally:
            lab.stop_unit(unit)


def main(args):
    os.umask(0o077)
    if os.getuid() != 0 or os.geteuid() != 0:
        raise LabError("owner-run root VM operation only")
    trusted(Path(__file__))
    trusted(Path("/usr/bin/python3").resolve())
    release = Path("/etc/os-release").read_text()
    virt = command(["systemd-detect-virt", "--vm"])
    fs = command(["findmnt", "-n", "-o", "FSTYPE", "-T", "/var/lib"])
    if 'ID=ubuntu\n' not in release or 'VERSION_ID="24.04"' not in release or virt.returncode != 0 or virt.stdout.strip() not in ("kvm", "qemu") or fs.returncode != 0 or fs.stdout.strip() != "ext4":
        raise LabError("dedicated Ubuntu 24.04 KVM/guest ext4 required")
    if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
        raise LabError("cgroups v2 required")
    tools = ("userdel", "groupdel", "systemctl", "getent", "pkill") if args and args[0] == "recover" else ("useradd", "userdel", "groupadd", "groupdel", "setpriv", "getfacl", "findmnt", "systemd-run", "systemctl", "getent", "pkill")
    for tool in tools:
        path = shutil.which(tool, path=ENV["PATH"])
        if path is None:
            raise LabError("required lab tool unavailable")
        trusted(Path(path).resolve())
    if len(args) == 3 and args[0] == "run":
        return run_lab(Path(args[1]), args[2])
    if len(args) == 2 and args[0] == "recover":
        with locked(Path(args[1])) as state:
            supervisor = state["supervisor"]
            if not state["recovery_ready"] and process_start(supervisor["pid"]) == supervisor["start"]:
                raise LabError("supervisor is active; cancel it before recovery")
            Lab(Path(args[1]), state).cleanup()
        return 0
    if len(args) == 3 and args[0] == "unit":
        data = sys.stdin.buffer.read((512 << 10) + 1)
        if len(data) > 512 << 10:
            raise LabError("unit envelope too large")
        launch_unit(Path(args[1]), args[2], json.loads(data))
        return 0
    raise LabError("invalid lab supervisor arguments")


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (LabError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        # Never echo arbitrary subprocess output or caller-supplied payloads.
        print("VM lab failed safely:", type(error).__name__, file=sys.stderr)
        sys.exit(1)

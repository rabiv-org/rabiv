"""Unprivileged regression tests; all account/systemd operations are mocked."""

import contextlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import signal
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("vm_lab", Path(__file__).with_name("vm_lab.py"))
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)
spec = importlib.util.spec_from_file_location("vm_receive", Path(__file__).with_name("vm_receive.py"))
receiver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receiver)


def result(stdout="", code=0):
    return SimpleNamespace(stdout=stdout, returncode=code)


class LabTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.control = Path(self.temp.name)
        self.root = self.control / "data"
        self.root.mkdir()
        self.unit = {"name": "rabiv-worker-example-probe", "nonce": "b"*64,
                     "invocation": "", "status": "pending"}
        self.state = {"version": 1, "owner": "a"*32, "root": str(self.root),
                      "identities": [], "baseline_uids": [], "units": {"probe": self.unit}}
        self.calls = []

    def properties(self, nonce=None, invocation=None):
        return result("LoadState=loaded\nActiveState=active\nInvocationID=" +
                      (invocation or "c"*32) + "\nSyslogIdentifier=rabiv-vm-" + (nonce or "b"*64) + "\n")

    def test_legacy_description_collision_is_not_ownership(self):
        def command(args):
            self.calls.append(args)
            p = self.properties(nonce="d"*64)
            p.stdout += "Description="+self.unit["name"]+"\n"
            self.assertEqual(self.unit["name"], dict(line.split("=", 1) for line in p.stdout.splitlines())["Description"])
            return p
        with self.assertRaises(lab.LabError):
            lab.Lab(self.control, self.state, command).stop_unit(self.unit)
        self.assertFalse(any("stop" in args for args in self.calls))

    def test_partial_unit_start_is_recovered_and_recovery_is_idempotent(self):
        outputs = [self.properties(), self.properties(), result(), result("LoadState=not-found\n")]
        def command(args):
            self.calls.append(args)
            return outputs.pop(0)
        manager = lab.Lab(self.control, self.state, command)
        manager.stop_unit(self.unit)
        self.assertEqual("c"*32, self.unit["invocation"])
        manager.stop_unit(self.unit)
        self.assertEqual(1, sum("stop" in args for args in self.calls))
        self.assertEqual("gone", self.unit["status"])

    def test_changed_invocation_refuses_stop(self):
        self.unit["invocation"] = "e"*32
        def command(args):
            self.calls.append(args)
            return self.properties()
        with self.assertRaises(lab.LabError):
            lab.Lab(self.control, self.state, command).stop_unit(self.unit)
        self.assertFalse(any("stop" in args for args in self.calls))

    def test_replacement_between_queries_refuses_stop(self):
        outputs = [self.properties(), self.properties(invocation="f"*32)]
        def command(args):
            self.calls.append(args)
            return outputs.pop(0)
        with self.assertRaises(lab.LabError):
            lab.Lab(self.control, self.state, command).stop_unit(self.unit)
        self.assertFalse(any("stop" in args for args in self.calls))

    def test_preexisting_unit_is_never_started_or_stopped(self):
        self.unit["status"] = "planned"
        def command(args):
            self.calls.append(args)
            return self.properties(nonce="d"*64)
        with patch.object(lab, "locked", return_value=contextlib.nullcontext(self.state)), patch.object(lab, "command", command):
            with self.assertRaises(lab.LabError):
                lab.launch_unit(self.control, "probe", {})
        self.assertEqual("rejected", self.unit["status"])
        lab.Lab(self.control, self.state, command).stop_unit(self.unit)
        self.assertFalse(any("stop" in args or "systemd-run" in args for args in self.calls))

    def test_preexisting_account_is_not_adopted(self):
        def command(args):
            self.calls.append(args)
            return result("existing:x:123:456:old:/nonexistent:/usr/sbin/nologin\n")
        manager = lab.Lab(self.control, self.state, command)
        with self.assertRaises(lab.LabError):
            manager.create("user", "existing", 456)
        self.assertEqual([], self.state["identities"])
        self.assertEqual(1, len(self.calls))

    def test_uncertain_creation_never_deletes_an_identity(self):
        self.unit["status"] = "planned"
        self.state["identities"] = [{"kind": "group", "name": "unacknowledged", "id": None, "status": "pending"}]
        with self.assertRaises(lab.LabError):
            lab.Lab(self.control, self.state, lambda args: self.fail("unsafe identity lookup/removal")).cleanup()
        self.assertEqual(0o700, stat.S_IMODE(self.root.stat().st_mode))
        self.assertTrue(self.state["cleanup_errors"])

    def test_changed_uid_refuses_kill_and_delete(self):
        def command(args):
            self.calls.append(args)
            return result("owned:x:999:456:RABIV-VM-" + self.state["owner"] + ":/nonexistent:/usr/sbin/nologin\n")
        entry = {"kind": "user", "name": "owned", "id": 123, "gid": 456, "status": "created"}
        with self.assertRaises(lab.LabError):
            lab.Lab(self.control, self.state, command).remove_identity(entry)
        self.assertEqual(1, len(self.calls))

    def test_created_identity_cleanup_is_idempotent(self):
        entry = {"kind": "group", "name": "owned", "id": 456, "status": "created"}
        responses = [result("owned:x:456:\n"), result()]
        def command(args):
            self.calls.append(args)
            return responses.pop(0)
        manager = lab.Lab(self.control, self.state, command)
        manager.remove_identity(entry)
        manager.remove_identity(entry)
        self.assertEqual("gone", entry["status"])
        self.assertEqual(1, sum(args[0] == "groupdel" for args in self.calls))

    def test_journal_private_and_atomic_from_creation(self):
        previous = os.umask(0)
        try:
            lab.save(self.control, self.state)
            path = self.control / "state.json"
            self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
            self.assertEqual(self.state, json.loads(path.read_text()))
            self.assertFalse(list(self.control.glob(".state-*")))
        finally:
            os.umask(previous)

    def test_provisioning_modes_counts(self):
        owner = self.state["owner"]
        groups, users = {}, {}
        bundle = self.control / "bundle"
        bundle.mkdir()
        for name in ("acquisition.test", "rabiv-ingestor"):
            (bundle / name).write_bytes(b"reviewed fixture, never executed")
        def command(args):
            self.calls.append(args)
            name = args[-1]
            if args[0] == "getent":
                entries = groups if args[1] == "group" else users
                return result(entries[name]+"\n") if name in entries else result(code=2)
            if args[0] == "groupadd":
                groups[name] = f"{name}:x:{500+len(groups)}:"
            if args[0] == "useradd":
                gid = args[args.index("--gid")+1]
                users[name] = f"{name}:x:{600+len(users)}:{gid}:RABIV-VM-{owner}:/nonexistent:/usr/sbin/nologin"
            return result()
        previous = os.umask(0o077)
        try:
            with patch.object(lab.os, "chown"):
                config = lab.provision(lab.Lab(self.control, self.state, command), bundle, "/fixture/syft", lambda: False)
        finally:
            os.umask(previous)
        self.assertEqual(6, len(users))
        self.assertEqual(13, len(groups))
        self.assertEqual(7, len(config["Channels"]))
        for path in config["Channels"].values():
            self.assertEqual(0o444, stat.S_IMODE(Path(path).stat().st_mode))
            root = Path(json.loads(Path(path).read_text())["root_dir"])
            self.assertEqual(0o755, stat.S_IMODE(root.stat().st_mode))
            self.assertEqual(0o700, stat.S_IMODE((root/"staging").stat().st_mode))
            self.assertEqual(0o2750, stat.S_IMODE((root/"committed").stat().st_mode))

    def test_supervisor_recovers_after_success_failure_or_exception(self):
        for outcome in (0, 7, 124, 143, lab.LabError("provisioning failure")):
            with self.subTest(outcome=str(outcome)), tempfile.TemporaryDirectory() as directory:
                base = Path(directory) / "lab"
                fake = SimpleNamespace(returncode=0)
                with patch.object(lab, "BASE", base), patch.object(lab, "trusted"), patch.object(lab, "verify_acl"), patch.object(lab, "begin_recovery"), patch.object(lab, "baseline_uids", return_value=[]), \
                     patch.object(lab, "provision", side_effect=outcome if isinstance(outcome, Exception) else None), \
                     patch.object(lab.subprocess, "Popen"), patch.object(lab, "wait_child", return_value=outcome), \
                     patch.object(lab, "run_recovery", return_value=0) as recover:
                    if isinstance(outcome, Exception):
                        with self.assertRaises(lab.LabError):
                            lab.run_lab(Path(directory), "/test/syft")
                    else:
                        self.assertEqual(outcome, lab.run_lab(Path(directory), "/test/syft"))
                    self.assertEqual(1, recover.call_count)
                    control = next(base.glob("control.*"))
                    self.assertEqual(0o700, stat.S_IMODE(control.stat().st_mode))
                    self.assertEqual(0o600, stat.S_IMODE((control / "report.txt").stat().st_mode))
                    self.assertEqual(0o700, stat.S_IMODE(next(base.glob("run.*")).stat().st_mode))

    def test_wait_child_handles_normal_failure_timeout_and_cancellation(self):
        for program, cancellation, seconds, expected in (("pass", 0, 3, 0),
                ("raise SystemExit(7)", 0, 3, 7),
                ("import time; time.sleep(10)", 0, 0, 124),
                ("import time; time.sleep(10)", 143, 3, 143)):
            with self.subTest(expected=expected):
                child = subprocess.Popen([sys.executable, "-c", program], start_new_session=True)
                self.assertEqual(expected, lab.wait_child(child, lambda: cancellation, seconds))

    def test_real_signals_request_external_recovery(self):
        real_popen = subprocess.Popen
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=signum), tempfile.TemporaryDirectory() as directory:
                base = Path(directory) / "lab"
                program = Path(directory) / "acquisition.test"
                program.write_text("#!/usr/bin/python3\nimport time\ntime.sleep(10)\n")
                program.chmod(0o700)
                timers = []
                def start(*args, **kwargs):
                    child = real_popen(*args, **kwargs)
                    timer = threading.Timer(0.05, lambda: os.kill(os.getpid(), signum))
                    timers.append(timer)
                    timer.start()
                    return child
                with patch.object(lab, "BASE", base), patch.object(lab, "trusted"), patch.object(lab, "verify_acl"), \
                     patch.object(lab, "begin_recovery"), patch.object(lab, "baseline_uids", return_value=[]), \
                     patch.object(lab, "provision"), patch.object(lab.subprocess, "Popen", side_effect=start), \
                     patch.object(lab, "run_recovery", return_value=0) as recover:
                    self.assertEqual(128+signum, lab.run_lab(Path(directory), "/fixture/syft"))
                    self.assertEqual(1, recover.call_count)
                for timer in timers:
                    timer.join()

    def test_failed_create_does_not_adopt_partial_or_foreign_identity(self):
        responses = [result(code=2), result(code=9)]
        def command(args):
            self.calls.append(args)
            return responses.pop(0)
        manager = lab.Lab(self.control, self.state, command)
        with self.assertRaises(lab.LabError):
            manager.create("group", "candidate")
        entry = self.state["identities"][0]
        self.assertEqual("uncertain", entry["status"])
        with self.assertRaises(lab.LabError):
            manager.remove_identity(entry)
        self.assertEqual(2, len(self.calls))

    def test_nss_lookup_failure_is_not_absence(self):
        manager = lab.Lab(self.control, self.state, lambda args: result(code=1))
        with self.assertRaises(lab.LabError):
            manager.create("group", "candidate")
        self.assertFalse(self.state["identities"])

    def test_cancellation_before_creation_never_issues_mutation(self):
        calls = []
        cancellation = [False]
        def command(args):
            calls.append(args)
            cancellation[0] = True
            return result(code=2)
        with self.assertRaises(lab.LabError):
            lab.Lab(self.control, self.state, command).create("group", "candidate", cancelled=lambda: cancellation[0])
        self.assertEqual(1, len(calls))
        self.assertFalse(self.state["identities"])

    def test_journal_cannot_select_an_unrelated_account(self):
        self.state["root"] = str(lab.BASE / "run.example")
        self.state["units"] = {slot: {"name": "rabiv-worker-"+self.state["owner"]+"-"+slot,
                                      "nonce": "b"*64} for slot in ("probe", "worker")}
        self.state["identities"] = [{"kind": "user", "name": "root", "id": 0}]
        with self.assertRaises(lab.LabError):
            lab.validate_state(self.state)


class ReceiverTests(unittest.TestCase):
    def archive(self, change=None, extra=None):
        import hashlib
        import io
        import tarfile
        payload = {name: b"reviewed content" for name in receiver.FILES}
        payload["SOURCE_COMMIT"] = b"a"*40 + b"\n"
        elf = bytearray(20)
        elf[:6] = b"\x7fELF\x02\x01"
        elf[18:20] = b"\x3e\x00"
        for name in receiver.BINARIES:
            payload[name] = bytes(elf)
        payload["SHA256SUMS"] = "".join(hashlib.sha256(data).hexdigest()+"  "+name+"\n"
                                       for name, data in sorted(payload.items()) if name != "SHA256SUMS").encode()
        if change:
            change(payload)
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w:gz") as archive:
            for name, data in payload.items():
                member = tarfile.TarInfo("./"+name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            if extra:
                archive.addfile(extra)
        data = raw.getvalue()
        return data, hashlib.sha256(data).hexdigest()

    def test_exact_payload_and_private_installation(self):
        data, digest = self.archive()
        payload = receiver.verified_payload(data, digest)
        with tempfile.TemporaryDirectory() as directory:
            previous = os.umask(0)
            try:
                root = receiver.install_payload(payload, directory)
            finally:
                os.umask(previous)
            self.assertEqual(0o700, stat.S_IMODE(root.stat().st_mode))
            self.assertEqual(receiver.FILES, {p.name for p in root.iterdir()})
            for p in root.iterdir():
                self.assertEqual(0o555 if p.name in receiver.BINARIES else 0o444, stat.S_IMODE(p.stat().st_mode))

    def test_wrong_archive_or_payload_hash_refused(self):
        data, digest = self.archive()
        with self.assertRaises(receiver.ReceiveError):
            receiver.verified_payload(data, "0"*64)
        data, digest = self.archive(lambda files: files.update({"BUILDINFO": b"tampered"}))
        with self.assertRaises(receiver.ReceiveError):
            receiver.verified_payload(data, digest)

    def test_paths_links_duplicates_and_unapproved_components_refused(self):
        import tarfile
        for name, kind in (("../escape", tarfile.REGTYPE), ("/absolute", tarfile.REGTYPE),
                           ("./vm_lab.py", tarfile.SYMTYPE), ("./BUILDINFO", tarfile.REGTYPE),
                           ("./unexpected.sh", tarfile.REGTYPE)):
            with self.subTest(name=name):
                member = tarfile.TarInfo(name)
                member.type = kind
                if kind == tarfile.SYMTYPE:
                    member.linkname = "/etc/passwd"
                data, digest = self.archive(extra=member)
                with self.assertRaises(receiver.ReceiveError):
                    receiver.verified_payload(data, digest)

    def test_manifest_must_cover_all_payload(self):
        data, digest = self.archive(lambda files: files.update({"SHA256SUMS": b""}))
        with self.assertRaises(receiver.ReceiveError):
            receiver.verified_payload(data, digest)


if __name__ == "__main__":
    unittest.main(verbosity=2)

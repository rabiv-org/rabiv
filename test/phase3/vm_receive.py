#!/usr/bin/python3
"""Install one owner-approved bundle as data. Does not execute its contents."""

import hashlib
import io
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile

FILES = {"BUILDINFO", "SOURCE_COMMIT", "SHA256SUMS", "source.tar",
         "rabiv-ingestor", "acquisition.test", "run-vm-security.sh", "vm_lab.py", "vm_receive.py"}
BINARIES = {"rabiv-ingestor", "acquisition.test"}


class ReceiveError(Exception):
    pass


def verified_payload(data, expected):
    if not re.fullmatch(r"[a-f0-9]{64}", expected) or len(data) > 32 << 20 or hashlib.sha256(data).hexdigest() != expected:
        raise ReceiveError("archive hash/size mismatch")
    payload = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive:
            if member.name in (".", "./") and member.isdir():
                continue
            name = member.name[2:] if member.name.startswith("./") else member.name
            if name not in FILES or name in payload or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or member.sparse or member.size > 32 << 20:
                raise ReceiveError("unexpected/duplicate/unsafe archive member")
            payload[name] = archive.extractfile(member).read()
    if set(payload) != FILES:
        raise ReceiveError("incomplete bundle")
    manifest = {}
    for line in payload["SHA256SUMS"].decode("ascii").splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9_.-]+)", line)
        if not match or match[2] in manifest:
            raise ReceiveError("invalid checksum manifest")
        manifest[match[2]] = match[1]
    if set(manifest) != FILES - {"SHA256SUMS"}:
        raise ReceiveError("manifest does not cover exact payload")
    if any(hashlib.sha256(payload[name]).hexdigest() != digest for name, digest in manifest.items()):
        raise ReceiveError("payload checksum mismatch")
    if not re.fullmatch(rb"[a-f0-9]{40}\n", payload["SOURCE_COMMIT"]):
        raise ReceiveError("invalid source commit")
    for name in BINARIES:
        header = payload[name][:20]
        if header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\x3e\x00":
            raise ReceiveError("expected Linux amd64 ELF")
    return payload


def install_payload(payload, parent):
    directory = Path(tempfile.mkdtemp(prefix="rabiv-phase3-reviewed.", dir=parent))
    for name, data in payload.items():
        fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
            os.fchmod(f.fileno(), 0o555 if name in BINARIES else 0o444)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return directory


def root_path(path):
    for p in (path, *path.parents):
        info = p.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ReceiveError("untrusted receiver/install path")


def main(args):
    os.umask(0o077)
    if os.getuid() != 0 or os.geteuid() != 0 or len(args) != 2:
        raise ReceiveError("usage: root-owned receiver ARCHIVE EXPECTED_SHA256")
    root_path(Path(__file__))
    root_path(Path("/var/lib"))
    release = Path("/etc/os-release").read_text()
    virt = subprocess.run(["/usr/bin/systemd-detect-virt", "--vm"], capture_output=True, text=True, timeout=5, check=False)
    fs = subprocess.run(["/usr/bin/findmnt", "-n", "-o", "FSTYPE", "-T", "/var/lib"], capture_output=True, text=True, timeout=5, check=False)
    if 'ID=ubuntu\n' not in release or 'VERSION_ID="24.04"' not in release or virt.returncode != 0 or virt.stdout.strip() not in ("kvm", "qemu") or fs.returncode != 0 or fs.stdout.strip() != "ext4":
        raise ReceiveError("dedicated Ubuntu 24.04 KVM/guest ext4 required")
    fd = os.open(args[0], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 32 << 20:
            raise ReceiveError("archive must be a bounded regular file")
        data = f.read((32 << 20) + 1)
    # Hash pinned bytes, not a path that can be substituted after verification.
    payload = verified_payload(data, args[1])
    if payload["vm_receive.py"] != Path(__file__).read_bytes():
        raise ReceiveError("receiver differs from reviewed bundle")
    print(install_payload(payload, Path("/var/lib")))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (ReceiveError, OSError, ValueError, UnicodeError, tarfile.TarError, subprocess.SubprocessError):
        print("Bundle receiver refused input; no execution performed", file=sys.stderr)
        sys.exit(1)

"""Archive a finished raw campaign, including partial attempts and pcaps, without overwriting prior files."""

from __future__ import annotations
import argparse
import gzip
import hashlib
import io
import os
import tarfile
import tempfile
from pathlib import Path


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def publish(temp, final):
    try:
        os.link(temp, final)
    except FileExistsError:
        if digest(temp) != digest(final):
            raise ValueError(f"existing file differs: {final}")


def seal(source, dest):
    source = source.resolve()
    dest = dest.resolve()
    if source == dest or source in dest.parents:
        raise ValueError("archives must be written outside the campaign")
    if not source.is_dir() or not (source / "plan.json").is_file():
        raise ValueError("missing campaign and plan")
    dest.mkdir(parents=True, exist_ok=True)
    files = sorted(path for path in source.rglob("*") if path.is_file())
    if any(p.is_symlink() for p in files):
        raise ValueError("unexpected symlink in acquisition")
    with tempfile.TemporaryDirectory(prefix="checkpoint-seal.", dir=dest) as staging:
        root = Path(staging)
        manifest = {p.relative_to(source).as_posix(): digest(p) for p in files}
        manifest_bytes = "".join(f"{d}  {name}\n" for name, d in manifest.items()).encode()
        m = root / "raw.sha256"
        m.write_bytes(manifest_bytes)
        temp = root / "raw.tar.gz"
        with (
            temp.open("wb") as f,
            gzip.GzipFile(filename="", fileobj=f, mode="wb", mtime=0, compresslevel=1) as gz,
            tarfile.open(fileobj=gz, mode="w|") as tar,
        ):
            for p in files:
                entry = tar.gettarinfo(p, arcname=f"{source.name}/{p.relative_to(source).as_posix()}")
                entry.uid = entry.gid = 0
                entry.uname = entry.gname = ""
                entry.mtime = 0
                with p.open("rb") as stream:
                    tar.addfile(entry, stream)
            entry = tarfile.TarInfo("manifest/raw.sha256")
            entry.size = len(manifest_bytes)
            tar.addfile(entry, io.BytesIO(manifest_bytes))
        verified = set()
        with tarfile.open(temp, "r|gz") as tar:
            for entry in tar:
                if entry.name == "manifest/raw.sha256":
                    assert tar.extractfile(entry).read() == manifest_bytes
                    continue
                prefix, name = entry.name.split("/", 1)
                assert entry.isfile() and prefix == source.name and name not in verified
                with tar.extractfile(entry) as stream:
                    actual = hashlib.file_digest(stream, "sha256").hexdigest()
                if actual != manifest[name]:
                    raise ValueError(f"restore checksum failed for {name}")
                verified.add(name)
        assert verified == manifest.keys()
        raw_sha = digest(temp)
        m_sha = digest(m)
        final = dest / f"{source.name}-raw-{raw_sha}.tar.gz"
        final_m = dest / f"{source.name}-raw-manifest-{m_sha}.sha256"
        publish(temp, final)
        publish(m, final_m)
        print(
            f"{raw_sha}  {final}\n{m_sha}  {final_m}\n"
            f"{len(verified)} verified files; {sum(p.stat().st_size for p in files)} source bytes; {final.stat().st_size} archive bytes"
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    parser.add_argument("archive_directory", type=Path)
    args = parser.parse_args()
    seal(args.campaign, args.archive_directory)

"""Restore and authenticate the five M2 capture-free campaign archives."""

import argparse
import contextlib
import hashlib
import json
import re
import shutil
import sys
import tarfile
from pathlib import Path, PurePosixPath

RESULTS = Path(__file__).resolve().parents[1]
CAMPAIGNS = {
    "checkpoint": ("m2-checkpoint", "m2-checkpoint", "", 1600),
    "bbr": (
        "m2-bbr", "smoke-769311e-a1",
        "m2c-bbr-smoke-769311e-verification-a1", 100,
    ),
    "ablation": ("m2-ablation", "m2d-ablation", "", 1400),
    "matrix": ("m2-matrix", "m2-matrix", "", 10844),
    "multiflow": ("m2-multiflow", "m2d-multiflow", "", 6497),
}


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def verify(path, expected):
    if sha256(path) != expected:
        raise ValueError(f"SHA-256 mismatch: {path}")
    print(f"{expected}  {path}", flush=True)


def read_manifest(path):
    entries = {}
    for line in path.read_text().splitlines():
        checksum, name = line.split("  ", 1)
        name = name.removeprefix("./")
        if (
            not re.fullmatch(r"[a-f0-9]{64}", checksum)
            or name in entries
            or not safe_path(name)
        ):
            raise ValueError(f"invalid manifest entry in {path}: {line}")
        entries[name] = checksum
    return entries


def safe_path(name):
    path = PurePosixPath(name)
    return (
        bool(path.parts)
        and not path.is_absolute()
        and ".." not in path.parts
        and str(path) == name
    )


def capture_path(name):
    return any(suffix.lower() in {".pcap", ".pcapng", ".cap"} for suffix in PurePosixPath(name).suffixes)


def extract(archive, output, campaign, allowed_manifests=()):
    output.mkdir()
    seen = set()
    with contextlib.ExitStack() as resources:
        if archive.name.endswith(".tar.zst"):
            from compression import zstd

            stream = resources.enter_context(zstd.open(archive, "rb"))
            tar = resources.enter_context(tarfile.open(fileobj=stream, mode="r|"))
        else:
            tar = resources.enter_context(tarfile.open(archive, mode="r|gz"))
        for member in tar:
            name = member.name
            if (
                not member.isfile()
                or not safe_path(name)
                or name in seen
                or capture_path(name)
                or not (name.startswith(campaign + "/") or name in allowed_manifests)
            ):
                raise ValueError(f"unexpected compact archive member: {name}")
            seen.add(name)
            target = output / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with tar.extractfile(member) as source, target.open("xb") as dest:
                shutil.copyfileobj(source, dest, length=1024 * 1024)
    return seen


def check_files(campaign, manifest, observed, count):
    if len(manifest) != count or set(manifest) != observed:
        raise ValueError(f"restored file set differs from manifest: {campaign}")
    for name, checksum in manifest.items():
        path = campaign / name
        if sha256(path) != checksum:
            raise ValueError(f"SHA-256 mismatch: {path}")


def copy_plan(source, target, checksum):
    verify(source, checksum)
    with target.open("xb") as dest, source.open("rb") as original:
        shutil.copyfileobj(original, dest)
    verify(target, checksum)


def restore_paired(choice, data, work, archive_dir, result, name, count, plans):
    manifest_file = "ARCHIVES.sha256" if choice == "bbr" else "archives.sha256"
    archives = read_manifest(result / manifest_file)
    (analysis,) = [
        filename for filename in archives
        if filename == "analysis.tar.gz" or "-analysis-" in filename
    ]
    (raw_manifest,) = [filename for filename in archives if "-raw-manifest-" in filename]
    verify(archive_dir / analysis, archives[analysis])
    verify(archive_dir / raw_manifest, archives[raw_manifest])
    raw = read_manifest(archive_dir / raw_manifest)
    unpacked = work / "restored"
    members = extract(archive_dir / analysis, unpacked, name)
    campaign = unpacked / name
    manifest = read_manifest(campaign / "MANIFEST.sha256")
    observed = {member.removeprefix(name + "/") for member in members}
    observed.remove("MANIFEST.sha256")
    check_files(campaign, manifest, observed, count)
    if choice == "matrix":
        verify(campaign / "plan.json", raw["plan.json"])
    else:
        # Bind the omitted plan to the Git-pinned full manifest without
        # opening a capture archive.
        source = (
            plans / choice / "plan.json"
            if plans
            else data / "m2" / ("m2c-bbr" if choice == "bbr" else "") / name / "plan.json"
        )
        supplement = work / "plan-supplement" / choice
        supplement.mkdir(parents=True)
        copy_plan(source, supplement / "plan.json", raw["plan.json"])
        (supplement / "SHA256SUMS").write_text(f"{raw['plan.json']}  plan.json\n")
        copy_plan(supplement / "plan.json", campaign / "plan.json", raw["plan.json"])
    return campaign


def restore_multiflow(work, archive_dir, result, name, count):
    receipt = json.loads((result / "measured/archive-replay.json").read_bytes())
    compact = receipt["archives"]["compact"]
    if count != compact["files"]:
        raise ValueError("compact file count differs from the published receipt")
    archive = archive_dir / compact["name"]
    if archive.stat().st_size != compact["archive_bytes"]:
        raise ValueError(f"size differs from published receipt: {archive}")
    verify(archive, compact["sha256"])
    unpacked = work / "restored"
    contents = "manifest/contents.sha256"
    source = "manifest/source.sha256"
    members = extract(archive, unpacked, name, (contents, source))
    members.difference_update({contents, source})
    verify(unpacked / contents, compact["manifest_sha256"])
    verify(unpacked / source, receipt["archives"]["full"]["manifest_sha256"])
    manifest = read_manifest(unpacked / contents)
    full = read_manifest(unpacked / source)
    if manifest != {path: sha for path, sha in full.items() if not capture_path(path)}:
        raise ValueError("compact set differs from non-capture source set")
    campaign = unpacked / name
    check_files(campaign, manifest, {m.removeprefix(name + "/") for m in members}, count)
    return campaign


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", choices=CAMPAIGNS)
    parser.add_argument("data", type=Path, help="read-only original volume mount")
    parser.add_argument("work", type=Path, help="existing fresh private working directory")
    parser.add_argument("--plans", type=Path, help="read-only directory of saved plan supplements")
    args = parser.parse_args()
    data, work = args.data.resolve(), args.work.resolve()
    if work == data or data in work.parents or work in data.parents or any(work.iterdir()):
        parser.error("working directory must be empty and separate from the input mount")
    result_name, name, subdir, count = CAMPAIGNS[args.campaign]
    archive_dir, result = data / "m2/archive" / subdir, RESULTS / result_name
    if args.campaign == "multiflow":
        campaign = restore_multiflow(work, archive_dir, result, name, count)
    else:
        campaign = restore_paired(
            args.campaign, data, work, archive_dir, result, name, count, args.plans
        )
    print(f"Verified {count} compact inputs in {campaign}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, tarfile.TarError) as e:
        sys.exit(str(e))

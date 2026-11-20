"""Package all non-packet acquisition inputs, optional wire-derived receipts and their digests.

Usage: compact.py CAMPAIGN OUTPUT.tar.gz [--physical DIRECTORY]
The normal frozen analyze.py tables --archive consumer reads this archive directly.
"""

import argparse
import gzip
import hashlib
import io
import tarfile
from pathlib import Path


def write_archive(
    campaign, output, physical, source_manifest, loss_inputs, queue_inputs=None
):
    if not (campaign / "plan.json").is_file() or output.exists():
        raise ValueError("expected a campaign with a plan and a new archive path")
    files = {}
    for path in sorted(campaign.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"unexpected symlink {path}")
        if path.is_file() and path.suffix != ".pcap":
            files[path.relative_to(campaign).as_posix()] = path
    if physical is not None:
        for path in sorted(physical.iterdir()):
            if (
                not path.is_file()
                or path.is_symlink()
                or path.suffix not in (".csv", ".json")
            ):
                raise ValueError(f"unexpected physical receipt {path}")
            name = "physical-replay/" + path.name
            if name in files:
                raise ValueError(f"duplicate entry {name}")
            files[name] = path
    if loss_inputs:
        for path in sorted(loss_inputs.iterdir()):
            if (
                not path.is_file()
                or path.is_symlink()
                or not (path.name == "index.csv" or path.name.endswith(".csv.gz"))
            ):
                raise ValueError(f"unexpected Linux loss input {path}")
            name = "wire-loss-inputs/" + path.name
            if name in files:
                raise ValueError(f"duplicate entry {name}")
            files[name] = path
    if queue_inputs:
        for path in sorted(queue_inputs.iterdir()):
            if (
                not path.is_file()
                or path.is_symlink()
                or not path.name.endswith(".json.gz")
            ):
                raise ValueError(f"unexpected paired-queue projection {path}")
            name = "wire-queue-inputs/" + path.name
            if name in files:
                raise ValueError(f"duplicate entry {name}")
            files[name] = path
    if source_manifest:
        if "source-manifest.sha256" in files:
            raise ValueError("reserved source manifest name")
        files["source-manifest.sha256"] = source_manifest
    if "MANIFEST.sha256" in files:
        raise ValueError("reserved manifest name")
    manifest = []
    with (
        output.open("xb") as raw,
        gzip.GzipFile(
            filename="", fileobj=raw, mode="wb", mtime=0, compresslevel=1
        ) as gz,
        tarfile.open(fileobj=gz, mode="w|") as archive,
    ):
        for name, path in sorted(files.items()):
            info = tarfile.TarInfo(f"{campaign.name}/{name}")
            info.size = path.stat().st_size
            with path.open("rb") as fh:
                digest = hashlib.file_digest(fh, "sha256").hexdigest()
                fh.seek(0)
                archive.addfile(info, fh)
            manifest.append(f"{digest}  {name}\n")
        contents = "".join(manifest).encode()
        info = tarfile.TarInfo(f"{campaign.name}/MANIFEST.sha256")
        info.size = len(contents)
        archive.addfile(info, io.BytesIO(contents))
    print(len(files), "verified input hashes recorded in manifest")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--physical", type=Path)
    parser.add_argument("--source-manifest", type=Path)
    parser.add_argument("--loss-inputs", type=Path)
    parser.add_argument("--queue-inputs", type=Path)
    args = parser.parse_args()
    write_archive(
        args.campaign,
        args.output,
        args.physical,
        args.source_manifest,
        args.loss_inputs,
        args.queue_inputs,
    )

"""Authenticate the two historical M2 freeze, gate and concurrency-proof families."""

import argparse
import json
import sys
from pathlib import Path

from replay_archive import capture_path, read_manifest, safe_path, sha256, verify

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "tools/m2"))
import analyze
import matrix

INTEGRATE = "3f48c30dbf70240d50234f095eaca6de24fc0625"
INTEGRATE_KEY = "cd50db51c944442c8f1158f6b5e48f01ab3f913d9b96034a675af9a8aed9c1fd"
BBR = "769311e157dea0e7983a2cd5bd086736339dc62b"
BBR_KEY = "f0ecf3e4882789e261bb9fa8a3da91adf519b7b0f8f2c8d9b8dbfee286c1013e"


def load(path):
    return json.loads(path.read_bytes())


def check_files(root, entries):
    for relative, checksum in entries.items():
        path = root / relative
        if not safe_path(relative) or capture_path(relative) or path.resolve() != path:
            raise ValueError(f"unexpected capture, linked or non-relative input: {path}")
        if sha256(path) != checksum:
            raise ValueError(f"SHA-256 mismatch: {path}")


def check_gate(path, freeze, slot, key):
    gate = load(path)
    if (
        gate["static"] != freeze["static"]
        or gate["cpusets"] != freeze["slots"][str(slot)]["cpus"]
        or matrix.gate_rejects(gate, slot, key) is not None
    ):
        raise ValueError(f"unexpected gate receipt: {path}")
    durations = {
        f"{row['run']}/summary.json": matrix.default_duration(row.get("rtt", 20))
        for row in gate["items"] if row.get("run") and row["item"] != 1
    }
    for relative, expected in gate["sources"].items():
        source = load(path.parent / relative)
        if analyze.proof_meta_digest(source) != expected:
            raise ValueError(f"gate input fingerprint mismatch: {relative}")
        if relative in durations and matrix.measured_transfer_window(source, durations[relative]) is None:
            raise ValueError(f"invalid gate measurement window: {relative}")
    print(f"67/67 checks and 62 verified source fingerprints in {path}")


def check_proof(path, freeze, key):
    proof = load(path)
    if (
        proof["passed"] is not True
        or not all(item["ok"] is True for item in proof["items"])
        or proof["evidence_errors"]
        or len(proof["valid_runs"]) != 15
        or not all(valid is True for valid in proof["valid_runs"].values())
        or len(proof["stack_overlap"]) != 5
    ):
        raise ValueError(f"unexpected proof receipt: {path}")
    for relative in proof["valid_runs"]:
        if not safe_path(relative):
            raise ValueError(f"non-relative proof run: {relative}")
        meta = load(path.parent / relative / "meta.json")
        if meta["reuse_key"] != key or any(
            meta[name] != value for name, value in freeze["static"].items()
        ):
            raise ValueError(f"proof run runtime mismatch: {relative}")
    root = path.parent
    sources = {
        source.relative_to(root).as_posix(): load(source)
        for pattern in ("proof-config.json", "*/*/ping.json", "*/*/meta.json", "*/*/summary.json")
        for source in root.glob(pattern)
    }
    if len(sources) != 31:
        raise ValueError(f"expected the 31 CUBIC proof inputs: {path}")
    config = matrix.proof_config(5, (), "cubic")
    if any(sources["proof-config.json"].get(name) != v for name, v in config.items()):
        raise ValueError(f"unexpected proof configuration: {path}")
    fresh = matrix.proof_evaluate(sources, proof["campaign"], 5, (), "cubic")
    if json.dumps(fresh, sort_keys=True) != json.dumps(proof, sort_keys=True):
        raise ValueError(f"recomputed concurrency proof differs: {path}")
    print(f"15 valid same-runtime transfers and five overlapping pairs in {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("data", type=Path, help="read-only volume mount")
    data = parser.parse_args().data.resolve(strict=True)
    for name, expected in read_manifest(HERE / "m2-qualification-inputs.sha256").items():
        path = data / name
        verify(path, expected)
        if path.name == "MANIFEST.sha256":
            members = read_manifest(path)
            check_files(path.parent, members)
            print(f"{len(members)} manifest members verified in {path.parent.name}")

    archives = data / "m2/archive"
    for stage in ("calib-a1-s0", "calib-a1-s1", "proof-a1-cubic"):
        integrate = f"m2-integrate-{INTEGRATE}-{stage}"
        closure = archives / f"m2-integrate-{INTEGRATE}-final-closure-a1"
        row = load(closure / "raw-index.json")["campaigns"][stage]
        for filename, checksum in row["sha256"].items():
            if filename == "physical-replay.json":
                root = archives / f"{integrate}-physical-a1"
            elif filename in ("gate.json", "proof.json"):
                root = data / "m2/m2-integrate" / f"{INTEGRATE}-{stage}"
            else:
                root = archives / f"{integrate}-audit-1"
            verify(root / filename, checksum)

    for directory, namespace, commit, short, key in (
        (f"m2-integrate-{INTEGRATE}-final-freeze-a1", "m2-integrate", INTEGRATE, INTEGRATE, INTEGRATE_KEY),
        ("m2c-bbr-769311e-topology-a1", "m2c-bbr", BBR, "769311e", BBR_KEY),
    ):
        frozen = load(archives / directory / "freeze.json")
        if (
            frozen["static"]["commit"] != commit
            or set(frozen["slots"]) != {"0", "1"}
            or any(entry["reuse_key"] != key for entry in frozen["slots"].values())
        ):
            raise ValueError(f"unexpected runtime freeze: {directory}")
        for slot in (0, 1):
            check_gate(data / "m2" / namespace / f"{short}-calib-a1-s{slot}/gate.json", frozen, slot, key)
        check_proof(data / "m2" / namespace / f"{short}-proof-a1-cubic/proof.json", frozen, key)


if __name__ == "__main__":
    main()

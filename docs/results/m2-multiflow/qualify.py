#!/usr/bin/env python3
"""Acquire and reopen both gates and the fifteen-transfer proof on the frozen runtime."""

import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools/m2"))
import multiflow as mf
import matrix as m


def topology(slot_n):
    names = set(m.sh(["docker", "ps", "--format", "{{.Names}}"]).splitlines())
    expected = {f"{m.PREFIX}-s{slot_n}-{role}" for role in ("snd", "r1", "r2", "rcv")}
    if not expected & names:
        log = m.tb("up.sh", "--slot", slot_n)
    elif expected <= names:
        log = m.tb("record.sh", "--slot", slot_n, "resume")
    else:
        raise RuntimeError(f"partial prior topology on slot {slot_n}")
    slot = m.Slot(slot_n)
    for container in slot.containers().values():
        mounts = json.loads(m.sh(["docker", "inspect", container]))[0]
        mounted = [x["Source"] for x in mounts["Mounts"] if x["Destination"] == "/utcp"]
        if mounted != [str(ROOT)] or mounts["Image"] != m.IMAGE:
            raise RuntimeError(f"wrong binary or source mount on {container}")
    if not slot.timing:
        raise RuntimeError(f"invalid timing placement {slot_n}")
    return slot, log


def run(label):
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,48}", label):
        raise ValueError("qualification label must be a plain identifier")
    base = f"m2d-multiflow/{label}"
    rd = f"/data/m2/{base}"
    proof = f"{base}/proof"
    with ExitStack() as locks:
        for n in (0, 1):
            locks.enter_context(mf.slot_lock(n))
        slots, keys = [], []
        static = m.static_meta()
        for n in (0, 1):
            slot, log = topology(n)
            slots.append(slot)
            m.dexec(slot.snd, f"mkdir -p {rd}/topology")
            m.vol_write(slot.snd, f"{rd}/topology/up-s{n}.txt", log)
            keys.append(m.current_key(slot, static))
        if (
            len(set(keys)) != 1
            or not static["core_sha256"]
            or not static["bulk_sha256"]
        ):
            raise RuntimeError("runtime identity or placement mismatch")
        old = m.parse_json_object(m.read_volume(slots[0], f"{rd}/freeze.json"))
        frozen = dict(
            reuse_key=keys[0],
            static=static,
            slots=[s.cpus for s in slots],
            schedule_sha256=mf.SCHEDULE_SHA,
        )
        if old and (
            old["reuse_key"] != keys[0] or old["schedule_sha256"] != mf.SCHEDULE_SHA
        ):
            raise RuntimeError("existing qualification binds different runtime")
        if not old:
            mf.write_meta(slots[0], f"{rd}/freeze.json", frozen)
        m.log("FROZEN", json.dumps(frozen))
        for n, slot in enumerate(slots):
            gate = f"{base}/gate-s{n}"
            if m.read_volume(slot, f"/data/m2/{gate}/gate.json") is None:
                m.calibrate(slot, gate, m.PAIRS, False, seed=1)
            if m.check_gate(slot, [gate], keys[n]) != gate:
                raise RuntimeError(f"slot {n} gate failed to reopen")
            m.log("REOPENED", gate, keys[n])
        m.proof_phase(proof, "serial", slots[:1], 5, (), "cubic")
        m.proof_phase(proof, "parallel", slots, 5, (), "cubic")
        report, _ = m.proof_report(proof, 5, (), "cubic")
        files = m.proof_files(proof)
        if report != m.proof_evaluate(files, proof, 5, (), "cubic"):
            raise RuntimeError("proof readback differs")
        if (
            report["notes"]
            or report["evidence_errors"]
            or len(report["valid_runs"]) != 15
            or not all(report["valid_runs"].values())
        ):
            raise RuntimeError("incomplete proof")
        if not all(x["ok"] for x in report["stack_overlap"]):
            raise RuntimeError("missing observed simultaneous proof overlap")
        # A failed parallel performance criterion is itself the proof result.
        # Production's serial decision was made before measuring this proof.
        m.log("PROOF", len(report["valid_runs"]), report["passed"])
        log = m.tb("down.sh", "--slot", 1)
        m.vol_write(slots[0].snd, f"{rd}/topology/down-s1.txt", log)
        mf.write_meta(
            slots[0],
            f"{rd}/qualified.json",
            dict(
                key=keys[0],
                gates=[f"{base}/gate-s0", f"{base}/gate-s1"],
                proof=proof,
                parallel_proof_passed=report["passed"],
                production_slot=0,
            ),
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("label")
    run(parser.parse_args().label)

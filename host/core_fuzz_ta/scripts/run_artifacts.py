#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Record reproducible QEMU runs and classify observed outcomes."""
import argparse
import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def digest(path):
    if not path.is_file():
        return None
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(chunk)
    return {"path": str(path), "size": path.stat().st_size, "sha256": sha.hexdigest()}


def git_state(path):
    def git(*args):
        return subprocess.run(["git", "-C", str(path), *args], capture_output=True,
                              text=True, check=True).stdout.strip()
    return {"commit": git("rev-parse", "HEAD"),
            "dirty": bool(git("status", "--porcelain", "--untracked-files=normal"))}


def coverage_config(path):
    names = ("CFG_CORE_FUZZ_COVERAGE", "CFG_CORE_SANITIZE_KADDRESS",
             "CFG_CORE_SANITIZE_UNDEFINED", "CFG_SANITIZE_UNDEFINED_PANIC",
             "CFG_CORE_ASLR", "CFG_TEE_RAM_VA_SIZE", "CFG_CRYPTOLIB_NAME",
             "CFG_CRYPTO_AES_GCM_FROM_CRYPTOLIB")
    selected = {}
    for line in path.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            name, value = line.split("=", 1)
            if name.startswith(names):
                selected[name] = value
    return selected


def seed_set(directory):
    entries = []
    combined = hashlib.sha256()
    for path in sorted(directory.glob("*.bin"), key=lambda p: p.name):
        info = digest(path)
        entries.append({"name": path.name, "size": info["size"], "sha256": info["sha256"]})
        combined.update(path.name.encode() + b"\0" + info["sha256"].encode() + b"\0")
    return {"count": len(entries), "sha256": combined.hexdigest(), "files": entries}


def write_manifest(args):
    root = Path(args.root).resolve()
    files = {"tee_elf": root / "optee_os/out/arm/core/tee.elf",
             "tee_header": root / "optee_os/out/arm/core/tee-header_v2.bin",
             "tee_pager": root / "optee_os/out/arm/core/tee-pager_v2.bin",
             "tee_pageable": root / "optee_os/out/arm/core/tee-pageable_v2.bin",
             "ta": Path(args.ta).resolve(), "runner": Path(args.runner).resolve(),
             "ta_conf": Path(args.ta_conf).resolve()}
    if args.broker:
        files["broker"] = Path(args.broker).resolve()
    scripts = root / "optee_test/host/core_fuzz_ta/scripts"
    files.update({"fuzz_wrapper": scripts / "run_qemu_fuzz.sh",
                  "replay_wrapper": scripts / "run_qemu_replay.sh",
                  "qemu_driver": scripts / "qemu_fuzz.exp",
                  "qemu_common": scripts / "qemu_common.sh",
                  "artifact_helper": scripts / "run_artifacts.py",
                  "seed_generator": scripts / "make_seeds.py"})
    manifest = {"schema": 1, "created_utc": datetime.now(timezone.utc).isoformat(),
                "mode": args.mode,
                "git": {"optee_os": git_state(root / "optee_os"),
                        "optee_test": git_state(root / "optee_test")},
                "build_config": coverage_config(Path(args.ta_conf)),
                "files": {name: digest(path) for name, path in files.items()},
                "parameters": {"iterations": args.iterations, "rng_seed": args.rng_seed,
                               "algorithms": args.algorithms,
                               "duration_seconds": args.duration,
                               "qemu_timeout_seconds": args.qemu_timeout,
                               "execution_timeout_seconds": args.execution_timeout,
                               "replay_timeout_seconds": args.replay_timeout,
                               "max_auto_replay_hangs": args.max_auto_replay_hangs}}
    if args.mode == "fuzz":
        manifest["parameters"]["corpus_transport"] = "tcp" if args.broker else "local"
    if args.seed_dir:
        manifest["seeds"] = seed_set(Path(args.seed_dir))
    if args.input:
        manifest["input"] = digest(Path(args.input))
    Path(args.output).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def last_count(normal, key):
    values = re.findall(r"\b" + re.escape(key) + r"=(\d+)", normal)
    return int(values[-1]) if values else 0


def classify(exit_code, phase, secure, normal, payload_phase, hang_count=0):
    """Return the primary outcome and its evidence, without inferring TA bugs."""
    if "[ASAN]: access violation" in secure:
        return ("CORE_ASAN" if phase == payload_phase else "UNATTRIBUTED_ASAN",
                "secure_console_asan_marker")
    if "Undefined behavior " in secure:
        return ("CORE_UBSAN" if phase == payload_phase else "UNATTRIBUTED_UBSAN",
                "secure_console_ubsan_marker")
    if re.search(r"Panic at core/", secure):
        return ("CORE_PANIC" if phase == payload_phase else "UNATTRIBUTED_CORE_PANIC",
                "secure_console_core_panic")
    if exit_code == 124:
        return ("HANG_CANDIDATE" if phase == payload_phase else "INFRA_TIMEOUT",
                "qemu_watchdog_timeout")
    if exit_code == 125:
        return "GUEST_PANIC", "normal_world_kernel_panic"
    if exit_code == 126:
        return "GUEST_EXIT", "qemu_exited_unexpectedly"
    if (last_count(normal, "INVOKE_ERRORS") or last_count(normal, "TARGET_DEAD")
            or "FUZZ_INVOKE_ERROR=" in normal
            or re.search(r"\brun=\d+ invoke=0x(?!0{8}\b)[0-9a-fA-F]{8}", normal)):
        return "HARNESS_ERROR", "teec_or_runner_failure_without_core_evidence"
    if last_count(normal, "INVALID_COVERAGE") or "invalid coverage map length" in normal:
        return "COVERAGE_INVALID", "missing_or_wrong_size_secure_coverage_map"
    if "FUZZ_ERROR=" in normal:
        return "HARNESS_ERROR", "runner_failure_without_core_evidence"
    if exit_code:
        return ("HARNESS_ERROR" if phase == payload_phase else "INFRA_ERROR",
                "nonzero_runner_or_wrapper_exit")
    if hang_count:
        return "COMPLETED_WITH_HANG_CANDIDATES", "libafl_timeout_objective"
    return "OK", "clean_exit"


def write_status(args):
    secure_path = Path(args.secure_log)
    normal_path = Path(args.normal_log)
    secure = secure_path.read_text(errors="replace") if secure_path.exists() else ""
    normal = normal_path.read_text(errors="replace") if normal_path.exists() else ""
    kind, reason = classify(args.exit_code, args.phase, secure, normal,
                            args.payload_phase, args.hang_count)
    status = {"schema": 1, "classification": kind, "reason": reason,
              "phase": args.phase, "exit_code": args.exit_code,
              "hang_candidates": args.hang_count,
              "invalid_coverage": last_count(normal, "INVALID_COVERAGE"),
              "invoke_errors": last_count(normal, "INVOKE_ERRORS"),
              "rejected_inputs": last_count(normal, "REJECTED_INPUTS"),
              "target_dead": last_count(normal, "TARGET_DEAD"),
              "logs": {"normal": str(normal_path), "secure": str(secure_path)}}
    if args.expected:
        status["expected"] = args.expected
        status["reproduced"] = kind == args.expected and args.phase == args.payload_phase
    Path(args.output).write_text(json.dumps(status, indent=2, sort_keys=True) + "\n")
    print(kind)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    manifest = commands.add_parser("manifest")
    for name in ("output", "root", "mode", "ta", "runner", "ta-conf"):
        manifest.add_argument("--" + name, required=True)
    for name in ("seed-dir", "input", "broker"):
        manifest.add_argument("--" + name)
    manifest.add_argument("--algorithms")
    for name in ("iterations", "rng-seed", "duration", "qemu-timeout",
                 "execution-timeout", "replay-timeout", "max-auto-replay-hangs"):
        manifest.add_argument("--" + name, type=int)
    status = commands.add_parser("classify")
    for name in ("output", "normal-log", "secure-log", "phase", "exit-code",
                 "payload-phase"):
        status.add_argument("--" + name, required=True,
                            type=int if name == "exit-code" else str)
    status.add_argument("--hang-count", type=int, default=0)
    status.add_argument("--expected")
    args = parser.parse_args()
    if args.command == "manifest":
        write_manifest(args)
    else:
        write_status(args)


if __name__ == "__main__":
    main()

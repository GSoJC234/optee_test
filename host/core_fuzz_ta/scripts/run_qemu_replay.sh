#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026, Jaehun Lee
#
# Launch a fresh VM for exactly one previously saved input.
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 INPUT_FILE [OUTPUT_DIR]" >&2
    exit 2
fi
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/qemu_common.sh"
setup_output_dir
if [ "${FUZZ_QEMU_LOCK_HELD:-0}" != 1 ]; then
    exec 9>"$FUZZ_OUTPUT_DIR/.qemu.lock"
    if ! flock -n 9; then
        echo "another core fuzz QEMU run owns the shared serial logs" >&2
        exit 2
    fi
fi
INPUT_FILE=$(realpath -- "$1")
if [ ! -f "$INPUT_FILE" ]; then
    echo "input file does not exist: $INPUT_FILE" >&2
    exit 2
fi
mkdir -p "$FUZZ_OUTPUT_DIR"
if [ "$#" -eq 2 ]; then
    mkdir -p "$2"
    REPLAY_DIR=$(CDPATH='' cd -- "$2" && pwd)
else
    REPLAY_DIR=$(mktemp -d "$FUZZ_OUTPUT_DIR/replay-XXXXXX")
fi
case "$REPLAY_DIR" in
    "$ROOT"/*) ;;
    *) echo "output directory must be inside $ROOT for QEMU 9p" >&2; exit 2 ;;
esac
case "$REPLAY_DIR" in
    *[!A-Za-z0-9_./-]*) echo "output directory has guest shell-unsafe characters" >&2; exit 2 ;;
esac
if [ "$INPUT_FILE" != "$REPLAY_DIR/input.bin" ]; then
    cp -- "$INPUT_FILE" "$REPLAY_DIR/input.bin"
fi
FUZZ_REPLAY_TIMEOUT=${FUZZ_REPLAY_TIMEOUT:-600}
case "$FUZZ_REPLAY_TIMEOUT" in
    ""|*[!0-9]*|0) echo "FUZZ_REPLAY_TIMEOUT must be a positive integer" >&2; exit 2 ;;
esac
check_build
KASAN=$(ta_conf CFG_CORE_SANITIZE_KADDRESS)
UBSAN=$(ta_conf CFG_CORE_SANITIZE_UNDEFINED)
UBSAN_PANIC=$(ta_conf CFG_SANITIZE_UNDEFINED_PANIC)
CORE_ASLR=$(ta_conf CFG_CORE_ASLR)
COVERAGE_CRYPTO_IMPL=$(ta_conf CFG_CORE_FUZZ_COVERAGE_CRYPTO_IMPL)
COVERAGE_TOMCRYPT=$(ta_conf CFG_CORE_FUZZ_COVERAGE_TOMCRYPT)
COVERAGE_MPI=$(ta_conf CFG_CORE_FUZZ_COVERAGE_MPI)
echo "BUILD_KASAN=$KASAN BUILD_UBSAN=$UBSAN" \
    "BUILD_UBSAN_PANIC=$UBSAN_PANIC BUILD_CORE_ASLR=$CORE_ASLR"
echo "COVERAGE_PROFILE base=on crypto_impl=$COVERAGE_CRYPTO_IMPL" \
    "tomcrypt=$COVERAGE_TOMCRYPT mpi=$COVERAGE_MPI"
if [ "${FUZZ_PREPARED:-0}" != 1 ]; then build_runner >/dev/null; fi
setup_qemu
if [ -z "${QEMU_WORK_DIR:-}" ]; then QEMU_WORK_DIR="$REPLAY_DIR/qemu"; fi
prepare_qemu_workdir
FUZZ_REPLAY_GUEST_INPUT="$(guest_path "$REPLAY_DIR")/input.bin"
FUZZ_REPLAY_NORMAL_LOG="$REPLAY_DIR/normal.log"
FUZZ_REPLAY_PHASE_FILE="$REPLAY_DIR/phase.txt"
export FUZZ_REPLAY_GUEST_INPUT FUZZ_REPLAY_NORMAL_LOG FUZZ_REPLAY_PHASE_FILE FUZZ_REPLAY_TIMEOUT

cd "$QEMU_WORK_DIR"
status=0
rm -f "$FUZZ_REPLAY_PHASE_FILE"
expect "$SCRIPT_DIR/qemu_fuzz.exp" replay 9>&- || status=$?
if [ -f serial1.log ]; then
    cp serial1.log "$REPLAY_DIR/secure.log"
else
    : > "$REPLAY_DIR/secure.log"
fi
phase=$(cat "$FUZZ_REPLAY_PHASE_FILE" 2>/dev/null || true)
expected=${FUZZ_REPLAY_EXPECT:-CORE_ASAN}
case "$expected" in
    CORE_ASAN|CORE_UBSAN|CORE_PANIC|HANG_CANDIDATE) ;;
    *) echo "invalid FUZZ_REPLAY_EXPECT: $expected" >&2; exit 2 ;;
esac
classification=$(python3 "$SCRIPT_DIR/run_artifacts.py" classify \
    --output "$REPLAY_DIR/status.json" \
    --normal-log "$REPLAY_DIR/normal.log" --secure-log "$REPLAY_DIR/secure.log" \
    --phase "$phase" --exit-code "$status" --payload-phase input \
    --expected "$expected")
python3 "$SCRIPT_DIR/run_artifacts.py" manifest \
    --output "$REPLAY_DIR/manifest.json" --root "$ROOT" --mode replay \
    --ta "$TA_FILE" --runner "$RUNNER" --ta-conf "$TA_CONF" \
    --input "$REPLAY_DIR/input.bin" --replay-timeout "$FUZZ_REPLAY_TIMEOUT"
reproduced=$(python3 -c \
    'import json,sys; print("yes" if json.load(open(sys.argv[1]))["reproduced"] else "no")' \
    "$REPLAY_DIR/status.json")
{
    printf 'reproduced=%s\nclassification=%s\nexpected=%s\nphase=%s\nguest_exit=%s\n' \
        "$reproduced" "$classification" "$expected" "$phase" "$status"
    sha256sum "$REPLAY_DIR/input.bin" | cut -d' ' -f1 | sed 's/^/input_sha256=/'
} > "$REPLAY_DIR/status.txt"
echo "Replay artifacts: $REPLAY_DIR"
if [ "$reproduced" = yes ]; then
    echo "REPLAY_REPRODUCED: $classification $REPLAY_DIR/input.bin"
    exit 0
fi
echo "REPLAY_NOT_OBSERVED: expected=$expected observed=$classification" \
    "phase=$phase guest_exit=$status"
exit 1

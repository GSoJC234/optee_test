#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
set -eu

if [ "$#" -gt 3 ]; then
    echo "usage: $0 [ITERATIONS] [RNG_SEED] [on|off]" >&2
    exit 2
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../../../.." && pwd)
TA_DIR="$ROOT/optee_test/ta/core_fuzz_ta"
mkdir -p "$ROOT/out/fuzz"
exec 9>"$ROOT/out/fuzz/.qemu.lock"
if ! flock -n 9; then
    echo "another core fuzz QEMU run owns the shared serial logs" >&2
    exit 2
fi
ITERATIONS=${1:-200}
RNG_SEED=${2:-1}
HOPPER_MODE=${3:-on}
TIMEOUT=${FUZZ_TIMEOUT:-600}
DURATION=${FUZZ_DURATION_SECONDS:-0}
case "$ITERATIONS:$RNG_SEED:$TIMEOUT:$DURATION" in
    *[!0-9:]*|:*|*::*|*:)
        echo "iterations, seed and timeout must be positive integers" >&2
        exit 2 ;;
esac
case "$HOPPER_MODE" in
    on|off) ;;
    *) echo "HOPPER mode must be on or off" >&2; exit 2 ;;
esac
if [ "$DURATION" -gt 0 ] && [ "$TIMEOUT" -le "$DURATION" ]; then
    echo "FUZZ_TIMEOUT must exceed FUZZ_DURATION_SECONDS" >&2
    exit 2
fi
if ! grep -qx 'CFG_CORE_FUZZ_COVERAGE=y' "$ROOT/optee_os/out/arm/conf.mk"; then
    echo "Build OP-TEE with CFG_CORE_FUZZ_COVERAGE=y first" >&2
    exit 2
fi
if grep -qx 'CFG_CORE_SANITIZE_KADDRESS=y' "$ROOT/optee_os/out/arm/conf.mk"; then
    KASAN=on
else
    KASAN=off
fi
if grep -qx 'CFG_CORE_ASLR=y' "$ROOT/optee_os/out/arm/conf.mk"; then
    CORE_ASLR=on
else
    CORE_ASLR=off
fi
echo "BUILD_KASAN=$KASAN BUILD_CORE_ASLR=$CORE_ASLR"
if [ ! -f "$ROOT/out-br/target/lib/optee_armtz/92ea581c-d6ec-449e-9aa6-cf93aa2b44dd.ta" ]; then
    echo "Build the signed core_fuzz_ta first" >&2
    exit 2
fi
make -C "$TA_DIR/host"
python3 "$TA_DIR/make_seeds.py"
mkdir -p "$ROOT/out/fuzz"
marker=$(mktemp "$ROOT/out/fuzz/.started-XXXXXX")
QEMU=$(make -s -C "$ROOT/build" \
    --eval='fuzz-print-qemu:;@printf "%s\n" "$(QEMU_BIN)"' fuzz-print-qemu)
BASE_ARGS=$(make -s -C "$ROOT/build" \
    --eval='fuzz-print-args:;@printf "%s\n" "$(QEMU_CHECK_ARGS)"' fuzz-print-args)
QEMU_CHECK_ARGS="$BASE_ARGS -fsdev local,id=fsdev0,path=$ROOT,security_model=none"
QEMU_CHECK_ARGS="$QEMU_CHECK_ARGS -device virtio-9p-device,fsdev=fsdev0,mount_tag=host"
FUZZ_ITERATIONS="$ITERATIONS"
FUZZ_RNG_SEED="$RNG_SEED"
FUZZ_HOPPER_MODE="$HOPPER_MODE"
FUZZ_TIMEOUT="$TIMEOUT"
FUZZ_DURATION_SECONDS="$DURATION"
FUZZ_NORMAL_LOG="$ROOT/out/fuzz/last-normal.log"
FUZZ_PHASE_FILE="$ROOT/out/fuzz/last-phase.txt"
rm -f "$FUZZ_PHASE_FILE"
export QEMU QEMU_CHECK_ARGS FUZZ_ITERATIONS FUZZ_RNG_SEED FUZZ_HOPPER_MODE
export FUZZ_TIMEOUT FUZZ_DURATION_SECONDS FUZZ_NORMAL_LOG FUZZ_PHASE_FILE

cd "$ROOT/out/bin"
status=0
expect "$TA_DIR/host/qemu_fuzz.exp" fuzz 9>&- || status=$?
# The original QEMU is reaped before this point. Save its log before replay
# launches a fresh QEMU in the same out/bin directory.
classification=NONE
if [ -f serial1.log ]; then
    if grep -aFq -- '[ASAN]: access violation' serial1.log; then
        classification=ASAN
    else
        grep_status=$?
        if [ "$grep_status" -ne 1 ]; then
            echo "failed to classify secure console (grep exit $grep_status)" >&2
            exit 2
        fi
    fi
fi
phase=$(cat "$FUZZ_PHASE_FILE" 2>/dev/null || true)
exact_run_dir=""
latest=""
if [ -f "$FUZZ_NORMAL_LOG" ]; then
    guest_run=$(tr -d '\r' < "$FUZZ_NORMAL_LOG" | sed -n 's/^FUZZ_RUN_DIR=//p' | tail -n 1)
    case "$guest_run" in
        /mnt/host/out/fuzz/run-*)
            candidate="$ROOT${guest_run#/mnt/host}"
            if [ -d "$candidate" ]; then exact_run_dir="$candidate"; latest="$candidate"; fi ;;
    esac
fi
if [ -z "$latest" ]; then
    latest=$(find "$ROOT/out/fuzz" -mindepth 1 -maxdepth 1 -type d \
        -name 'run-*' -newer "$marker" -printf '%T@ %p\n' |
        sort -nr | head -1 | cut -d' ' -f2-)
fi
rm -f "$marker"
if [ -n "$latest" ]; then
    cp "$FUZZ_NORMAL_LOG" "$latest/normal.log" 2>/dev/null || true
    cp serial1.log "$latest/secure.log" 2>/dev/null || true
    printf 'kasan=%s\ncore_aslr=%s\n' "$KASAN" "$CORE_ASLR" > "$latest/build-config.txt"
    if [ "$classification" = NONE ] && [ "$phase" = fuzz ] &&
       { [ "$status" -eq 124 ] || [ "$status" -eq 125 ] || [ "$status" -eq 126 ]; }; then
        cp "$latest/current.bin" "$latest/crashes/watchdog-$(date +%s).bin" 2>/dev/null || true
    fi
    echo "Fuzz artifacts: $latest"
fi
if [ "$classification" = ASAN ]; then
    if [ "$phase" = fuzz ] && [ -n "$exact_run_dir" ] && [ -f "$exact_run_dir/current.bin" ]; then
        event_dir=$(mktemp -d "$exact_run_dir/crashes/asan-XXXXXX")
        cp "$exact_run_dir/current.bin" "$event_dir/input.bin"
        cp "$exact_run_dir/current.meta" "$event_dir/input.meta" 2>/dev/null || true
        cp "$FUZZ_NORMAL_LOG" "$event_dir/original-normal.log" 2>/dev/null || true
        cp serial1.log "$event_dir/original-secure.log" 2>/dev/null || true
        printf 'classification=ASAN\nphase=fuzz\noriginal_exit=%s\nkasan=%s\ncore_aslr=%s\n' \
            "$status" "$KASAN" "$CORE_ASLR" > "$event_dir/status.txt"
        echo "ASAN_CRASH_INPUT: $event_dir/input.bin"
        replay_status=0
        FUZZ_QEMU_LOCK_HELD=1 "$TA_DIR/host/run_qemu_replay.sh" \
            "$event_dir/input.bin" "$event_dir/replay" || replay_status=$?
        printf 'replay_exit=%s\n' "$replay_status" >> "$event_dir/status.txt"
        # The original campaign failed, even if the fresh-VM replay reproduced.
        exit 127
    fi
    event_dir=$(mktemp -d "$ROOT/out/fuzz/asan-unattributed-XXXXXX")
    cp "$FUZZ_NORMAL_LOG" "$event_dir/normal.log" 2>/dev/null || true
    cp serial1.log "$event_dir/secure.log" 2>/dev/null || true
    printf 'classification=ASAN\nphase=%s\noriginal_exit=%s\nkasan=%s\ncore_aslr=%s\n' \
        "$phase" "$status" "$KASAN" "$CORE_ASLR" > "$event_dir/status.txt"
    echo "ASAN_UNATTRIBUTED: $event_dir"
    exit 127
fi
exit "$status"

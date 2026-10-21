#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Launch a fresh VM for exactly one previously saved input.
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 INPUT_FILE [OUTPUT_DIR]" >&2
    exit 2
fi
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../../../.." && pwd)
TA_DIR="$ROOT/optee_test/ta/core_fuzz_ta"
mkdir -p "$ROOT/out/fuzz"
if [ "${FUZZ_QEMU_LOCK_HELD:-0}" != 1 ]; then
    exec 9>"$ROOT/out/fuzz/.qemu.lock"
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
mkdir -p "$ROOT/out/fuzz"
if [ "$#" -eq 2 ]; then
    mkdir -p "$2"
    REPLAY_DIR=$(CDPATH= cd -- "$2" && pwd)
else
    REPLAY_DIR=$(mktemp -d "$ROOT/out/fuzz/replay-XXXXXX")
fi
case "$REPLAY_DIR" in
    "$ROOT"/*) ;;
    *) echo "output directory must be inside $ROOT for QEMU 9p" >&2; exit 2 ;;
esac
case "$REPLAY_DIR" in
    *[!A-Za-z0-9_./-]*) echo "output directory has guest shell-unsafe characters" >&2; exit 2 ;;
esac
if [ "$INPUT_FILE" != "$REPLAY_DIR/input.bin" ]; then
    rm -f "$REPLAY_DIR/input.meta"
    cp -- "$INPUT_FILE" "$REPLAY_DIR/input.bin"
fi
# The fuzzer records the fourth TEEC parameter for target-operation probes.
# A manually supplied seed has no sidecar and uses whole-sequence coverage.
case "$INPUT_FILE" in
    */current.bin) SOURCE_META="${INPUT_FILE%.bin}.meta" ;;
    */input.bin) SOURCE_META="$(dirname -- "$INPUT_FILE")/input.meta" ;;
    *) SOURCE_META="" ;;
esac
if [ -n "$SOURCE_META" ] && [ -f "$SOURCE_META" ] && \
   [ "$SOURCE_META" != "$REPLAY_DIR/input.meta" ]; then
    cp -- "$SOURCE_META" "$REPLAY_DIR/input.meta"
fi
SHAPE_KNOWN=no
TARGET_INDEX=-1
if [ -f "$REPLAY_DIR/input.meta" ]; then
    TARGET_INDEX=$(sed -n 's/^target_index=//p' "$REPLAY_DIR/input.meta" | head -n 1)
    case "$TARGET_INDEX" in
        -1) SHAPE_KNOWN=yes ;;
        ""|*[!0-9]*) echo "invalid target_index in input.meta" >&2; exit 2 ;;
        *)
            if [ "$TARGET_INDEX" -gt 63 ]; then
                echo "target_index exceeds maximum 63" >&2
                exit 2
            fi
            SHAPE_KNOWN=yes ;;
    esac
fi
FUZZ_REPLAY_TIMEOUT=${FUZZ_REPLAY_TIMEOUT:-600}
case "$FUZZ_REPLAY_TIMEOUT" in
    ""|*[!0-9]*|0) echo "FUZZ_REPLAY_TIMEOUT must be a positive integer" >&2; exit 2 ;;
esac
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
make -C "$TA_DIR/host" >/dev/null
QEMU=$(make -s -C "$ROOT/build" \
    --eval='fuzz-print-qemu:;@printf "%s\n" "$(QEMU_BIN)"' fuzz-print-qemu)
BASE_ARGS=$(make -s -C "$ROOT/build" \
    --eval='fuzz-print-args:;@printf "%s\n" "$(QEMU_CHECK_ARGS)"' fuzz-print-args)
QEMU_CHECK_ARGS="$BASE_ARGS -fsdev local,id=fsdev0,path=$ROOT,security_model=none"
QEMU_CHECK_ARGS="$QEMU_CHECK_ARGS -device virtio-9p-device,fsdev=fsdev0,mount_tag=host"
FUZZ_REPLAY_GUEST_INPUT="/mnt/host/${REPLAY_DIR#"$ROOT"/}/input.bin"
FUZZ_REPLAY_NORMAL_LOG="$REPLAY_DIR/normal.log"
FUZZ_REPLAY_PHASE_FILE="$REPLAY_DIR/phase.txt"
FUZZ_REPLAY_TARGET_INDEX="$TARGET_INDEX"
export QEMU QEMU_CHECK_ARGS FUZZ_REPLAY_GUEST_INPUT FUZZ_REPLAY_NORMAL_LOG
export FUZZ_REPLAY_PHASE_FILE FUZZ_REPLAY_TIMEOUT FUZZ_REPLAY_TARGET_INDEX

cd "$ROOT/out/bin"
status=0
rm -f "$FUZZ_REPLAY_PHASE_FILE"
expect "$TA_DIR/host/qemu_fuzz.exp" replay 9>&- || status=$?
if [ -f serial1.log ]; then
    cp serial1.log "$REPLAY_DIR/secure.log"
else
    : > "$REPLAY_DIR/secure.log"
fi
classification=NONE
if grep -aFq -- '[ASAN]: access violation' "$REPLAY_DIR/secure.log"; then
    classification=ASAN
else
    grep_status=$?
    if [ "$grep_status" -ne 1 ]; then
        echo "failed to classify replay secure console (grep exit $grep_status)" >&2
        exit 2
    fi
fi
phase=$(cat "$FUZZ_REPLAY_PHASE_FILE" 2>/dev/null || true)
if [ "$classification" = ASAN ] && [ "$phase" = input ]; then
    reproduced=yes
else
    reproduced=no
fi
{
    printf 'reproduced=%s\n' "$reproduced"
    printf 'classification=%s\n' "$classification"
    printf 'phase=%s\n' "$phase"
    printf 'guest_exit=%s\n' "$status"
    printf 'shape_known=%s\ntarget_index=%s\n' "$SHAPE_KNOWN" "$TARGET_INDEX"
    printf 'kasan=%s\ncore_aslr=%s\n' "$KASAN" "$CORE_ASLR"
    sha256sum "$REPLAY_DIR/input.bin" | cut -d' ' -f1 | sed 's/^/input_sha256=/'
} > "$REPLAY_DIR/status.txt"
echo "Replay artifacts: $REPLAY_DIR"
if [ "$reproduced" = yes ]; then
    echo "ASAN_REPRODUCED: $REPLAY_DIR/input.bin"
    exit 0
fi
echo "ASAN_NOT_OBSERVED: phase=$phase guest_exit=$status shape_known=$SHAPE_KNOWN"
exit 1

#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026, Jaehun Lee
#
# Boot the OP-TEE QEMU guest once and run a LibAFL campaign against
# core_fuzz_ta. See ../README.md.
set -eu

ITERATIONS=200
RNG_SEED=1
WORKERS=${FUZZ_WORKERS:-1}
ALGORITHMS=${FUZZ_ALGORITHMS:-all}
position=0
for argument do
    case "$argument" in
        --algorithms=*) ALGORITHMS=${argument#*=} ;;
        --workers=*) WORKERS=${argument#*=} ;;
        --*)
            echo "usage: $0 [ITERATIONS] [RNG_SEED] [--algorithms=LIST] [--workers=N]" >&2
            exit 2 ;;
        *)
            position=$((position + 1))
            case "$position" in
                1) ITERATIONS=$argument ;;
                2) RNG_SEED=$argument ;;
                *)
                    echo "usage: $0 [ITERATIONS] [RNG_SEED] [--algorithms=LIST] [--workers=N]" >&2
                    exit 2 ;;
            esac ;;
    esac
done
if ! printf '%s' "$ALGORITHMS" | LC_ALL=C grep -Eq '^(all|[a-z0-9-]+(,[a-z0-9-]+)*)$'; then
    echo "FUZZ_ALGORITHMS must be a comma-separated list of algorithm names" >&2
    exit 2
fi
if [ "$ALGORITHMS" != all ]; then
    old_ifs=$IFS
    IFS=,
    for algorithm in $ALGORITHMS; do
        case "$algorithm" in
            sha256|sha512|hmac-sha256|aes-ctr|aes-gcm|hkdf|\
            rsa-pkcs1v15-sha256|rsaes-pkcs1v15|aes-ccm|\
            rsa-pss-sha256|rsa-oaep-sha256|random) ;;
            *) echo "unsupported algorithm: $algorithm" >&2; exit 2 ;;
        esac
    done
    IFS=$old_ifs
fi

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/qemu_common.sh"
setup_output_dir
FUZZ_GUEST_OUTPUT_DIR=$(guest_path "$FUZZ_OUTPUT_DIR")
TIMEOUT=${FUZZ_TIMEOUT:-1800}
DURATION=${FUZZ_DURATION_SECONDS:-0}
EXEC_TIMEOUT=${FUZZ_EXECUTION_TIMEOUT_SECONDS:-360}
MAX_AUTO_REPLAY_HANGS=${FUZZ_MAX_AUTO_REPLAY_HANGS:-1}
case "$ITERATIONS:$RNG_SEED:$TIMEOUT:$DURATION:$EXEC_TIMEOUT:$MAX_AUTO_REPLAY_HANGS" in
    *[!0-9:]*|:*|*::*|*:)
        echo "iterations, seed and timeout must be positive integers" >&2
        exit 2 ;;
esac
case "$WORKERS" in
    ''|*[!0-9]*|0) echo "workers must be a positive integer" >&2; exit 2 ;;
esac
if [ "$WORKERS" -gt 16 ] || [ "$WORKERS" -gt "$ITERATIONS" ]; then
    echo "workers must be at most 16 and no greater than iterations" >&2
    exit 2
fi
if [ "$EXEC_TIMEOUT" -eq 0 ] || [ "$EXEC_TIMEOUT" -gt 3600 ]; then
    echo "FUZZ_EXECUTION_TIMEOUT_SECONDS must be in 1..3600" >&2
    exit 2
fi
if [ "$DURATION" -gt 0 ] && [ "$TIMEOUT" -le "$DURATION" ]; then
    echo "FUZZ_TIMEOUT must exceed FUZZ_DURATION_SECONDS" >&2
    exit 2
fi
check_build
KASAN=$(ta_conf CFG_CORE_SANITIZE_KADDRESS)
UBSAN=$(ta_conf CFG_CORE_SANITIZE_UNDEFINED)
UBSAN_PANIC=$(ta_conf CFG_SANITIZE_UNDEFINED_PANIC)
CORE_ASLR=$(ta_conf CFG_CORE_ASLR)
COVERAGE_CRYPTO_IMPL=$(ta_conf CFG_CORE_FUZZ_COVERAGE_CRYPTO_IMPL)
COVERAGE_TOMCRYPT=$(ta_conf CFG_CORE_FUZZ_COVERAGE_TOMCRYPT)
COVERAGE_MPI=$(ta_conf CFG_CORE_FUZZ_COVERAGE_MPI)
echo "BUILD_KASAN=$KASAN BUILD_UBSAN=$UBSAN" \
    "BUILD_UBSAN_PANIC=$UBSAN_PANIC BUILD_CORE_ASLR=$CORE_ASLR ENGINE=libafl"
echo "COVERAGE_PROFILE base=on crypto_impl=$COVERAGE_CRYPTO_IMPL" \
    "tomcrypt=$COVERAGE_TOMCRYPT mpi=$COVERAGE_MPI"
if [ "$UBSAN" = on ] && [ "$UBSAN_PANIC" != on ]; then
    echo "UBSan fuzzing requires CFG_SANITIZE_UNDEFINED_PANIC=y" \
        "to attribute a report to current.bin" >&2
    exit 2
fi
if [ "$COVERAGE_CRYPTO_IMPL:$COVERAGE_TOMCRYPT:$COVERAGE_MPI" != on:on:on ]; then
    echo "Build OP-TEE once with CFG_CORE_FUZZ_COVERAGE=y and all crypto coverage flags enabled" >&2
    exit 2
fi
echo "FUZZ_ALGORITHMS=$ALGORITHMS"
if [ "${FUZZ_WORKER_MODE:-0}" != 1 ] && [ "$WORKERS" -gt 1 ]; then
    exec 9>"$FUZZ_OUTPUT_DIR/.qemu.lock"
    if ! flock -n 9; then
        echo "another campaign owns $FUZZ_OUTPUT_DIR" >&2
        exit 2
    fi
    build_runner
    python3 "$SCRIPT_DIR/make_seeds.py"
    campaign=$(mktemp -d "$FUZZ_OUTPUT_DIR/campaign-XXXXXXXX")
    printf 'workers=%s\niterations=%s\nmaster_seed=%s\nalgorithms=%s\nduration_seconds=%s\n' \
        "$WORKERS" "$ITERATIONS" "$RNG_SEED" "$ALGORITHMS" "$DURATION" > "$campaign/config.txt"
    printf 'worker_id\tpid\n' > "$campaign/workers.tsv"
    base_iterations=$((ITERATIONS / WORKERS))
    extra_iterations=$((ITERATIONS % WORKERS))
    worker_id=0
    while [ "$worker_id" -lt "$WORKERS" ]; do
        worker_iterations=$base_iterations
        if [ "$worker_id" -lt "$extra_iterations" ]; then
            worker_iterations=$((worker_iterations + 1))
        fi
        worker_seed=$(python3 -c \
            'import sys; print((int(sys.argv[1]) + int(sys.argv[2])) % (1 << 64))' \
            "$RNG_SEED" "$worker_id")
        FUZZ_WORKER_MODE=1 FUZZ_PREPARED=1 FUZZ_WORKERS=1 FUZZ_WORKER_ID="$worker_id" \
            FUZZ_OUTPUT_DIR="$campaign/worker-$worker_id" \
            QEMU_WORK_DIR="$campaign/worker-$worker_id/qemu" \
            "$SCRIPT_DIR/run_qemu_fuzz.sh" "$worker_iterations" "$worker_seed" \
            "--algorithms=$ALGORITHMS" > "$campaign/worker-$worker_id.log" 2>&1 9>&- &
        printf '%s\t%s\n' "$worker_id" "$!" >> "$campaign/workers.tsv"
        worker_id=$((worker_id + 1))
    done
    overall_status=0
    printf 'worker_id\texit_status\tlog\n' > "$campaign/status.tsv"
    while IFS="$(printf '\t')" read -r worker_id worker_pid; do
        [ "$worker_id" = worker_id ] && continue
        worker_status=0
        wait "$worker_pid" || worker_status=$?
        [ "$worker_status" -eq 0 ] || overall_status=1
        printf '%s\t%s\t%s\n' "$worker_id" "$worker_status" \
            "$campaign/worker-$worker_id.log" >> "$campaign/status.tsv"
        echo "FUZZ_WORKER_DONE id=$worker_id status=$worker_status" \
            "log=$campaign/worker-$worker_id.log"
    done < "$campaign/workers.tsv"
    total_executions=0
    worker_id=0
    while [ "$worker_id" -lt "$WORKERS" ]; do
        executions=$(tr -d '\r' < "$campaign/worker-$worker_id.log" |
            sed -n 's/.*FUZZ_DONE .* EXECUTIONS=\([0-9]*\).*/\1/p' | tail -n 1)
        total_executions=$((total_executions + ${executions:-0}))
        worker_id=$((worker_id + 1))
    done
    echo "FUZZ_CAMPAIGN_DONE WORKERS=$WORKERS EXECUTIONS=$total_executions" \
        "STATUS=$overall_status ARTIFACTS=$campaign"
    exit "$overall_status"
fi
echo "FUZZ_WORKER_ID=${FUZZ_WORKER_ID:-0}"
exec 9>"$FUZZ_OUTPUT_DIR/.qemu.lock"
if ! flock -n 9; then
    echo "another worker owns $FUZZ_OUTPUT_DIR" >&2
    exit 2
fi
if [ "${FUZZ_PREPARED:-0}" != 1 ]; then
    build_runner
    python3 "$SCRIPT_DIR/make_seeds.py"
fi
marker=$(mktemp "$FUZZ_OUTPUT_DIR/.started-XXXXXX")
setup_qemu
prepare_qemu_workdir
FUZZ_ITERATIONS="$ITERATIONS"
FUZZ_RNG_SEED="$RNG_SEED"
FUZZ_TIMEOUT="$TIMEOUT"
FUZZ_DURATION_SECONDS="$DURATION"
FUZZ_EXECUTION_TIMEOUT_SECONDS="$EXEC_TIMEOUT"
FUZZ_ALGORITHMS="$ALGORITHMS"
FUZZ_NORMAL_LOG="$FUZZ_OUTPUT_DIR/last-normal.log"
FUZZ_PHASE_FILE="$FUZZ_OUTPUT_DIR/last-phase.txt"
rm -f "$FUZZ_PHASE_FILE"
export FUZZ_ITERATIONS FUZZ_RNG_SEED FUZZ_TIMEOUT
export FUZZ_DURATION_SECONDS FUZZ_EXECUTION_TIMEOUT_SECONDS
export FUZZ_ALGORITHMS
export FUZZ_OUTPUT_DIR FUZZ_GUEST_OUTPUT_DIR FUZZ_NORMAL_LOG FUZZ_PHASE_FILE

cd "$QEMU_WORK_DIR"
status=0
expect "$SCRIPT_DIR/qemu_fuzz.exp" fuzz 9>&- || status=$?
# Preserve the first VM's logs before a fresh-VM replay replaces serial1.log.
phase=$(cat "$FUZZ_PHASE_FILE" 2>/dev/null || true)
exact_run_dir=""
latest=""
if [ -f "$FUZZ_NORMAL_LOG" ]; then
    guest_run=$(tr -d '\r' < "$FUZZ_NORMAL_LOG" | sed -n 's/^FUZZ_RUN_DIR=//p' | tail -n 1)
    case "$guest_run" in
        "$FUZZ_GUEST_OUTPUT_DIR"/run-*)
            candidate="$ROOT${guest_run#/mnt/host}"
            if [ -d "$candidate" ]; then exact_run_dir="$candidate"; latest="$candidate"; fi ;;
    esac
fi
if [ -z "$latest" ]; then
    latest=$(find "$FUZZ_OUTPUT_DIR" -mindepth 1 -maxdepth 1 -type d \
        -name 'run-*' -newer "$marker" -printf '%T@ %p\n' |
        sort -nr | head -1 | cut -d' ' -f2-)
fi
rm -f "$marker"
if [ -z "$latest" ]; then
    latest=$(mktemp -d "$FUZZ_OUTPUT_DIR/failed-run-XXXXXX")
fi
cp "$FUZZ_NORMAL_LOG" "$latest/normal.log" 2>/dev/null || : > "$latest/normal.log"
if [ -f serial1.log ]; then cp serial1.log "$latest/secure.log"; else : > "$latest/secure.log"; fi
{
    printf 'kasan=%s\nubsan=%s\nubsan_panic=%s\ncore_aslr=%s\ncoverage_base=on\n' \
        "$KASAN" "$UBSAN" "$UBSAN_PANIC" "$CORE_ASLR"
    printf 'coverage_crypto_impl=%s\ncoverage_tomcrypt=%s\ncoverage_mpi=%s\n' \
        "$COVERAGE_CRYPTO_IMPL" "$COVERAGE_TOMCRYPT" "$COVERAGE_MPI"
    printf 'algorithms=%s\n' "$ALGORITHMS"
    printf 'execution_timeout_seconds=%s\n' "$EXEC_TIMEOUT"
    printf 'worker_id=%s\n' "${FUZZ_WORKER_ID:-0}"
} > "$latest/build-config.txt"
MANIFEST_SEED_DIR="$SEED_DIR"
if [ -d "$latest/selected-seeds" ]; then MANIFEST_SEED_DIR="$latest/selected-seeds"; fi
python3 "$SCRIPT_DIR/run_artifacts.py" manifest \
    --output "$latest/manifest.json" --root "$ROOT" --mode fuzz \
    --ta "$TA_FILE" --runner "$RUNNER" --ta-conf "$TA_CONF" \
    --seed-dir "$MANIFEST_SEED_DIR" --algorithms "$ALGORITHMS" \
    --iterations "$ITERATIONS" --rng-seed "$RNG_SEED" \
    --duration "$DURATION" --qemu-timeout "$TIMEOUT" \
    --execution-timeout "$EXEC_TIMEOUT" \
    --max-auto-replay-hangs "$MAX_AUTO_REPLAY_HANGS"
hang_count=0
if [ -d "$latest/hangs" ]; then
    hang_count=$(find "$latest/hangs" -maxdepth 1 -type f ! -name '.*' | wc -l)
fi
classification=$(python3 "$SCRIPT_DIR/run_artifacts.py" classify \
    --output "$latest/status.json" --normal-log "$latest/normal.log" \
    --secure-log "$latest/secure.log" --phase "$phase" \
    --exit-code "$status" --payload-phase fuzz --hang-count "$hang_count")
echo "FUZZ_CLASSIFICATION=$classification phase=$phase evidence=$latest/status.json"
echo "Fuzz artifacts: $latest"
case "$classification" in
    CORE_ASAN|CORE_UBSAN|CORE_PANIC|HANG_CANDIDATE)
        if [ "$phase" = fuzz ] && [ -n "$exact_run_dir" ] && \
           [ -f "$exact_run_dir/current.bin" ]; then
            case "$classification" in
                HANG_CANDIDATE)
                    mkdir -p "$exact_run_dir/hangs"
                    event_dir=$(mktemp -d "$exact_run_dir/hangs/watchdog-XXXXXX") ;;
                *)
                    mkdir -p "$exact_run_dir/crashes"
                    event_dir=$(mktemp -d "$exact_run_dir/crashes/core-XXXXXX") ;;
            esac
            cp "$exact_run_dir/current.bin" "$event_dir/input.bin"
            cp "$latest/normal.log" "$event_dir/original-normal.log"
            cp "$latest/secure.log" "$event_dir/original-secure.log"
            cp "$latest/manifest.json" "$event_dir/manifest.json"
            printf 'classification=%s\nreason=%s\noriginal_exit=%s\nphase=%s\n' \
                "$classification" "$(python3 -c \
                    'import json,sys;print(json.load(open(sys.argv[1]))["reason"])' \
                    "$latest/status.json")" \
                "$status" "$phase" > "$event_dir/status.txt"
            replay_status=0
            FUZZ_QEMU_LOCK_HELD=1 FUZZ_REPLAY_EXPECT="$classification" \
                "$SCRIPT_DIR/run_qemu_replay.sh" \
                    "$event_dir/input.bin" "$event_dir/replay" || replay_status=$?
            printf 'replay_exit=%s\n' "$replay_status" >> "$event_dir/status.txt"
            if [ "$replay_status" -eq 0 ]; then
                printf 'reproduced=yes\n' >> "$event_dir/status.txt"
            else
                printf 'reproduced=no\n' >> "$event_dir/status.txt"
            fi
            echo "FUZZ_FINDING: $classification $event_dir/input.bin"
        else
            echo "FUZZ_UNATTRIBUTED: $classification $latest"
        fi
        case "$classification" in HANG_CANDIDATE) exit 124 ;; *) exit 127 ;; esac ;;
    UNATTRIBUTED_ASAN|UNATTRIBUTED_UBSAN|UNATTRIBUTED_CORE_PANIC)
        echo "FUZZ_UNATTRIBUTED: $classification $latest"
        exit 127 ;;
esac
# LibAFL's timeout solutions are only candidates until a fresh VM reproduces.
AUTO_REPLAY_HANGS=${FUZZ_AUTO_REPLAY_HANGS:-1}
case "$AUTO_REPLAY_HANGS" in
    0|1) ;;
    *) echo "FUZZ_AUTO_REPLAY_HANGS must be 0 or 1" >&2; exit 2 ;;
esac
auto_replays=0
if [ -d "$latest/hangs" ]; then
    for candidate in "$latest/hangs/"*; do
        [ -f "$candidate" ] || continue
        triage_dir="$latest/hangs/triage/$(basename "$candidate")"
        mkdir -p "$triage_dir"
        printf 'classification=HANG_CANDIDATE\nreason=libafl_timeout_objective\n' \
            > "$triage_dir/status.txt"
        if [ "$AUTO_REPLAY_HANGS" -eq 1 ] && [ "$auto_replays" -lt "$MAX_AUTO_REPLAY_HANGS" ]; then
            auto_replays=$((auto_replays + 1))
            replay_status=0
            FUZZ_QEMU_LOCK_HELD=1 FUZZ_REPLAY_EXPECT=HANG_CANDIDATE \
                FUZZ_REPLAY_TIMEOUT="$EXEC_TIMEOUT" \
                "$SCRIPT_DIR/run_qemu_replay.sh" \
                    "$candidate" "$triage_dir/replay" || replay_status=$?
            printf 'replay_exit=%s\n' "$replay_status" >> "$triage_dir/status.txt"
            if [ "$replay_status" -eq 0 ]; then
                printf 'reproduced=yes\n' >> "$triage_dir/status.txt"
            else
                printf 'reproduced=no\n' >> "$triage_dir/status.txt"
            fi
        else
            printf 'replay=not_run\n' >> "$triage_dir/status.txt"
        fi
    done
fi
if [ "$classification" = HARNESS_ERROR ] || [ "$classification" = COVERAGE_INVALID ]; then
    exit 2
fi
exit "$status"

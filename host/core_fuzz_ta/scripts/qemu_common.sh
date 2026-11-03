# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026, Jaehun Lee
#
# Settings shared by run_qemu_fuzz.sh and run_qemu_replay.sh. Source it after
# setting SCRIPT_DIR. It expects the OP-TEE QEMU development tree layout
# (repo manifest qemu_v8.xml): build/, optee_os/, optee_test/, out-br/.
#
# Overridable from the environment:
#   TA_DEV_KIT_DIR       default: OPTEE_OS_TA_DEV_KIT_DIR from build/
#   OPTEE_CLIENT_EXPORT  default: the Buildroot sysroot's usr/
#   CROSS_COMPILE        default: AARCH64_CROSS_COMPILE from build/
#   FUZZ_OUTPUT_DIR      default: host/core_fuzz_ta/out/fuzz_out

ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/../../../.." && pwd)
FUZZER_DIR=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
TA_SRC_DIR=$(CDPATH='' cd -- "$FUZZER_DIR/../../ta/core_fuzz_ta" && pwd)

# Prints a variable as the OP-TEE build tree (and `make check`) sees it.
build_var() {
    make -s -C "$ROOT/build" \
        --eval="core-fuzz-print:;@printf \"%s\\n\" \"\$($1)\"" core-fuzz-print
}

# Maps a path below $ROOT to the guest's 9p mount of $ROOT.
guest_path() {
    case "$1" in
        "$ROOT"/*) printf '/mnt/host/%s\n' "${1#"$ROOT"/}" ;;
        *) echo "$1 is outside the QEMU 9p share $ROOT" >&2; return 1 ;;
    esac
}

TA_UUID=$(sed -n 's/^BINARY[[:space:]]*=[[:space:]]*//p' "$TA_SRC_DIR/Makefile")
TA_FILE="$ROOT/out-br/target/lib/optee_armtz/$TA_UUID.ta"
TA_DEV_KIT_DIR=${TA_DEV_KIT_DIR:-$(build_var OPTEE_OS_TA_DEV_KIT_DIR)}
TA_CONF="$TA_DEV_KIT_DIR/host_include/conf.mk"
BR_SYSROOT="$ROOT/out-br/host/aarch64-buildroot-linux-gnu/sysroot"
OPTEE_CLIENT_EXPORT=${OPTEE_CLIENT_EXPORT:-"$BR_SYSROOT/usr"}
CROSS_COMPILE=${CROSS_COMPILE:-"$ROOT/out-br/host/bin/aarch64-linux-gnu-"}
RUNNER_BUILD_DIR="$FUZZER_DIR/out"
RUNNER="$RUNNER_BUILD_DIR/core_fuzz_ta/core-fuzz-ta-libafl"
SEED_DIR="$FUZZER_DIR/out/seeds"

# Prints "on" or "off" for a boolean CFG_ option of the TA dev kit.
ta_conf() {
    if grep -qx "$1=y" "$TA_CONF"; then echo on; else echo off; fi
}

check_build() {
    if [ ! -f "$TA_CONF" ]; then
        echo "TA dev kit not found: $TA_DEV_KIT_DIR" >&2
        exit 2
    fi
    if [ "$(ta_conf CFG_CORE_FUZZ_COVERAGE)" != on ]; then
        echo "Build OP-TEE with CFG_CORE_FUZZ_COVERAGE=y first" >&2
        exit 2
    fi
    if [ ! -f "$TA_FILE" ]; then
        echo "Build the signed core_fuzz_ta first: $TA_FILE" >&2
        exit 2
    fi
}

build_runner() {
    make -C "$FUZZER_DIR" O="$RUNNER_BUILD_DIR" CROSS_COMPILE="$CROSS_COMPILE" \
        TA_DEV_KIT_DIR="$TA_DEV_KIT_DIR" \
        OPTEE_CLIENT_EXPORT="$OPTEE_CLIENT_EXPORT" core_fuzz_ta
}

# Validates FUZZ_OUTPUT_DIR, creates it and makes it absolute.
setup_output_dir() {
    FUZZ_OUTPUT_DIR=${FUZZ_OUTPUT_DIR:-"$FUZZER_DIR/out/fuzz_out"}
    case "$FUZZ_OUTPUT_DIR" in
        /*) ;;
        *) FUZZ_OUTPUT_DIR="$ROOT/$FUZZ_OUTPUT_DIR" ;;
    esac
    case "$FUZZ_OUTPUT_DIR" in
        *[!A-Za-z0-9_./-]*)
            echo "FUZZ_OUTPUT_DIR may only contain letters, numbers," \
                "slash, dot, underscore and hyphen" >&2
            exit 2 ;;
    esac
    FUZZ_OUTPUT_DIR=$(realpath -m -- "$FUZZ_OUTPUT_DIR")
    case "$FUZZ_OUTPUT_DIR" in
        "$ROOT"/*) ;;
        *)
            echo "FUZZ_OUTPUT_DIR must be inside $ROOT (the QEMU 9p share)" >&2
            exit 2 ;;
    esac
    mkdir -p "$FUZZ_OUTPUT_DIR"
    FUZZ_OUTPUT_DIR=$(CDPATH='' cd -- "$FUZZ_OUTPUT_DIR" && pwd -P)
}

# Sets QEMU and QEMU_CHECK_ARGS from build/, sharing $ROOT with the guest.
setup_qemu() {
    QEMU=$(build_var QEMU_BIN)
    QEMU_CHECK_ARGS="$(build_var QEMU_CHECK_ARGS)"
    QEMU_CHECK_ARGS="$QEMU_CHECK_ARGS -fsdev local,id=fsdev0,path=$ROOT,security_model=none"
    QEMU_CHECK_ARGS="$QEMU_CHECK_ARGS -device virtio-9p-device,fsdev=fsdev0,mount_tag=host"
    FUZZ_TA_UUID="$TA_UUID"
    FUZZ_GUEST_TA=$(guest_path "$TA_FILE")
    FUZZ_GUEST_RUNNER=$(guest_path "$RUNNER")
    FUZZ_GUEST_SEED_DIR=$(guest_path "$SEED_DIR")
    export QEMU QEMU_CHECK_ARGS FUZZ_TA_UUID FUZZ_GUEST_TA FUZZ_GUEST_RUNNER FUZZ_GUEST_SEED_DIR
}

# Keep QEMU's relative boot paths and serial1.log private to this worker.
prepare_qemu_workdir() {
    QEMU_WORK_DIR=${QEMU_WORK_DIR:-"$FUZZ_OUTPUT_DIR/qemu"}
    mkdir -p "$QEMU_WORK_DIR"
    for name in Image linux.bin uImage rootfs.cpio.uboot bl1.bin bl2.bin \
                bl31.bin bl32.bin bl32_extra1.bin bl32_extra2.bin bl33.bin \
                rootfs.cpio.gz qemu_v8.dtb; do
        source_file="$ROOT/out/bin/$name"
        if [ -e "$source_file" ]; then
            ln -sfn "$source_file" "$QEMU_WORK_DIR/$name"
        fi
    done
    QEMU_WORK_DIR=$(CDPATH='' cd -- "$QEMU_WORK_DIR" && pwd -P)
    export QEMU_WORK_DIR
}

#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../../../.." && pwd)
QEMU=$(make -s -C "$ROOT/build" \
	--eval='fuzz-print-qemu:;@printf "%s\n" "$(QEMU_BIN)"' \
	fuzz-print-qemu)
BASE_ARGS=$(make -s -C "$ROOT/build" \
	--eval='fuzz-print-args:;@printf "%s\n" "$(QEMU_CHECK_ARGS)"' \
	fuzz-print-args)

QEMU_CHECK_ARGS="$BASE_ARGS -fsdev local,id=fsdev0,path=$ROOT,security_model=none"
QEMU_CHECK_ARGS="$QEMU_CHECK_ARGS -device virtio-9p-device,fsdev=fsdev0,mount_tag=host"
export QEMU QEMU_CHECK_ARGS

python3 "$ROOT/optee_test/ta/core_fuzz_ta/make_seeds.py"

cd "$ROOT/out/bin"
status=0
expect "$ROOT/optee_test/ta/core_fuzz_ta/host/qemu_smoke.exp" || status=$?
if [ -f serial1.log ]; then
	cp serial1.log fuzz-stage1-secure.log
fi
exit "$status"

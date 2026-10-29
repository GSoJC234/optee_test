# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026, Jaehun Lee
#
# Builds the LibAFL runner for ta/core_fuzz_ta. This is not part of the
# default optee_test build: it needs a Rust toolchain and a TA dev kit from an
# optee_os built with CFG_CORE_FUZZ_COVERAGE=y.
#
# Inputs, named as for host/xtest:
#   CROSS_COMPILE        toolchain prefix for the normal-world guest
#   TA_DEV_KIT_DIR       optee_os export-ta_<arch> directory
#   OPTEE_CLIENT_EXPORT  directory with include/tee_client_api.h and lib/libteec.so
#   O                    output directory (default: ./out)
#   RUST_TARGET          Rust target triple (default: derived from CROSS_COMPILE)
#   CARGO                cargo command (default: cargo from PATH)
#
# Targets:
#   core_fuzz_ta (default)  cross-build $(O)/core_fuzz_ta/core-fuzz-ta-libafl
#   check                   rustfmt, clippy and tests of the portable library;
#                           needs neither the inputs above nor a TEE
#   clean                   remove $(O)/core_fuzz_ta

include ../../scripts/common.mk

O ?= $(CURDIR)/out
out-dir := $(call strip-trailing-slashes-and-dots,$(O))
ifeq ($(out-dir),)
$(error invalid output directory (O=$(O)))
endif
build-dir := $(abspath $(out-dir))/core_fuzz_ta

OPTEE_CLIENT_EXPORT ?= ../../../optee_client/out/export
CARGO ?= cargo

-include $(TA_DEV_KIT_DIR)/host_include/conf.mk

# CROSS_COMPILE may carry a launcher such as "ccache aarch64-linux-gnu-". The
# Rust linker and the cc crate need the plain tool prefix.
cross-prefix := $(lastword $(CROSS_COMPILE))

cc-arch := $(firstword $(subst -, ,$(shell $(cross-prefix)gcc -dumpmachine 2>/dev/null)))
rust-target-aarch64 := aarch64-unknown-linux-gnu
rust-target-arm := armv7-unknown-linux-gnueabihf
rust-target-riscv64 := riscv64gc-unknown-linux-gnu
rust-target-x86_64 := x86_64-unknown-linux-gnu
RUST_TARGET ?= $(rust-target-$(cc-arch))

manifest := $(CURDIR)/Cargo.toml
runner := $(build-dir)/core-fuzz-ta-libafl

# cargo does its own dependency tracking, so it runs on every invocation.
# Only the cc crate in build.rs compiles C, and it gets the prefix explicitly.
cargo-env := env -u CROSS_COMPILE

.PHONY: all
all: core_fuzz_ta

# `cargo rustc` passes the arguments after `--` to the final link only. Build
# scripts and proc macros keep the host linker, which matters when the build
# host and the guest share a target triple (e.g. an AArch64 development VM).
.PHONY: core_fuzz_ta
core_fuzz_ta:
ifeq ($(wildcard $(TA_DEV_KIT_DIR)/host_include/conf.mk),)
	$(error TA_DEV_KIT_DIR must point to an optee_os TA dev kit (export-ta_<arch>))
endif
ifneq ($(CFG_CORE_FUZZ_COVERAGE),y)
	$(error the TA dev kit in $(TA_DEV_KIT_DIR) is not built with CFG_CORE_FUZZ_COVERAGE=y)
endif
ifeq ($(wildcard $(OPTEE_CLIENT_EXPORT)/include/tee_client_api.h),)
	$(error OPTEE_CLIENT_EXPORT must contain include/tee_client_api.h and lib/libteec.so)
endif
ifeq ($(RUST_TARGET),)
	$(error cannot derive RUST_TARGET from $(cross-prefix)gcc; set RUST_TARGET)
endif
	@echo '  CARGO   $(runner)'
	$(q)mkdir -p $(build-dir)
	$(q)$(cargo-env) \
		CORE_FUZZ_CROSS_COMPILE=$(cross-prefix) \
		TA_DEV_KIT_DIR=$(abspath $(TA_DEV_KIT_DIR)) \
		OPTEE_CLIENT_EXPORT=$(abspath $(OPTEE_CLIENT_EXPORT)) \
		CARGO_TARGET_DIR=$(build-dir)/cargo \
		$(CARGO) rustc --locked --release --manifest-path $(manifest) \
			--bin core-fuzz-ta-libafl --target $(RUST_TARGET) \
			-- -C linker=$(cross-prefix)gcc
	$(q)cp $(build-dir)/cargo/$(RUST_TARGET)/release/core-fuzz-ta-libafl $(runner)

.PHONY: check
check:
	$(q)$(cargo-env) $(CARGO) fmt --check --manifest-path $(manifest)
	$(q)$(cargo-env) CARGO_TARGET_DIR=$(build-dir)/cargo-host \
		$(CARGO) clippy --locked --no-default-features --all-targets \
			--manifest-path $(manifest) -- -D warnings
	$(q)$(cargo-env) CARGO_TARGET_DIR=$(build-dir)/cargo-host \
		$(CARGO) test --locked --no-default-features --manifest-path $(manifest)

.PHONY: clean
clean:
	$(q)rm -rf $(build-dir)

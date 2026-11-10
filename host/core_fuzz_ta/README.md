# core_fuzz_ta LibAFL host runner

This is an optional Linux host-side fuzzer for the TA in `ta/core_fuzz_ta/`.
It uses LibAFL to mutate the TA's versioned command stream and sends each
input through `libteec`. The TA and OP-TEE core remain the fuzz target; LibAFL
is not linked into the secure world or into `xtest`.

## Requirements

- Rust 1.86 or newer (edition 2024), with the standard library for the guest
  target (`rustup target add <triple>` when it differs from the build host)
- An optee_os TA dev kit built with `CFG_CORE_FUZZ_COVERAGE=y`, which provides
  the coverage PTA and `pta_core_fuzz_cov.h`
- libteec headers and library from optee_client

LibAFL dependencies are pinned in `Cargo.toml` and `Cargo.lock`. The default
optee_test build (`make`, CMake, Buildroot, Android) does not invoke Cargo, and
`ta/Makefile.gmake` builds the TA only with `CFG_CORE_FUZZ_COVERAGE=y`.

## Build

The Makefile takes the same inputs as `host/xtest`:

| Variable | Meaning |
| --- | --- |
| `CROSS_COMPILE` | Toolchain prefix for the normal-world guest |
| `TA_DEV_KIT_DIR` | optee_os `export-ta_<arch>` directory |
| `OPTEE_CLIENT_EXPORT` | Directory with `include/tee_client_api.h` and `lib/libteec.so` |
| `O` | Output directory (default `out/`) |
| `RUST_TARGET` | Rust target triple; derived from `$(CROSS_COMPILE)gcc` for AArch64, Arm and RISC-V |

From the optee_test top level, with the variables used for `xtest`:

```sh
make core_fuzz_ta CROSS_COMPILE_HOST=aarch64-linux-gnu- \
    TA_DEV_KIT_DIR=<optee_os>/out/arm/export-ta_arm64 \
    OPTEE_CLIENT_EXPORT=<optee_client export>/usr
```

This writes `$(O)/core_fuzz_ta/core-fuzz-ta-libafl`. It is not part of the
default `all` target. `cargo rustc` passes the cross linker to the final link
only, so build scripts keep the host linker even when the build host and the
guest share a target triple.

In the OP-TEE QEMU development tree the scripts below use the Buildroot
toolchain wrapper and sysroot, and build the runner before each run.

## Run and replay

Use the wrapper scripts from the OP-TEE development tree:

```sh
~/optee/optee_test/host/core_fuzz_ta/scripts/run_qemu_fuzz.sh 200 1
~/optee/optee_test/host/core_fuzz_ta/scripts/run_qemu_fuzz.sh 200 1 --algorithms=sha256,aes-gcm
~/optee/optee_test/host/core_fuzz_ta/scripts/run_qemu_replay.sh \
  ~/optee/optee_test/host/core_fuzz_ta/out/fuzz_out/run-YYYYMMDDHHMMSS/corpus/id-00000001.bin
```

`--algorithms=LIST` accepts a comma-separated set: `sha256`, `sha512`,
`hmac-sha256`, `aes-ctr`, `aes-gcm`, `hkdf`,
`rsa-pkcs1v15-sha256`, `rsaes-pkcs1v15`, `aes-ccm`,
`rsa-pss-sha256`, `rsa-oaep-sha256`, and `random`. The default is `all`.
The selected set filters whole seed programs and all mutator outputs before
they reach the TA. Object setup needed by a selected algorithm remains
available; a seed mixing selected and unselected algorithms is excluded.
The core coverage build is reused across campaigns and is not rebuilt by the
runner script. Build it once with `CFG_CORE_FUZZ_COVERAGE=y`; its linked
crypto implementations default to being instrumented.

The wrapper generates baseline inputs under
`host/core_fuzz_ta/out/seeds/`; generated files are ignored by Git. Fuzz
campaign artifacts go under `host/core_fuzz_ta/out/fuzz_out/` by default. Set `FUZZ_OUTPUT_DIR` to another path below `~/optee` to override this location. For example:

```sh
FUZZ_OUTPUT_DIR="$HOME/optee/out/fuzz" \
  ~/optee/optee_test/host/core_fuzz_ta/scripts/run_qemu_fuzz.sh 200 1
```

The `invariants.toml` usage rules check AES-CTR encryption and decryption after
restricting a fresh key to either `TEE_USAGE_ENCRYPT` or `TEE_USAGE_DECRYPT`.
Their `restrict_usage.mask` bindings match only the exact requested mask.
The allowed rules check valid operations; the denied rules report a violation
if a restricted key actually performs the forbidden operation. The generated
seeds exercise all four cases. Replay prints
`FUZZ_INVARIANT_CHECK`, and campaigns save counterexamples in `violations/`.

For independent QEMU workers, set `FUZZ_WORKERS` (up to 16):

```sh
FUZZ_WORKERS=2 ~/optee/optee_test/host/core_fuzz_ta/scripts/run_qemu_fuzz.sh 400 42
```

The wrapper starts one host-side LibAFL TCP broker and gives each QEMU worker
its own output directory, secure log and RNG seed. The guests connect through
QEMU user networking to the broker on the host loopback. LibAFL forwards new
corpus inputs as events; each receiving worker executes them against its own
OP-TEE core before deciding whether to keep them. `FUZZ_CORPUS_IMPORTED` counts
inputs accepted into that worker's corpus. The campaign directory contains
`broker.log`, `config.txt` and `status.tsv`, and each worker keeps its own run
artifacts. The broker binary is hashed in each worker's manifest.

The per-input timeout defaults to 360 seconds with this coverage build.
Set `FUZZ_EXECUTION_TIMEOUT_SECONDS` to 1..3600 to tune it; the whole QEMU
fuzz run has a separate `FUZZ_TIMEOUT` limit (default 1800 seconds), which
must also cover loading every seed before the requested fuzz duration starts.
Each run writes `manifest.json` with OP-TEE core image, TA, runner and TA
configuration and harness script SHA-256 hashes; `optee_os` and `optee_test` revisions and dirty
flags; coverage options; selected seed hashes; the algorithm set, RNG seed; and timeouts. The
legacy `build-config.txt` remains for quick reading. `status.json` records the
primary outcome, reason, phase and diagnostic counters; `normal.log` and
`secure.log` retain the evidence. A dirty revision means the commit alone is
insufficient to recreate the binaries, so use their hashes to verify a rebuild.

Only a secure-console ASan report or core panic during input execution is a
core crash. These inputs go in `crashes/`. LibAFL timeouts and QEMU watchdog
inputs go in `hangs/` as candidates. A fresh QEMU replay records its own
`status.json`, `manifest.json`, logs and whether it reproduced the expected
outcome. TEEC invocation failures are `HARNESS_ERROR`; missing or malformed
coverage is `COVERAGE_INVALID`. Deliberately malformed streams rejected with
`TEEC_ERROR_BAD_PARAMETERS` are counted as `REJECTED_INPUTS`. Boot and normal-world failures have separate
classifications and are never counted as core crashes. The wrapper replays at
most one LibAFL hang candidate automatically by default; set
`FUZZ_MAX_AUTO_REPLAY_HANGS` to change this count, or
`FUZZ_AUTO_REPLAY_HANGS=0` to skip LibAFL hang replay. Candidates that were
not replayed record `replay=not_run` in their triage status.

The override must be inside the QEMU-shared `~/optee` tree and use a path
without spaces. `run_qemu_replay.sh` uses the same variable for its default
`replay-*` directory; an explicit `OUTPUT_DIR` argument overrides it for that
replay. `--replay` executes one saved input in a fresh QEMU guest. Input and
response layouts are defined in `ta/core_fuzz_ta/include/core_fuzz_ta.h`.
Rust constants are regenerated from that header during the build, and
`scripts/make_seeds.py` reads its opcode enum when generating crypto seeds.

## Code layout

The crate is split so that everything except the TEEC client can be tested
on a development host:

- `src/lib.rs` and its modules (no libteec, no TEE): `protocol` (constants
  generated from the TA header), `program` (FZP2 parse/encode), `mutator`
  (structured LibAFL edits), `crypto_mutator` (crypto-specific field values),
  `response` (FZR2 decoder and per-opcode counters), `algorithms`, `cli`, `stats` and
  `output`.
- `src/main.rs` and `src/runner/` (the `runner` feature, on by default):
  the `teec_shim.c` wrapper, the coverage map and the fuzz and replay loops.
- `src/bin/broker.rs`: the host-side TCP broker for multi-worker campaigns.

`core-fuzz-ta-libafl --help` lists the command-line forms.

## Rust checks

`make check` runs rustfmt, clippy (`-D warnings`) and the tests of the
library: input parser and encoder, mutator, response decoder, command line
and output files. It needs only a Rust toolchain, no TA dev kit or TEE, and
is what CI runs:

```sh
make -C host/core_fuzz_ta check
```

Campaign run directories are named from the current UTC time.

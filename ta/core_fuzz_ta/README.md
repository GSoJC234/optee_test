# OP-TEE S-EL0 core fuzz TA and mini fuzzer

This TA executes bounded digest, HMAC, transient-object, cipher,
authenticated-encryption, key-derivation, RNG and asymmetric crypto syscall
sequences from S-EL0. Its algorithm selectors include SHA-256, SHA-512,
HMAC-SHA256, AES-CTR, AES-GCM, HKDF-SHA256, RSA signatures and RSA
encryption/decryption.
The single-input Linux client remains available for smoke tests. A separate
coverage-guided client mutates the same input format, collects OP-TEE core
feedback and retains useful inputs.

## Wire format

All multi-byte fields are little endian. The input is at most 4096 bytes.

| Offset | Size | Meaning |
| --- | ---: | --- |
| 0 | 4 | ASCII `FZP2` |
| 4 | 1 | Version `2` |
| 5 | 1 | Operation count, 1..64 |
| 6 | 2 | Reserved, zero |

Each operation has a 7-byte header followed by `data_len` bytes:

| Offset | Size | Meaning |
| --- | ---: | --- |
| 0 | 1 | Opcode, 1..27 |
| 1 | 1 | Slot, 0..7; state or object slot according to opcode |
| 2 | 1 | Opcode-specific selector, described below |
| 3 | 2 | `data_len` |
| 5 | 2 | Opcode-specific `aux`, described below |

Version 1 inputs used an 8-byte operation header and must be regenerated for
this layout. State slots and object slots are separate arrays of eight handles.
Each invocation begins with both arrays empty. The opcodes are:

| Opcode | Name | Action and relevant fields |
| ---: | --- | --- |
| 1 | ALLOC | Allocate state in `slot`. `selector` 0: SHA-256 digest; 1: SHA-512 digest; 2: HMAC-SHA256; 3/4: AES-CTR encrypt/decrypt; 5/6: AES-GCM encrypt/decrypt; 7: HKDF-SHA256 derive; 8/9: RSA-SHA256 sign/verify; 10/11: RSAES-PKCS1-v1_5 encrypt/decrypt. For selectors 2..11, `aux` is the key object slot (0..7). |
| 2 | INIT | Initialize a digest or MAC state with `_utee_hash_init`. |
| 3 | UPDATE | Pass `data` to `_utee_hash_update`. |
| 4 | FINAL | Pass `data` to `_utee_hash_final` with output capacity `aux` (0..64). |
| 5 | FREE | Free the state in `slot`. The core also closes a key object bound to that state. |
| 6 | OBJ_ALLOC | Allocate a transient object in `slot`. `selector` 0: HMAC-SHA256 key; 1: generic secret; 2: AES key; 3: HKDF IKM; 4: RSA keypair. `aux` is maximum key bits, with zero meaning 256. |
| 7 | OBJ_POPULATE | Populate the object from `data`; `selector` 0 uses `TEE_ATTR_SECRET_VALUE`, 1 uses `TEE_ATTR_HKDF_IKM`. |
| 8 | OBJ_CLOSE | Close the object in `slot`. |
| 9 | OBJ_GET_INFO | Retrieve the object's information into the result record. |
| 10 | OBJ_RESTRICT_USAGE | Intersect object usage with the `aux` bit mask. |
| 11 | OBJ_RESET | Reset the transient object to its uninitialized state. |
| 12 | OBJ_GET_ATTR | Read an attribute using capacity `aux` (0..32). `selector` 0 selects `TEE_ATTR_SECRET_VALUE`; other selector values are passed as attribute IDs. |
| 13 | OBJ_COPY | Copy the object in source slot `selector` to uninitialized destination `slot`. |
| 14 | OBJ_GENERATE_KEY | Generate a key in the object at `slot`; `aux` is key bits, with zero meaning 256. |
| 15 | STATE_COPY | Copy the crypto state in source state slot `selector` to destination state slot `slot`. |
| 16 | CIPHER_INIT | Initialize a cipher state in `slot` with IV `data`. |
| 17 | CIPHER_UPDATE | Process `data` with the cipher; `aux` is output capacity (0..256). |
| 18 | CIPHER_FINAL | Finalize the cipher with `data`; `aux` is output capacity (0..256). |
| 19 | DERIVE_KEY | Derive into destination object slot `selector` from state `slot`. `aux` is output key bytes (0..256); `data` is optional HKDF salt. |
| 20 | RANDOM | Generate `aux` random bytes (0..256). |
| 21 | AUTHENC_INIT | Initialize authenticated encryption with nonce `data`. `selector` is tag length in bytes (zero means 16, maximum 16); the high and low bytes of `aux` are the declared AAD and payload lengths. |
| 22 | AUTHENC_UPDATE_AAD | Pass `data` as additional authenticated data. |
| 23 | AUTHENC_UPDATE_PAYLOAD | Process payload `data`; `aux` is output capacity (0..256). |
| 24 | AUTHENC_ENC_FINAL | Encrypt final payload `data`; `aux` is output capacity (0..256), and `selector` is tag length in bytes (zero means 16, maximum 16). |
| 25 | AUTHENC_DEC_FINAL | `data` is the tag followed by final ciphertext. `selector` is tag length in bytes (zero means 16, maximum 16), and `aux` is plaintext capacity (0..256). |
| 26 | ASYMM_OPERATE | Sign or RSA encrypt/decrypt `data`; `aux` is output capacity (0..256). The full successful output is retained for opcode 27. |
| 27 | ASYMM_VERIFY | Verify a signature over a digest in `data`. With `selector` 0, `aux` is digest length and the remaining `data` bytes are the signature; with `selector` 1, `data` is the digest and the signature is the last successful opcode 26 output. |

The HMAC success sequence is OBJ_ALLOC (HMAC key) -> OBJ_POPULATE ->
ALLOC (HMAC-SHA256, referring to that object slot) -> INIT -> UPDATE ->
FINAL -> FREE. FREE closes a linked key object, so a sequence that needs the
same key later must copy the object before binding it to a state.
Any remaining states are freed before remaining objects on invocation exit.
An unset slot is passed as handle zero so the core can return an
invalid-handle result. Fields unused by an opcode remain legal fuzz input.

The table above defines the canonical input format for REE generators. The TA
copies REE shared memory into private memory, then checks only the bounds needed
for safe execution: operation count, each record's header and payload length,
slot index, bounded output capacities, and tag and signature field lengths.
Header magic, version, reserved fields,
operation-specific unused fields, unknown opcodes, zero operations, and trailing
bytes are accepted. It returns one 40-byte result per declared operation.
The result header is `FZR2`, version, count and two reserved bytes. Each result
contains a 32-bit syscall result, opcode, slot, 16-bit reported output length,
and up to 32 output bytes. FINAL stores the full digest length but only its
first 32 bytes; for successful SHA-512, the reported length is 64 and the
record contains a 32-byte prefix. Other byte-producing operations report
their full output length and retain at most the first 32 bytes in the result.
AUTHENC_ENC_FINAL instead stores up to 16 ciphertext bytes followed by up to
16 tag bytes. OBJ_GET_INFO writes the object information, and OBJ_GET_ATTR
writes at most 32 attribute bytes. Syscall errors and
unknown-opcode errors are result values. Record bounds violations return
`TEE_ERROR_BAD_PARAMETERS` from the TA command. The host client prints
`TEEC_ERROR_TARGET_DEAD` separately if the TA dies.

## Build

From the Ubuntu development VM:

```sh
make -C ~/optee/build -j4 optee-os \
  CFG_CORE_FUZZ_COVERAGE=y CFG_CORE_SANITIZE_KADDRESS=y CFG_CORE_ASLR=n
make -C ~/optee/build -j4 arm-tf \
  CFG_CORE_FUZZ_COVERAGE=y CFG_CORE_SANITIZE_KADDRESS=y CFG_CORE_ASLR=n
make -C ~/optee/build -j4 buildroot \
  CFG_CORE_FUZZ_COVERAGE=y CFG_CORE_SANITIZE_KADDRESS=y CFG_CORE_ASLR=n
make -C ~/optee/optee_test/ta/core_fuzz_ta/host
```

Run these build targets in order: TF-A must package the newly built core.
Use the same three options when rebuilding this image, or make may replace it
with a coverage-only core. `CFG_CORE_SANITIZE_KADDRESS=y` enables core KASan;
OP-TEE requires `CFG_CORE_ASLR=n` with this option. The TA sanitizer remains
off (`CFG_TA_SANITIZE_KADDRESS=n`). Core KASan adds substantial CPU and memory
cost; use this build for bug finding rather than throughput measurements.
`CFG_CORE_FUZZ_COVERAGE` defaults to `n` outside this test build. When enabled,
GCC instruments `core/tee/tee_svc_cryp.c` with `-fsanitize-coverage=trace-pc`.
The uninstrumented coverage PTA records a 16 KiB byte map for one TA invocation.
Each ID hashes a core-ASLR-relative call site together with the previous call
site, so this is PC-derived edge feedback with possible hash collisions. It
currently measures only the crypto syscall service file, not every core file.

The in-tree TA is built and signed by `optee-os`. Its UUID is
`92ea581c-d6ec-449e-9aa6-cf93aa2b44dd`; the file is under
`~/optee/out-br/target/lib/optee_armtz/`. The client links against the
Buildroot `libteec` sysroot. The Ubuntu VM itself has no `/dev/tee`: run the
client in the nested OP-TEE QEMU normal-world guest after the TA and client
are available there.

For a baseline boot and client smoke test in the nested QEMU guest:

```sh
make -C ~/optee/build -j4 check \
  CFG_CORE_FUZZ_COVERAGE=y CFG_CORE_SANITIZE_KADDRESS=y CFG_CORE_ASLR=n \
  CHECK_TESTS=xtest XTEST_ARGS=1001
~/optee/optee_test/ta/core_fuzz_ta/host/run_qemu_smoke.sh
```

The smoke script regenerates all 17 seed files, then uses virtio 9p to
share `~/optee` with QEMU. It copies the latest signed TA into the guest and
checks the original five seed cases, then exits QEMU. The newer crypto/object
cases enter the fuzzer baseline corpus; the stage-1 smoke script does not
assert their results. The normal-world and secure-world logs are
`~/optee/out/bin/fuzz-stage1-normal.log` and
`~/optee/out/bin/fuzz-stage1-secure.log`.

To confirm the image configuration after building, check
`~/optee/optee_os/out/arm/conf.mk` for `CFG_CORE_SANITIZE_KADDRESS=y`,
`CFG_CORE_ASLR=n`, and `CFG_CORE_FUZZ_COVERAGE=y`. The linked `tee.elf` should
contain both `__asan_load*` and `__sanitizer_cov_trace_pc` symbols. A detected
core memory violation is printed on the secure console as
`[ASAN]: access violation, addr: ... size: ...`; the default callback then
panics the core. `xtest 1001` intentionally triggers several KASan reports
while testing the sanitizer with a recovery callback. Its `[ASAN]` lines and
`regression_1001.1 OK` are expected self-test evidence, not fuzz findings.

## Seeds

`make_seeds.py` generates 17 reproducible files in `seeds/`. These generated
files are ignored by Git. Run
`python3 ~/optee/optee_test/ta/core_fuzz_ta/make_seeds.py` to create them without
running the smoke test.

- `sha256_abc.bin`: complete SHA-256 state lifecycle; expected digest
  `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`.
- `invalid_handle.bin`: core error results from a never-allocated state slot.
- `interleaved_slot.bin`: valid SHA-256 lifecycle in slot 0 with another state
  in slot 1 interleaved.
- `short_digest_buffer.bin`: FINAL capacity one, expecting
  `TEE_ERROR_SHORT_BUFFER` (`0xffff0010`) and required length 32.
- `truncated_record.bin`: malformed framing, expecting a TA command error.
- `sha512_abc.bin`: SHA-512 lifecycle with FINAL capacity 64; the result
  records length 64 and its first 32 digest bytes.
- `hmac_sha256_abc.bin`: 256-bit HMAC key in object slot 4, HMAC state in
  state slot 0, INIT/UPDATE/FINAL, then FREE.
- `object_lifecycle.bin`: HMAC key population, info and attribute reads,
  usage restriction, reset, key generation, and close.
- `object_copy.bin`: populate source object slot 2, copy to destination slot
  3, read the copied secret, then close both.
- `aes_generated_key.bin`: AES object allocation, 128-bit key generation,
  info/attribute reads, and close.
- `state_copy_sha256.bin`: copy an initialized SHA-256 state and finalize both
  copies independently.
- `aes_ctr.bin`: AES-CTR initialization, update and final with a fixed key and IV.
- `hkdf_sha256.bin`: derive a 32-byte generic secret from HKDF IKM and salt.
- `random_32.bin`: request 32 random bytes.
- `gcm_encrypt.bin`: AES-GCM initialization, AAD, payload update and encryption
  finalization with a 16-byte tag.
- `gcm_decrypt_empty.bin`: authenticate the AES-GCM empty-message test vector;
  its data begins with the known 16-byte tag.
- `rsa_sign_verify.bin`: generate a 2048-bit RSA keypair, copy it before the
  signing state consumes the original, then sign and verify a SHA-256 digest.

Run the same file repeatedly with `core_fuzz_ta_ca INPUT_FILE [REPEAT_COUNT]`.
The client opens a new TA session for every repetition and prints each syscall
result. A future syzkaller executor can generate this same byte format.

## Coverage-guided mini fuzzer

After the build above, run a bounded campaign from the Ubuntu development VM:

```sh
~/optee/optee_test/ta/core_fuzz_ta/host/run_qemu_fuzz.sh 200 1
```

The arguments are iteration count, optional deterministic RNG seed, and
optional HOPPER mode (`on` by default). For a coverage-only comparison, run:

```sh
~/optee/optee_test/ta/core_fuzz_ta/host/run_qemu_fuzz.sh 200 1 off
```

`on` enables target-call coverage, predecessor deletion, learned-parent
selection, and learned sequence assembly. `off` keeps whole-sequence core
coverage, ordinary mutation, corpus retention, and crash capture, but does not
run target probes or use learned relations. The guest fuzzer also accepts
`--hopper=on|off` directly after its positional arguments. Run logs include
`FUZZ_HOPPER`, the final mode, and `TA_INVOKES`: attempted host-to-TA
`TEEC_InvokeCommand` calls after a session opens, including replays and probes.
The same iteration count is not the same execution budget across modes.

For a three-hour mutation campaign, use a high iteration ceiling and a QEMU
watchdog greater than the requested duration:

```sh
FUZZ_DURATION_SECONDS=10800 FUZZ_TIMEOUT=14400 \
  ~/optee/optee_test/ta/core_fuzz_ta/host/run_qemu_fuzz.sh 100000000 1 on
```

The duration starts after all 17 seeds have been validated and any HOPPER
baseline probes have completed; total VM wall time can therefore exceed three
hours. `FUZZ_DONE` reports `ELAPSED_SEC` and `STOP_REASON=duration` when the time
limit ends the mutation loop, or `STOP_REASON=iterations` if the iteration
ceiling is reached first. The summary also prints per-opcode call and success
counts as `FUZZ_OPCODE` lines.

The script boots QEMU once, mounts the 9p share, installs the newest signed TA from
`out-br/target/lib/optee_armtz/`, and runs the guest C fuzzer. The fuzzer opens a
fresh TA session per input. It begins core coverage inside the TA before the
crypto/object syscall sequence and ends it after handle cleanup; the old two-memref
`CMD_RUN` call still works. The optional third output memref carries the map.
Malformed inputs rejected before the sequence intentionally have no core
coverage in this version.

For call-dependency learning, `CMD_RUN` also accepts the third output memref
plus a fourth `VALUE_INPUT` whose `a` field is a zero-based operation index
(`b` must be zero). In this mode the TA enables coverage only around that
operation. The ordinary whole-sequence mode and its wire format are unchanged.

The fuzzer loads all `.bin` seeds, mostly mutates operation records while
preserving their bounds, and sometimes mutates raw bytes to test framing.
Its structured mutator generates opcodes 1..27, including state, object,
cipher, authenticated-encryption, KDF, RNG and asymmetric operations.
It executes each seed twice
and replays a candidate when it first sees new map bytes. Only bits present
in both executions are committed. New inputs become future mutation parents.
The `feedback_criterion` registry in `host/core_fuzz_ta_fuzzer.c` has separate
`new_features` and `commit` callbacks so later criteria can inspect execution
results without changing the mutation loop.

The fuzzer also tracks target-operation edges separately for each opcode.
When a target reaches unseen edges, it replays the input in fresh TA sessions
and requires identical target coverage and result records. It then deletes
earlier operations one at a time, replays each deletion twice, and records an
earlier operation as an effective predecessor if removing it changes the
target's coverage, result code, or output. Unrelated predecessors are removed
from the saved witness. At most 16 predecessors are probed per new target path
to bound the extra executions. These are observed effects for a particular
input, not universal API preconditions. Target probes consider operation
indices 1..count-1: state opcodes INIT, UPDATE, FINAL and FREE (2..5), and
opcodes 6..27. State ALLOC (1) is never a target, and an OBJ_ALLOC in the
first position is not probed. Whole-sequence core coverage still includes
all executed operations.
Each relation records whether the target core map or its 40-byte result record
changed. A cross-slot coverage-only relation can reflect shared core state or
handle lookup behavior; it is not labeled as a handle producer requirement.

Reduced witnesses become mutation parents. One quarter of parent selections
prefer this learned pool; half of those mutations alter payload or FINAL
capacity while preserving the witness's call sequence. Other mutations still
explore invalid orderings and handles. Structured mutation can also insert a
new call before a target using the target's slot as a producer/consumer hint.
The fuzzer also assembles new programs: it takes the verified predecessor
prefix from one learned witness and a matching target opcode (including its
arguments) from a different corpus entry, rebinding the prefix to the target's
slot. Only witnesses whose remaining predecessors were all deletion-checked
and use the target slot are assembly templates; cross-slot coverage-only
observations are not treated as required producers. Assembly currently accepts
only unkeyed state operations 1..5. Object operations and HMAC state allocation
depend on separate object and state slots; the one-slot rebinding rule cannot
safely transplant those dependencies. Their paths can still enter the ordinary
corpus and the learner can record their observed predecessor effects.
The assembled program
runs through the ordinary crash, whole-sequence coverage, and target-coverage
feedback paths. The summary distinguishes assembly attempts, generated
programs, target result records and successes, and new edges attributable to
assembly. The first 32 assembled inputs per run are saved with both corpus
parent indices for reproduction. This reuses observed sequences without
turning an input-specific relation into a universal API rule.
This is inspired by HOPPER's
target-call coverage and predecessor deletion; it does not implement its
header-driven API discovery or intra-API constraint inference.

Each run creates `~/optee/out/fuzz/run-XXXXXX/` outside the source tree:

- `corpus/id-*.bin`, `.cov` and `.txt`: new stable coverage, its map and metadata.
- `target/id-*` (`on` only): stable new coverage for a specific target opcode without a
  confirmed predecessor relation.
- `learned/id-*` (`on` only): a reduced target witness; its `.txt` lists predecessors
  whose deletion changed the target observation, with separate coverage and
  result-record evidence. The `.cov` contains only target-operation coverage.
- `assembled/id-*` (`on` only): up to 32 newly assembled programs and metadata naming
  the target source and learned template source.
- `crashes/id-*.bin` and `.txt`: `TEEC_ERROR_TARGET_DEAD` inputs. This
  result indicates TA death and does not by itself prove a core panic.
- `current.bin` and `current.meta`: the last input and its invocation shape.
  Each file is individually published by rename before entering the secure world;
  the two files are not replaced as an atomic pair. `target_index=-1` means
  whole-sequence coverage; `0..63` selects a target operation.
- `normal.log`: the Expect transcript containing the Linux console and
  monitored secure-console tail output; `secure.log`: raw OP-TEE `serial1.log`.
- `build-config.txt`: the campaign's core KASan and ASLR settings.
- `crashes/asan-*/input.bin`, `input.meta`, `original-normal.log`,
  `original-secure.log`, and `status.txt`: a candidate present when the secure
  console reported `[ASAN]`, including the copied invocation shape.
- `crashes/asan-*/replay/input.bin`, `input.meta`, `normal.log`, `secure.log`,
  `phase.txt`, and `status.txt`: one automatic replay in a fresh QEMU VM.
  `reproduced=yes` means `[ASAN]` was observed during the replayed input;
  it does not compare the fault address or stack trace with the original.

An `[ASAN]` report is attributed to an input only when the runner is in
the fuzz phase, the guest has reported its exact `FUZZ_RUN_DIR`, and that run
has a `current.bin`. Otherwise, including boot/setup reports or an unknown run
directory, the runner saves console logs and status under
`~/optee/out/fuzz/asan-unattributed-*/`. It copies no input and starts no
replay for these reports. To replay a saved input manually in a fresh VM, run:

```sh
~/optee/optee_test/ta/core_fuzz_ta/host/run_qemu_replay.sh INPUT_FILE [OUTPUT_DIR]
```

If supplied, `OUTPUT_DIR` must be under `~/optee` so the guest can read the
input through the shared 9p mount. If omitted, the script creates
`~/optee/out/fuzz/replay-XXXXXX/`. A manual replay writes `input.bin`,
`normal.log`, `secure.log`, `phase.txt`, and `status.txt` in that directory.
The replay runner discovers `input.meta` beside an ASan event's `input.bin`, or
`current.meta` beside a run's `current.bin`, and copies it to the replay folder.
It invokes `core_fuzz_ta_ca --reproduce INPUT_FILE [TARGET_INDEX]` so the replay
uses the same three-parameter whole-sequence call or four-parameter target
probe as the original. `status.txt` records `shape_known` and `target_index`.
A manually supplied seed without metadata defaults to whole-sequence coverage
and reports `shape_known=no`.

The outer QEMU runner copies `current.bin` into `crashes/watchdog-*.bin` if a
kernel panic or campaign timeout is observed. A TA parser error such as
`TEE_ERROR_BAD_PARAMETERS` is an expected result, not a crash. A core panic
can halt the VM; restart the runner to begin a new campaign. The first version
runs one fuzzer at a time because the PTA maintains one active coverage map.

The surrounding `build`, `optee_client`, and `optee_test` repositories in this
VM are still at 4.10.0. Align those repositories before treating this as a
4.11.0 whole-stack validation.

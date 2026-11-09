# OP-TEE S-EL0 core fuzz TA

This TA executes bounded digest, HMAC, transient-object, cipher,
authenticated-encryption, key-derivation, RNG and asymmetric crypto syscall
sequences from S-EL0. Its algorithm selectors include SHA-256, SHA-512,
HMAC-SHA256, AES-CTR, AES-GCM, AES-CCM, HKDF-SHA256, RSA PKCS#1 v1.5
signatures/encryption, RSA-PSS and RSA-OAEP with SHA-256.
A Rust LibAFL runner mutates this input format, collects OP-TEE core coverage,
keeps inputs that expose new coverage, and replays saved inputs.

## Wire format

All multi-byte fields are little endian. The input is at most 4096 bytes.

| Offset | Size | Meaning |
| --- | ---: | --- |
| 0 | 4 | ASCII `FZP3` |
| 4 | 1 | Version `3` |
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

Version 1 inputs used an 8-byte operation header. Version 2 used 40-byte
result records; version 3 uses full-output records and indexed references.
Regenerate seeds when switching versions. State slots and object slots are
separate arrays of eight handles.
Each invocation begins with both arrays empty. The opcodes are:

| Opcode | Name | Action and relevant fields |
| ---: | --- | --- |
| 1 | ALLOC | Allocate state in slot. selector 0: SHA-256 digest; 1: SHA-512 digest; 2: HMAC-SHA256; 3/4: AES-CTR encrypt/decrypt; 5/6: AES-GCM encrypt/decrypt; 7: HKDF-SHA256 derive; 8/9: RSA-SHA256 PKCS#1 v1.5 sign/verify; 10/11: RSAES-PKCS1-v1_5 encrypt/decrypt; 12/13: AES-CCM encrypt/decrypt; 14/15: RSA-PSS-SHA256 sign/verify; 16/17: RSA-OAEP-SHA256 encrypt/decrypt. For selectors 2..17, aux is the key object slot (0..7). |
| 2 | INIT | Initialize a digest or MAC state with `_utee_hash_init`. |
| 3 | UPDATE | Pass `data` to `_utee_hash_update`. |
| 4 | FINAL | Pass `data` to `_utee_hash_final` with output capacity `aux` (0..64). |
| 5 | FREE | Free the state in `slot`. The core also closes a key object bound to that state. |
| 6 | OBJ_ALLOC | Allocate a transient object in `slot`. `selector` 0: HMAC-SHA256 key; 1: generic secret; 2: AES key; 3: HKDF IKM; 4: RSA keypair; 5: RSA public key. `aux` is maximum key bits, with zero meaning 256. |
| 7 | OBJ_POPULATE | Populate the object from `data`; `selector` 0 uses `TEE_ATTR_SECRET_VALUE`, 1 uses `TEE_ATTR_HKDF_IKM`. |
| 8 | OBJ_CLOSE | Close the object in `slot`. |
| 9 | OBJ_GET_INFO | Retrieve the object's information into the result record. |
| 10 | OBJ_RESTRICT_USAGE | Intersect object usage with the `aux` bit mask. |
| 11 | OBJ_RESET | Reset the transient object to its uninitialized state. |
| 12 | OBJ_GET_ATTR | Read an attribute using capacity `aux` (0..256). `selector` 0 selects `TEE_ATTR_SECRET_VALUE`; other selector values are passed as attribute IDs. |
| 13 | OBJ_COPY | Copy the object in source slot `selector` to uninitialized destination `slot`. |
| 14 | OBJ_GENERATE_KEY | Generate a key in the object at `slot`; `aux` is key bits, with zero meaning 256. |
| 15 | STATE_COPY | Copy the crypto state in source state slot `selector` to destination state slot `slot`. |
| 16 | CIPHER_INIT | Initialize a cipher state in `slot` with IV `data`. |
| 17 | CIPHER_UPDATE | Process `data` with the cipher; `aux` is output capacity (0..256). With selector `0x80`, `data` is a one-byte index of a previous successful CIPHER_UPDATE or CIPHER_FINAL result to use in full as input. |
| 18 | CIPHER_FINAL | Finalize the cipher with `data`; `aux` is output capacity (0..256). Selector `0x80` has the same indexed-input meaning as CIPHER_UPDATE. |
| 19 | DERIVE_KEY | Derive into destination object slot `selector` from state `slot`. `aux` is output key bytes (0..256); `data` is optional HKDF salt. |
| 20 | RANDOM | Generate `aux` random bytes (0..256). |
| 21 | AUTHENC_INIT | Initialize authenticated encryption with nonce `data`. `selector` is tag length in bytes (zero means 16, maximum 16); the high and low bytes of `aux` are the declared AAD and payload lengths. |
| 22 | AUTHENC_UPDATE_AAD | Pass `data` as additional authenticated data. |
| 23 | AUTHENC_UPDATE_PAYLOAD | Process payload `data`; `aux` is output capacity (0..256). |
| 24 | AUTHENC_ENC_FINAL | Encrypt final payload `data`; `aux` is output capacity (0..256), and `selector` is tag length in bytes (zero means 16, maximum 16). |
| 25 | AUTHENC_DEC_FINAL | Normally `data` is the tag followed by final ciphertext. The low seven bits of `selector` are tag length in bytes (zero means 16, maximum 16), and `aux` is plaintext capacity (0..256). With the high selector bit set, `data` is a one-byte index of a successful AUTHENC_ENC_FINAL result; its full ciphertext and tag become the inputs. |
| 26 | ASYMM_OPERATE | Sign or RSA encrypt/decrypt data; `aux` is output capacity (0..256). Selector 0 uses `data`; selector 1 uses the previous successful opcode 26 output; selector 2 uses the output of the previous successful opcode 26 indexed by the sole byte in `data`. |
| 27 | ASYMM_VERIFY | Verify a signature over a digest in `data`. With selector 0, `aux` is digest length and the remaining `data` bytes are the signature; with selector 1, `data` is the digest and the signature is the last successful opcode 26 output; with selector 2, `aux` indexes the previous successful opcode 26 result to use as the signature. |

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
bytes are accepted. It returns one 280-byte result per declared operation.
The result header is `FZR3`, version, count and two reserved bytes. Each result
contains a 32-bit syscall result, opcode, slot, 16-bit reported output length,
256 output bytes at offsets 8..263, and 16 AEAD tag bytes at offsets 264..279.
The full output of each bounded byte-producing operation is available to the
host and to later indexed operations. AUTHENC_ENC_FINAL stores its ciphertext
in the output region and its tag in the tag region. OBJ_GET_INFO writes the
object information, and OBJ_GET_ATTR can write up to 256 attribute bytes.
Indexed references accept only previous successful records of the specified
opcode and a reported output length no greater than 256. Syscall errors and
unknown-opcode errors are result values. Record bounds violations return
`TEE_ERROR_BAD_PARAMETERS` from the TA command. The host client prints
`TEEC_ERROR_TARGET_DEAD` separately if the TA dies.

## Source layout

ta_entry.c contains the TA entry points. fuzz_run.c validates the copied
input and manages the result buffer and coverage session. crypto_ops.c
executes the crypto operations and releases their handles. The FZP3 input and
FZR3 result formats share the opcode and slot semantics with version 2.

## Build

From the Ubuntu development VM:

```sh
make -C ~/optee/build -j4 optee-os \
  CFG_CORE_FUZZ_COVERAGE=y CFG_CORE_SANITIZE_KADDRESS=y CFG_CORE_ASLR=n
make -C ~/optee/build -j4 arm-tf \
  CFG_CORE_FUZZ_COVERAGE=y CFG_CORE_SANITIZE_KADDRESS=y CFG_CORE_ASLR=n
make -C ~/optee/build -j4 buildroot \
  CFG_CORE_FUZZ_COVERAGE=y CFG_CORE_SANITIZE_KADDRESS=y CFG_CORE_ASLR=n
make -C ~/optee/optee_test/host/core_fuzz_ta \
  CROSS_COMPILE=$HOME/optee/out-br/host/bin/aarch64-linux-gnu- \
  TA_DEV_KIT_DIR=$HOME/optee/optee_os/out/arm/export-ta_arm64 \
  OPTEE_CLIENT_EXPORT=$HOME/optee/out-br/host/aarch64-buildroot-linux-gnu/sysroot/usr
```

Run these build targets in order: TF-A must package the newly built core.
Use the same three options when rebuilding this image, or make may replace it
with a coverage-only core. `CFG_CORE_SANITIZE_KADDRESS=y` enables core KASan;
OP-TEE requires `CFG_CORE_ASLR=n` with this option. The TA sanitizer remains
off (`CFG_TA_SANITIZE_KADDRESS=n`). Core KASan adds substantial CPU and memory
cost; use this build for bug finding rather than throughput measurements.
`CFG_CORE_FUZZ_COVERAGE` defaults to `n` outside this test build. When enabled,
GCC instruments the crypto syscall front end and helpers in `core/tee`.
The same build includes the linked `core/crypto` implementations, core
TomCrypt provider, core MbedTLS MPI and built ARM crypto C wrappers. The
three implementation coverage options default to `y` when
`CFG_CORE_FUZZ_COVERAGE=y`, so a campaign can select algorithms at runtime
without rebuilding OP-TEE. Deep instrumentation costs execution time; tune
the per-input and QEMU timeouts for RSA-heavy campaigns. The coverage PTA
remains
uninstrumented and records a 16 KiB byte map for one TA invocation. Each ID
hashes a core-ASLR-relative call site together with the previous call site,
so this is PC-derived edge feedback with possible hash collisions. Unrelated
core paths are outside this profile. Instrumenting the coverage callback or
its thread-ID dependency would risk recursive callback calls.

`ta/Makefile.gmake` builds this TA only when the TA dev kit reports
`CFG_CORE_FUZZ_COVERAGE=y`, so a default optee_test build skips it. Buildroot
builds and signs it with the other optee_test TAs. Its UUID is
`92ea581c-d6ec-449e-9aa6-cf93aa2b44dd`; the file is under
`~/optee/out-br/target/lib/optee_armtz/`. The client links against the
Buildroot `libteec` sysroot. The Ubuntu VM itself has no `/dev/tee`: run the
client in the nested OP-TEE QEMU normal-world guest after the TA and client
are available there.

For a short end-to-end fuzz run in the nested QEMU guest, use the runner script:

```sh
~/optee/optee_test/host/core_fuzz_ta/scripts/run_qemu_fuzz.sh 10 1
```

The campaign logs and corpus are written below
`~/optee/optee_test/host/core_fuzz_ta/out/fuzz_out/run-*` by default; set
`FUZZ_OUTPUT_DIR` to override the output location.

## Seeds

`make_seeds.py` generates 24 reproducible files in
`host/core_fuzz_ta/out/seeds/`. These generated files are ignored by Git.
Run `python3 ~/optee/optee_test/host/core_fuzz_ta/scripts/make_seeds.py` to
create them without booting QEMU.

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
- `aes_ctr_decrypt.bin`: decrypt the matching AES-CTR known ciphertext.
- `hkdf_sha256.bin`: derive a 32-byte generic secret from HKDF IKM and salt.
- `random_32.bin`: request 32 random bytes.
- `gcm_encrypt.bin`: AES-GCM initialization, AAD, payload update and encryption
  finalization with a 16-byte tag.
- `gcm_decrypt_empty.bin`: authenticate the AES-GCM empty-message test vector;
  its data begins with the known 16-byte tag.
- `ccm_encrypt.bin` and `ccm_decrypt.bin`: AES-CCM encrypt and authenticate
  the same `hello` payload with AAD and a 16-byte tag.
- `rsa_sign_verify.bin`: generate a 2048-bit RSA keypair, copy it before the
  signing state consumes the original, then sign and verify a SHA-256 digest.
- `rsa_pss_sha256.bin`, `rsaes_pkcs1v15.bin`, and `rsa_oaep_sha256.bin`:
  separate RSA seeds for algorithm-selected campaigns.
- `rsa_modes.bin`: generate one RSA keypair, then exercise RSA-PSS-SHA256
  sign/verify, RSAES-PKCS1-v1_5 encrypt/decrypt, and RSA-OAEP-SHA256
  encrypt/decrypt using the previous asymmetric result as the next input.

Inside the QEMU guest, replay one input through the LibAFL runner with
`host/core_fuzz_ta/out/core_fuzz_ta/core-fuzz-ta-libafl --replay INPUT_FILE
[REPEAT_COUNT]`. Repetitions share one TA session, as fuzzing does; each
prints the invocation status, coverage count, and per-operation results.

## LibAFL coverage-guided fuzzer

Build the host tools after building the signed TA and QEMU image
(`host/core_fuzz_ta/README.md` describes the variables):

```sh
make -C ~/optee/optee_test/host/core_fuzz_ta \
  CROSS_COMPILE=$HOME/optee/out-br/host/bin/aarch64-linux-gnu- \
  TA_DEV_KIT_DIR=$HOME/optee/optee_os/out/arm/export-ta_arm64 \
  OPTEE_CLIENT_EXPORT=$HOME/optee/out-br/host/aarch64-buildroot-linux-gnu/sysroot/usr
```

This builds the Rust LibAFL fuzzer. It provides both coverage-guided fuzzing
and one-shot input replay, so short campaigns and saved-input reproduction use the
same TEEC execution path.

Run a bounded campaign:

```sh
~/optee/optee_test/host/core_fuzz_ta/scripts/run_qemu_fuzz.sh 100 1
```

The arguments are the maximum mutation iterations and deterministic RNG seed.
For a timed campaign, the duration starts after seed loading and baseline
execution; set the QEMU watchdog higher than the requested run time:

```sh
FUZZ_DURATION_SECONDS=21600 FUZZ_TIMEOUT=24000 \
  ~/optee/optee_test/host/core_fuzz_ta/scripts/run_qemu_fuzz.sh 100000000 1
```

The runner boots QEMU once and passes FZP3 command streams to the TA through
`TEEC_InvokeCommand`; the TA returns FZR3 result records. The custom LibAFL
mutator performs structured command and argument changes for 80% of mutations
and raw bit changes for the remaining 20%. Structured changes can edit opcode,
slot, selector, auxiliary fields and payloads, or add, remove, duplicate and
reorder commands. `StdMapObserver` reads the 16 KiB whole-invocation
secure-world coverage map, and `MaxMapFeedback` retains inputs that add map
features. TA target-death results are saved as crashes. This runner uses one worker.

Each campaign writes to
`~/optee/optee_test/host/core_fuzz_ta/out/fuzz_out/run-YYYYMMDDHHMMSS/` by
default; set `FUZZ_OUTPUT_DIR` to override the output location:

- `corpus/`: LibAFL's on-disk corpus of inputs retained for new coverage.
- `crashes/`: inputs classified as crashes by LibAFL's objective.
- `current.bin`: the input being executed or most recently executed.
- `normal.log` and `secure.log`: Linux/Expect and OP-TEE secure-console logs.
- `build-config.txt`: whether core KASan and core ASLR were enabled.
- `FUZZ_OPCODE_STEP` lines record each returned operation result; final
  `FUZZ_OPCODE` lines contain per-opcode totals.
- `FUZZ_BASELINE_SEEDS`, `FUZZ_PROGRESS` and `FUZZ_DONE` lines summarize the
  seed/corpus counts, execution rate, coverage-map counts and stop reason.

The runner watches the secure console for `[ASAN]`. When a report occurs during
fuzzing, it saves the current input and both console logs under
`crashes/asan-*`, then replays the input in a fresh QEMU instance. A replay is
reported as reproduced when the secure console emits `[ASAN]` during the input
phase.

To replay a saved input manually:

```sh
~/optee/optee_test/host/core_fuzz_ta/scripts/run_qemu_replay.sh INPUT_FILE [OUTPUT_DIR]
```

`OUTPUT_DIR`, when provided, must be inside `~/optee` so QEMU can read it
through the 9p share. The replay directory contains the input, normal and
secure logs, phase, and status. The LibAFL replay mode reports each operation result and the number of
nonzero coverage-map bytes.

The TA's `CMD_RUN` accepts one input memref, one result memref, and one
coverage-map output memref. It starts coverage before executing the operation
sequence and returns the map after sequence cleanup. The fuzzer and replay mode use this same whole-input interface.

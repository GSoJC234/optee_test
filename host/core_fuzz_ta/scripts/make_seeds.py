#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026, Jaehun Lee
"""Create deterministic crypto syscall input programs."""

import re
from enum import IntEnum
from hashlib import sha256
from pathlib import Path
from struct import pack

SEEDS = Path(__file__).resolve().parent.parent / "out" / "seeds"
OPCODE_HEADER = (
    Path(__file__).resolve().parents[3]
    / "ta/core_fuzz_ta/include/core_fuzz_ta.h"
)


def load_opcodes() -> type[IntEnum]:
    header = OPCODE_HEADER.read_text()
    match = re.search(r"enum core_fuzz_ta_opcode\s*\{([^}]*)\}", header, re.S)
    if not match:
        raise ValueError(f"opcode enum not found in {OPCODE_HEADER}")
    members = {
        name: int(value)
        for name, value in re.findall(
            r"CORE_FUZZ_TA_([A-Z0-9_]+)\s*=\s*(\d+)\s*,", match.group(1)
        )
    }
    if not members:
        raise ValueError(f"opcode constants not found in {OPCODE_HEADER}")
    return IntEnum("Opcode", members)


Opcode = load_opcodes()


def op(
    code: int,
    slot: int = 0,
    data: bytes = b"",
    aux: int = 0,
    selector: int = 0,
) -> bytes:
    return pack("<BBBHH", code, slot, selector, len(data), aux) + data


def stream(*records: bytes) -> bytes:
    return b"FZP2" + bytes((2, len(records), 0, 0)) + b"".join(records)


def main() -> None:
    SEEDS.mkdir(exist_ok=True)
    hmac_key = b"K" * 32
    zero_aes_key = bytes(16)
    zero_nonce = bytes(12)
    ccm_ciphertext_and_tag = bytes.fromhex(
        "06a233de8dfc1f1de0a7e39461a5ed5d50f9ea90a1"
    )
    ccm_tag_then_ciphertext = ccm_ciphertext_and_tag[-16:] + \
        ccm_ciphertext_and_tag[:-16]
    rsa_digest = sha256(b"abc").digest()
    rsa_records = [
        op(Opcode.OBJ_ALLOC, slot=0, selector=4, aux=1024),
        op(Opcode.OBJ_GENERATE_KEY, slot=0, aux=1024),
    ]
    for slot in range(1, 6):
        rsa_records.extend((
            op(Opcode.OBJ_ALLOC, slot=slot, selector=4, aux=1024),
            op(Opcode.OBJ_COPY, slot=slot, selector=0),
        ))
    rsa_records.extend((
        op(Opcode.ALLOC, slot=0, selector=14, aux=1),
        op(Opcode.ASYMM_OPERATE, slot=0, data=rsa_digest, aux=256),
        op(Opcode.ALLOC, slot=1, selector=15, aux=2),
        op(Opcode.ASYMM_VERIFY, slot=1, selector=1, data=rsa_digest),
        op(Opcode.ALLOC, slot=2, selector=10, aux=3),
        op(Opcode.ASYMM_OPERATE, slot=2, data=b"v1.5", aux=256),
        op(Opcode.ALLOC, slot=3, selector=11, aux=4),
        op(Opcode.ASYMM_OPERATE, slot=3, selector=1, aux=256),
        op(Opcode.ALLOC, slot=4, selector=16, aux=5),
        op(Opcode.ASYMM_OPERATE, slot=4, data=b"oaep", aux=256),
        op(Opcode.ALLOC, slot=5, selector=17, aux=0),
        op(Opcode.ASYMM_OPERATE, slot=5, selector=1, aux=256),
    ))
    cases = {
        "sha256_abc.bin": stream(
            op(Opcode.ALLOC), op(Opcode.INIT), op(Opcode.UPDATE, data=b"abc"), op(Opcode.FINAL, aux=32), op(Opcode.FREE)
        ),
        "invalid_handle.bin": stream(
            op(Opcode.INIT, slot=7), op(Opcode.UPDATE, slot=7, data=b"x"), op(Opcode.FINAL, slot=7, aux=32)
        ),
        "interleaved_slot.bin": stream(
            op(Opcode.ALLOC, slot=0),
            op(Opcode.INIT, slot=0),
            op(Opcode.ALLOC, slot=1),
            op(Opcode.UPDATE, slot=0, data=b"abc"),
            op(Opcode.FINAL, slot=0, aux=32),
            op(Opcode.FREE, slot=1),
            op(Opcode.FREE, slot=0),
        ),
        "short_digest_buffer.bin": stream(
            op(Opcode.ALLOC), op(Opcode.INIT), op(Opcode.UPDATE, data=b"abc"), op(Opcode.FINAL, aux=1), op(Opcode.FREE)
        ),
        "truncated_record.bin": b"FZP2" + bytes((2, 1, 0, 0))
        + pack("<BBBHH", Opcode.UPDATE, 0, 0, 4, 0)
        + b"x",
        "sha512_abc.bin": stream(
            op(Opcode.ALLOC, selector=1), op(Opcode.INIT), op(Opcode.UPDATE, data=b"abc"), op(Opcode.FINAL, aux=64), op(Opcode.FREE)
        ),
        "hmac_sha256_abc.bin": stream(
            op(Opcode.OBJ_ALLOC, slot=4, aux=256),
            op(Opcode.OBJ_POPULATE, slot=4, data=hmac_key),
            op(Opcode.ALLOC, slot=0, selector=2, aux=4),
            op(Opcode.INIT),
            op(Opcode.UPDATE, data=b"abc"),
            op(Opcode.FINAL, aux=32),
            op(Opcode.FREE),
        ),
        "object_lifecycle.bin": stream(
            op(Opcode.OBJ_ALLOC, slot=1, aux=256),
            op(Opcode.OBJ_POPULATE, slot=1, data=hmac_key),
            op(Opcode.OBJ_GET_INFO, slot=1),
            op(Opcode.OBJ_GET_ATTR, slot=1, aux=32),
            op(Opcode.OBJ_RESTRICT_USAGE, slot=1, aux=8),
            op(Opcode.OBJ_RESET, slot=1),
            op(Opcode.OBJ_GENERATE_KEY, slot=1, aux=256),
            op(Opcode.OBJ_GET_INFO, slot=1),
            op(Opcode.OBJ_CLOSE, slot=1),
        ),
        "object_copy.bin": stream(
            op(Opcode.OBJ_ALLOC, slot=2, aux=256),
            op(Opcode.OBJ_POPULATE, slot=2, data=hmac_key),
            op(Opcode.OBJ_ALLOC, slot=3, aux=256),
            op(Opcode.OBJ_COPY, slot=3, selector=2),
            op(Opcode.OBJ_GET_ATTR, slot=3, aux=32),
            op(Opcode.OBJ_CLOSE, slot=3),
            op(Opcode.OBJ_CLOSE, slot=2),
        ),
        "aes_generated_key.bin": stream(
            op(Opcode.OBJ_ALLOC, slot=5, selector=2, aux=256),
            op(Opcode.OBJ_GENERATE_KEY, slot=5, aux=128),
            op(Opcode.OBJ_GET_INFO, slot=5),
            op(Opcode.OBJ_GET_ATTR, slot=5, aux=16),
            op(Opcode.OBJ_CLOSE, slot=5),
        ),
        "state_copy_sha256.bin": stream(
            op(Opcode.ALLOC, slot=0),
            op(Opcode.INIT, slot=0),
            op(Opcode.UPDATE, slot=0, data=b"abc"),
            op(Opcode.ALLOC, slot=1),
            op(Opcode.STATE_COPY, slot=1, selector=0),
            op(Opcode.FINAL, slot=1, aux=32),
            op(Opcode.FINAL, slot=0, aux=32),
            op(Opcode.FREE, slot=1),
            op(Opcode.FREE, slot=0),
        ),
        "aes_ctr.bin": stream(
            op(Opcode.OBJ_ALLOC, slot=4, selector=2, aux=128),
            op(Opcode.OBJ_POPULATE, slot=4, data=bytes(16)),
            op(Opcode.ALLOC, selector=3, aux=4),
            op(Opcode.CIPHER_INIT, data=bytes(16)),
            op(Opcode.CIPHER_UPDATE, data=b"abc", aux=3),
            op(Opcode.CIPHER_FINAL, data=b"def", aux=3),
            op(Opcode.FREE),
        ),
        "aes_ctr_decrypt.bin": stream(
            op(Opcode.OBJ_ALLOC, slot=4, selector=2, aux=128),
            op(Opcode.OBJ_POPULATE, slot=4, data=zero_aes_key),
            op(Opcode.ALLOC, selector=4, aux=4),
            op(Opcode.CIPHER_INIT, data=bytes(16)),
            op(Opcode.CIPHER_UPDATE, data=bytes.fromhex("07"), aux=1),
            op(Opcode.CIPHER_FINAL, data=bytes.fromhex("8b28"), aux=2),
            op(Opcode.FREE),
        ),
        "ccm_encrypt.bin": stream(
            op(Opcode.OBJ_ALLOC, slot=4, selector=2, aux=128),
            op(Opcode.OBJ_POPULATE, slot=4, data=zero_aes_key),
            op(Opcode.ALLOC, selector=12, aux=4),
            op(Opcode.AUTHENC_INIT, data=zero_nonce, selector=16, aux=(3 << 8) | 5),
            op(Opcode.AUTHENC_UPDATE_AAD, data=b"aad"),
            op(Opcode.AUTHENC_UPDATE_PAYLOAD, data=b"hello", aux=5),
            op(Opcode.AUTHENC_ENC_FINAL, selector=16),
            op(Opcode.FREE),
        ),
        "ccm_decrypt.bin": stream(
            op(Opcode.OBJ_ALLOC, slot=4, selector=2, aux=128),
            op(Opcode.OBJ_POPULATE, slot=4, data=zero_aes_key),
            op(Opcode.ALLOC, selector=13, aux=4),
            op(Opcode.AUTHENC_INIT, data=zero_nonce, selector=16, aux=(3 << 8) | 5),
            op(Opcode.AUTHENC_UPDATE_AAD, data=b"aad"),
            op(Opcode.AUTHENC_DEC_FINAL, data=ccm_tag_then_ciphertext, selector=16, aux=5),
            op(Opcode.FREE),
        ),
        "hkdf_sha256.bin": stream(
            op(Opcode.OBJ_ALLOC, slot=0, selector=3, aux=256),
            op(Opcode.OBJ_POPULATE, slot=0, selector=1, data=b"I" * 32),
            op(Opcode.OBJ_ALLOC, slot=1, selector=1, aux=256),
            op(Opcode.ALLOC, slot=0, selector=7, aux=0),
            op(Opcode.DERIVE_KEY, slot=0, selector=1, data=b"salt", aux=32),
            op(Opcode.OBJ_GET_ATTR, slot=1, aux=32),
            op(Opcode.FREE, slot=0),
            op(Opcode.OBJ_CLOSE, slot=1),
        ),
        "random_32.bin": stream(op(Opcode.RANDOM, aux=32)),
        "gcm_encrypt.bin": stream(
            op(Opcode.OBJ_ALLOC, slot=4, selector=2, aux=128),
            op(Opcode.OBJ_POPULATE, slot=4, data=bytes(16)),
            op(Opcode.ALLOC, selector=5, aux=4),
            op(Opcode.AUTHENC_INIT, data=bytes(12), selector=16, aux=(3 << 8) | 5),
            op(Opcode.AUTHENC_UPDATE_AAD, data=b"aad"),
            op(Opcode.AUTHENC_UPDATE_PAYLOAD, data=b"hello", aux=5),
            op(Opcode.AUTHENC_ENC_FINAL, selector=16),
            op(Opcode.FREE),
        ),
        "gcm_decrypt_empty.bin": stream(
            op(Opcode.OBJ_ALLOC, slot=4, selector=2, aux=128),
            op(Opcode.OBJ_POPULATE, slot=4, data=bytes(16)),
            op(Opcode.ALLOC, selector=6, aux=4),
            op(Opcode.AUTHENC_INIT, data=bytes(12), selector=16),
            op(Opcode.AUTHENC_DEC_FINAL, data=bytes.fromhex("58e2fccefa7e3061367f1d57a4e7455a"),
               selector=16),
            op(Opcode.FREE),
        ),
        "rsa_sign_verify.bin": stream(
            op(Opcode.OBJ_ALLOC, slot=0, selector=4, aux=2048),
            op(Opcode.OBJ_GENERATE_KEY, slot=0, aux=2048),
            op(Opcode.OBJ_ALLOC, slot=1, selector=4, aux=2048),
            op(Opcode.OBJ_COPY, slot=1, selector=0),
            op(Opcode.ALLOC, slot=0, selector=8, aux=0),
            op(Opcode.ASYMM_OPERATE, slot=0, data=rsa_digest, aux=256),
            op(Opcode.FREE, slot=0),
            op(Opcode.ALLOC, slot=1, selector=9, aux=1),
            op(Opcode.ASYMM_VERIFY, slot=1, selector=1, data=rsa_digest),
            op(Opcode.FREE, slot=1),
        ),
        "rsa_pss_sha256.bin": stream(
            op(Opcode.OBJ_ALLOC, slot=0, selector=4, aux=1024),
            op(Opcode.OBJ_GENERATE_KEY, slot=0, aux=1024),
            op(Opcode.ALLOC, slot=0, selector=14, aux=0),
            op(Opcode.ASYMM_OPERATE, slot=0, data=rsa_digest, aux=128),
        ),
        "rsaes_pkcs1v15.bin": stream(
            op(Opcode.OBJ_ALLOC, slot=0, selector=4, aux=1024),
            op(Opcode.OBJ_GENERATE_KEY, slot=0, aux=1024),
            op(Opcode.ALLOC, slot=0, selector=10, aux=0),
            op(Opcode.ASYMM_OPERATE, slot=0, data=b"v1.5", aux=128),
        ),
        "rsa_oaep_sha256.bin": stream(
            op(Opcode.OBJ_ALLOC, slot=0, selector=4, aux=1024),
            op(Opcode.OBJ_GENERATE_KEY, slot=0, aux=1024),
            op(Opcode.ALLOC, slot=0, selector=16, aux=0),
            op(Opcode.ASYMM_OPERATE, slot=0, data=b"oaep", aux=128),
        ),
        "rsa_modes.bin": stream(*rsa_records),
    }
    for name, data in cases.items():
        (SEEDS / name).write_bytes(data)
        print(f"{name}: {len(data)} bytes")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Create deterministic crypto syscall input programs."""

from hashlib import sha256
from pathlib import Path
from struct import pack

ROOT = Path(__file__).resolve().parent
SEEDS = ROOT / "seeds"


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
    cases = {
        "sha256_abc.bin": stream(
            op(1), op(2), op(3, data=b"abc"), op(4, aux=32), op(5)
        ),
        "invalid_handle.bin": stream(
            op(2, slot=7), op(3, slot=7, data=b"x"), op(4, slot=7, aux=32)
        ),
        "interleaved_slot.bin": stream(
            op(1, slot=0),
            op(2, slot=0),
            op(1, slot=1),
            op(3, slot=0, data=b"abc"),
            op(4, slot=0, aux=32),
            op(5, slot=1),
            op(5, slot=0),
        ),
        "short_digest_buffer.bin": stream(
            op(1), op(2), op(3, data=b"abc"), op(4, aux=1), op(5)
        ),
        "truncated_record.bin": b"FZP2" + bytes((2, 1, 0, 0))
        + pack("<BBBHH", 3, 0, 0, 4, 0)
        + b"x",
        "sha512_abc.bin": stream(
            op(1, selector=1), op(2), op(3, data=b"abc"), op(4, aux=64), op(5)
        ),
        "hmac_sha256_abc.bin": stream(
            op(6, slot=4, aux=256),
            op(7, slot=4, data=hmac_key),
            op(1, slot=0, selector=2, aux=4),
            op(2),
            op(3, data=b"abc"),
            op(4, aux=32),
            op(5),
        ),
        "object_lifecycle.bin": stream(
            op(6, slot=1, aux=256),
            op(7, slot=1, data=hmac_key),
            op(9, slot=1),
            op(12, slot=1, aux=32),
            op(10, slot=1, aux=8),
            op(11, slot=1),
            op(14, slot=1, aux=256),
            op(9, slot=1),
            op(8, slot=1),
        ),
        "object_copy.bin": stream(
            op(6, slot=2, aux=256),
            op(7, slot=2, data=hmac_key),
            op(6, slot=3, aux=256),
            op(13, slot=3, selector=2),
            op(12, slot=3, aux=32),
            op(8, slot=3),
            op(8, slot=2),
        ),
        "aes_generated_key.bin": stream(
            op(6, slot=5, selector=2, aux=256),
            op(14, slot=5, aux=128),
            op(9, slot=5),
            op(12, slot=5, aux=16),
            op(8, slot=5),
        ),
        "state_copy_sha256.bin": stream(
            op(1, slot=0),
            op(2, slot=0),
            op(3, slot=0, data=b"abc"),
            op(1, slot=1),
            op(15, slot=1, selector=0),
            op(4, slot=1, aux=32),
            op(4, slot=0, aux=32),
            op(5, slot=1),
            op(5, slot=0),
        ),
        "aes_ctr.bin": stream(
            op(6, slot=4, selector=2, aux=128),
            op(7, slot=4, data=bytes(16)),
            op(1, selector=3, aux=4),
            op(16, data=bytes(16)),
            op(17, data=b"abc", aux=3),
            op(18, data=b"def", aux=3),
            op(5),
        ),
        "hkdf_sha256.bin": stream(
            op(6, slot=0, selector=3, aux=256),
            op(7, slot=0, selector=1, data=b"I" * 32),
            op(6, slot=1, selector=1, aux=256),
            op(1, slot=0, selector=7, aux=0),
            op(19, slot=0, selector=1, data=b"salt", aux=32),
            op(12, slot=1, aux=32),
            op(5, slot=0),
            op(8, slot=1),
        ),
        "random_32.bin": stream(op(20, aux=32)),
        "gcm_encrypt.bin": stream(
            op(6, slot=4, selector=2, aux=128),
            op(7, slot=4, data=bytes(16)),
            op(1, selector=5, aux=4),
            op(21, data=bytes(12), selector=16, aux=(3 << 8) | 5),
            op(22, data=b"aad"),
            op(23, data=b"hello", aux=5),
            op(24, selector=16),
            op(5),
        ),
        "gcm_decrypt_empty.bin": stream(
            op(6, slot=4, selector=2, aux=128),
            op(7, slot=4, data=bytes(16)),
            op(1, selector=6, aux=4),
            op(21, data=bytes(12), selector=16),
            op(25, data=bytes.fromhex("58e2fccefa7e3061367f1d57a4e7455a"),
               selector=16),
            op(5),
        ),
        "rsa_sign_verify.bin": stream(
            op(6, slot=0, selector=4, aux=2048),
            op(14, slot=0, aux=2048),
            op(6, slot=1, selector=4, aux=2048),
            op(13, slot=1, selector=0),
            op(1, slot=0, selector=8, aux=0),
            op(26, slot=0, data=sha256(b"abc").digest(), aux=256),
            op(5, slot=0),
            op(1, slot=1, selector=9, aux=1),
            op(27, slot=1, selector=1, data=sha256(b"abc").digest()),
            op(5, slot=1),
        ),
    }
    for name, data in cases.items():
        (SEEDS / name).write_bytes(data)
        print(f"{name}: {len(data)} bytes")


if __name__ == "__main__":
    main()

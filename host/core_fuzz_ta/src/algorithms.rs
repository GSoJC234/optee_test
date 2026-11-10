// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Jaehun Lee
//! Algorithms supported by the core fuzz TA and campaign input policy.

use std::{fmt, str::FromStr};

use crate::{
    program::Program,
    protocol::{OP_ALLOC, OP_OBJ_ALLOC, OP_RANDOM},
};

const NAMES: [&str; 13] = [
    "sha256",
    "sha512",
    "hmac-sha256",
    "aes-ctr",
    "aes-gcm",
    "hkdf",
    "rsa-pkcs1v15-sha256",
    "rsaes-pkcs1v15",
    "aes-ccm",
    "rsa-pss-sha256",
    "rsa-oaep-sha256",
    "random",
    "ecdsa-p256-sha256",
];
const ALL: u16 = (1 << NAMES.len()) - 1;

/// Set of algorithms allowed in one fuzzing campaign.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlgorithmSet(u16);

impl Default for AlgorithmSet {
    fn default() -> Self {
        Self(ALL)
    }
}

impl FromStr for AlgorithmSet {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text == "all" {
            return Ok(Self::default());
        }
        let mut bits = 0;
        for name in text.split(',') {
            let index = NAMES
                .iter()
                .position(|candidate| *candidate == name)
                .ok_or_else(|| {
                    format!(
                        "unknown algorithm {name:?}; choose from {} or all",
                        NAMES.join(",")
                    )
                })?;
            bits |= 1 << index;
        }
        if bits == 0 {
            return Err("algorithm set must not be empty".into());
        }
        Ok(Self(bits))
    }
}

impl fmt::Display for AlgorithmSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == ALL {
            return f.write_str("all");
        }
        let names: Vec<_> = NAMES
            .iter()
            .enumerate()
            .filter_map(|(i, name)| self.has(i).then_some(*name))
            .collect();
        f.write_str(&names.join(","))
    }
}

impl AlgorithmSet {
    fn has(self, index: usize) -> bool {
        self.0 & (1 << index) != 0
    }

    fn allows_object(self, selector: u8) -> bool {
        match selector {
            0 => self.has(2),
            1 => self.has(2) || self.has(5),
            2 => self.has(3) || self.has(4) || self.has(8),
            3 => self.has(5),
            4 | 5 => (6..=10).any(|index| self.has(index)),
            6 | 7 => self.has(12),
            _ => true, // Invalid selectors only exercise parameter rejection.
        }
    }

    /// Returns whether a decoded program can execute only selected algorithms.
    #[must_use]
    pub fn allows_program(self, program: &Program) -> bool {
        if self.0 == ALL {
            return true;
        }
        program.operations.iter().all(|op| match op.opcode {
            OP_ALLOC => {
                let index = match op.selector {
                    0..=2 => Some(usize::from(op.selector)),
                    3..=4 => Some(3),
                    5..=6 => Some(4),
                    7 => Some(5),
                    8..=9 => Some(6),
                    10..=11 => Some(7),
                    12..=13 => Some(8),
                    14..=15 => Some(9),
                    16..=17 => Some(10),
                    18..=19 => Some(12),
                    _ => None,
                };
                index.is_none_or(|i| self.has(i))
            }
            OP_OBJ_ALLOC => self.allows_object(op.selector),
            OP_RANDOM => self.has(11),
            _ => true,
        })
    }

    /// Checks a wire input. Malformed framing cannot reach a crypto operation.
    #[must_use]
    pub fn allows_bytes(self, bytes: &[u8]) -> bool {
        Program::parse(bytes).is_none_or(|program| self.allows_program(&program))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::Operation;

    fn program(opcode: u8, selector: u8) -> Program {
        Program {
            header: [0; 8],
            operations: vec![Operation {
                opcode,
                slot: 0,
                selector,
                aux: 0,
                data: vec![],
            }],
            trailing: vec![],
        }
    }

    #[test]
    fn parses_and_normalizes_sets() {
        assert_eq!(
            "aes-gcm,sha256,aes-gcm"
                .parse::<AlgorithmSet>()
                .unwrap()
                .to_string(),
            "sha256,aes-gcm"
        );
        assert_eq!(
            "all".parse::<AlgorithmSet>().unwrap(),
            AlgorithmSet::default()
        );
        assert!("ecc".parse::<AlgorithmSet>().is_err());
        assert!("".parse::<AlgorithmSet>().is_err());
    }

    #[test]
    fn filters_algorithm_and_key_object_selectors() {
        let selected: AlgorithmSet = "aes-gcm".parse().unwrap();
        assert!(selected.allows_program(&program(OP_ALLOC, 5)));
        assert!(selected.allows_program(&program(OP_ALLOC, 6)));
        assert!(!selected.allows_program(&program(OP_ALLOC, 3)));
        assert!(selected.allows_program(&program(OP_OBJ_ALLOC, 2)));
        assert!(!selected.allows_program(&program(OP_OBJ_ALLOC, 4)));
        assert!(!selected.allows_program(&program(OP_RANDOM, 0)));
        assert!(!selected.allows_program(&program(OP_ALLOC, 18)));
        let ecdsa: AlgorithmSet = "ecdsa-p256-sha256".parse().unwrap();
        assert!(ecdsa.allows_program(&program(OP_ALLOC, 18)));
        assert!(ecdsa.allows_program(&program(OP_ALLOC, 19)));
        assert!(ecdsa.allows_program(&program(OP_OBJ_ALLOC, 6)));
        assert!(ecdsa.allows_program(&program(OP_OBJ_ALLOC, 7)));
        assert!(!ecdsa.allows_program(&program(OP_OBJ_ALLOC, 4)));
    }
}

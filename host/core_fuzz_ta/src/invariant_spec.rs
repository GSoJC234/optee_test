// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Jaehun Lee
//! Declarative, ordered trace invariants loaded from TOML.
//!
//! A rule describes a sequence of operations, logical object bindings, and
//! one assertion. The sequence is a subsequence: operations unrelated to a
//! particular match may occur between its steps. Matching and checking live
//! in the invariant evaluator; this module only parses and validates rules.

use std::collections::{BTreeMap, HashSet};
use std::fmt;

use serde::Deserialize;

/// The complete set of invariants from one TOML document.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvariantSpec {
    /// The rules in their document order.
    pub invariants: Vec<Invariant>,
}

/// One ordered operation pattern and its assertion.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invariant {
    /// Stable name used in findings and logs.
    pub id: String,
    /// Kind of input whose value is carried through the flow.
    #[serde(rename = "inputType")]
    pub input_type: InputType,
    /// Ordered operations, with unrelated operations allowed between steps.
    pub flow: Vec<Operation>,
    /// Maps an operation port such as `sign.key` to a logical object name.
    pub bind: BTreeMap<String, String>,
    /// Assertion applied after a complete flow match.
    pub expect: Expectation,
}

/// The value carried into an invariant flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputType {
    /// Digest bytes used in signing and verification.
    Digest,
    /// Plaintext bytes used in encryption and decryption.
    Plain,
    /// Object secret bytes used in copy and attribute checks.
    Secret,
    /// Requested object usage flags.
    UsageMask,
}

/// Operations currently exposed by the crypto trace adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Sign a digest.
    Sign,
    /// Verify a signature.
    Verify,
    /// Encrypt plaintext.
    Encrypt,
    /// Decrypt ciphertext.
    Decrypt,
    /// Authenticated encryption.
    AuthEncrypt,
    /// Authenticated decryption.
    AuthDecrypt,
    /// Copy object contents.
    Copy,
    /// Read an object attribute.
    GetAttr,
    /// Reset an object.
    Reset,
    /// Generate a key.
    Generate,
    /// Populate an object.
    Populate,
    /// Read object metadata.
    GetInfo,
    /// Allocate an object.
    Allocate,
    /// Restrict object usage.
    RestrictUsage,
}

impl Operation {
    /// The operation name as written in a TOML `flow` or `bind` key.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sign => "sign",
            Self::Verify => "verify",
            Self::Encrypt => "encrypt",
            Self::Decrypt => "decrypt",
            Self::AuthEncrypt => "auth_encrypt",
            Self::AuthDecrypt => "auth_decrypt",
            Self::Copy => "copy",
            Self::GetAttr => "get_attr",
            Self::Reset => "reset",
            Self::Generate => "generate",
            Self::Populate => "populate",
            Self::GetInfo => "get_info",
            Self::Allocate => "allocate",
            Self::RestrictUsage => "restrict_usage",
        }
    }

    fn permits_port(self, port: &str) -> bool {
        match self {
            Self::Sign
            | Self::Verify
            | Self::Encrypt
            | Self::Decrypt
            | Self::AuthEncrypt
            | Self::AuthDecrypt
            | Self::Generate => port == "key",
            Self::Copy => matches!(port, "source" | "destination" | "destination_type"),
            Self::GetAttr
            | Self::Reset
            | Self::Populate
            | Self::GetInfo
            | Self::Allocate
            | Self::RestrictUsage => port == "object",
        }
    }
}

/// Assertions supported by the current evaluator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum Expectation {
    /// The final operation must succeed.
    #[serde(rename = "success")]
    Success,
    /// The final output bytes must equal the original flow input.
    #[serde(rename = "output == input")]
    OutputEqualsInput,
    /// The final object information must report an uninitialized object.
    #[serde(rename = "output.initialized == false")]
    OutputUninitialized,
    /// The final object usage mask must equal the requested input mask.
    #[serde(rename = "output.usage == input")]
    OutputUsageEqualsInput,
}

/// The flow shapes currently implemented by the crypto trace evaluator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleKind {
    Signature,
    Encryption,
    Aead,
    SecretCopy,
    Reset,
    Usage,
}

impl Invariant {
    pub(crate) fn kind(&self) -> Option<RuleKind> {
        use {Expectation as E, InputType as I, Operation as O, RuleKind as R};
        match (self.input_type, self.expect, self.flow.as_slice()) {
            (I::Digest, E::Success, [O::Sign, O::Verify]) => Some(R::Signature),
            (I::Plain, E::OutputEqualsInput, [O::Encrypt, O::Decrypt]) => Some(R::Encryption),
            (I::Plain, E::OutputEqualsInput, [O::AuthEncrypt, O::AuthDecrypt]) => Some(R::Aead),
            (I::Secret, E::OutputEqualsInput, [O::Copy, O::GetAttr]) => Some(R::SecretCopy),
            (I::Secret, E::OutputEqualsInput, [O::Copy, O::Reset, O::GetAttr]) => {
                Some(R::SecretCopy)
            }
            (I::Plain, E::OutputEqualsInput, [O::Copy, O::Encrypt, O::Decrypt]) => {
                Some(R::Encryption)
            }
            (I::Digest, E::Success, [O::Copy, O::Sign, O::Verify]) => Some(R::Signature),
            (I::Digest, E::Success, [O::Generate, O::Sign, O::Verify]) => Some(R::Signature),
            (I::Secret, E::OutputUninitialized, [O::Populate, O::Reset, O::GetInfo]) => {
                Some(R::Reset)
            }
            (
                I::UsageMask,
                E::OutputUsageEqualsInput,
                [O::Allocate, O::RestrictUsage, O::GetInfo],
            ) => Some(R::Usage),
            (
                I::UsageMask,
                E::OutputUsageEqualsInput,
                [O::Allocate, O::RestrictUsage, O::Copy, O::GetInfo],
            ) => Some(R::Usage),
            _ => None,
        }
    }
}

impl Expectation {
    /// The assertion expression as written in TOML.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::OutputEqualsInput => "output == input",
            Self::OutputUninitialized => "output.initialized == false",
            Self::OutputUsageEqualsInput => "output.usage == input",
        }
    }
}

/// A malformed or unreadable invariant specification.
#[derive(Debug)]
pub enum SpecError {
    /// The TOML text cannot be decoded to the documented fields and enums.
    Parse(toml::de::Error),
    /// Parsed fields contradict the rule grammar or one another.
    Validation {
        /// ID of the rule containing the invalid field.
        invariant: String,
        /// Human-readable explanation of the invalid field.
        reason: String,
    },
}

impl fmt::Display for SpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => write!(f, "invalid invariant TOML: {error}"),
            Self::Validation { invariant, reason } => {
                write!(f, "invalid invariant {invariant:?}: {reason}")
            }
        }
    }
}

impl std::error::Error for SpecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(error) => Some(error),
            Self::Validation { .. } => None,
        }
    }
}

impl InvariantSpec {
    /// Parses and validates a TOML document containing `[[invariants]]` rules.
    pub fn parse(source: &str) -> Result<Self, SpecError> {
        let spec: Self = toml::from_str(source).map_err(SpecError::Parse)?;
        if spec.invariants.is_empty() {
            return Err(validation(
                "<document>",
                "at least one invariant is required",
            ));
        }

        let mut ids = HashSet::new();
        for rule in &spec.invariants {
            validate_name(&rule.id).map_err(|reason| validation(&rule.id, reason))?;
            if !ids.insert(rule.id.clone()) {
                return Err(validation(&rule.id, "duplicate invariant ID"));
            }
            if rule.flow.is_empty() {
                return Err(validation(
                    &rule.id,
                    "flow must contain at least one operation",
                ));
            }
            let mut seen_operations = HashSet::new();
            if rule
                .flow
                .iter()
                .any(|operation| !seen_operations.insert(*operation))
            {
                return Err(validation(&rule.id, "flow repeats an operation name"));
            }
            if rule.kind().is_none() {
                return Err(validation(
                    &rule.id,
                    "unsupported flow, inputType, and expect combination",
                ));
            }

            for (port_name, value) in &rule.bind {
                let (operation_name, port) = port_name.split_once('.').ok_or_else(|| {
                    validation(
                        &rule.id,
                        format!("binding {port_name:?} must be operation.port"),
                    )
                })?;
                let operation = rule
                    .flow
                    .iter()
                    .find(|operation| operation.as_str() == operation_name)
                    .ok_or_else(|| {
                        validation(
                            &rule.id,
                            format!("binding {port_name:?} names an operation absent from flow"),
                        )
                    })?;
                if !operation.permits_port(port) {
                    return Err(validation(
                        &rule.id,
                        format!("binding {port_name:?} uses an unknown port"),
                    ));
                }
                validate_name(value).map_err(|reason| {
                    validation(
                        &rule.id,
                        format!("binding {port_name:?} has invalid value: {reason}"),
                    )
                })?;
            }
        }
        Ok(spec)
    }
}

fn validate_name(name: &str) -> Result<(), &'static str> {
    let mut bytes = name.bytes();
    if !matches!(bytes.next(), Some(b'a'..=b'z' | b'A'..=b'Z' | b'_')) {
        return Err("must start with an ASCII letter or underscore");
    }
    if !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') {
        return Err("may contain only ASCII letters, digits, and underscores");
    }
    Ok(())
}

fn validation(invariant: &str, reason: impl Into<String>) -> SpecError {
    SpecError::Validation {
        invariant: invariant.to_owned(),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::{Expectation, InputType, InvariantSpec, Operation, SpecError};

    const ALL_RULES: &str = include_str!("../invariants.toml");

    #[test]
    fn parses_all_eleven_rules_in_order() {
        let spec = InvariantSpec::parse(ALL_RULES).unwrap();
        assert_eq!(spec.invariants.len(), 11);
        assert_eq!(spec.invariants[0].id, "sign_verify");
        assert_eq!(spec.invariants[0].input_type, InputType::Digest);
        assert_eq!(
            spec.invariants[0].flow,
            [Operation::Sign, Operation::Verify]
        );
        assert_eq!(spec.invariants[0].expect, Expectation::Success);
        assert_eq!(
            spec.invariants[6].bind["copy.destination_type"],
            "public_key"
        );
        assert_eq!(spec.invariants[10].id, "copy_preserves_usage");
        assert_eq!(
            spec.invariants[10].expect,
            Expectation::OutputUsageEqualsInput
        );
    }

    #[test]
    fn rejects_duplicate_ids() {
        let input = format!("{ALL_RULES}\n{ALL_RULES}");
        let error = InvariantSpec::parse(&input).unwrap_err();
        assert!(matches!(error, SpecError::Validation { .. }));
        assert!(error.to_string().contains("duplicate invariant ID"));
    }

    #[test]
    fn rejects_binding_to_missing_flow_operation() {
        let input = ALL_RULES.replace("\"sign.key\" = \"k\"", "\"decrypt.key\" = \"k\"");
        let error = InvariantSpec::parse(&input).unwrap_err();
        assert!(error.to_string().contains("absent from flow"));
    }

    #[test]
    fn rejects_unknown_operation_port() {
        let input = ALL_RULES.replace("\"sign.key\" = \"k\"", "\"sign.object\" = \"k\"");
        let error = InvariantSpec::parse(&input).unwrap_err();
        assert!(error.to_string().contains("unknown port"));
    }

    #[test]
    fn rejects_unknown_fields_and_expectations() {
        let wrong_field = ALL_RULES.replacen("inputType =", "input =", 1);
        assert!(matches!(
            InvariantSpec::parse(&wrong_field),
            Err(SpecError::Parse(_))
        ));
        let wrong_expect = ALL_RULES.replacen("expect = \"success\"", "expect = \"magic\"", 1);
        assert!(matches!(
            InvariantSpec::parse(&wrong_expect),
            Err(SpecError::Parse(_))
        ));
    }
}

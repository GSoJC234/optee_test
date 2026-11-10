// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Jaehun Lee
//! Match ordered trace subsequences and check invariant assertions.

use super::*;
use crate::invariant_spec::{Expectation, Invariant, InvariantSpec, RuleKind};

fn bindings_match(rule: &Invariant, selected: &[&Event]) -> bool {
    let mut values: BTreeMap<&str, String> = BTreeMap::new();
    let material_symbols: Vec<_> = rule
        .bind
        .iter()
        .filter_map(|(port, symbol)| {
            rule.bind
                .iter()
                .filter(|(_, other)| *other == symbol)
                .all(|(name, _)| name.ends_with(".key"))
                .then_some((port.as_str(), symbol.as_str()))
        })
        .collect();
    for (port, symbol) in &rule.bind {
        let Some((operation, field)) = port.split_once('.') else {
            return false;
        };
        let Some(event) = selected.iter().find(|e| e.kind.as_str() == operation) else {
            return false;
        };
        let Some(value) = event.ports.get(field) else {
            return false;
        };
        if field == "mask" {
            let expected = match symbol.as_str() {
                "encrypt" => 0x02,
                "decrypt" => 0x04,
                _ => return false,
            };
            if value.parse::<u32>() != Ok(expected) {
                return false;
            }
        } else if field == "destination_type" {
            if value != symbol {
                return false;
            }
        } else {
            let compare = if material_symbols.contains(&(port.as_str(), symbol.as_str())) {
                if event.key_material() == 0 {
                    return false;
                }
                event.key_material().to_string()
            } else {
                value.clone()
            };
            if let Some(previous) = values.get(symbol.as_str()) {
                if previous != &compare {
                    return false;
                }
            } else {
                values.insert(symbol, compare);
            }
        }
    }
    true
}

fn same_crypto_context(first: &Event, last: &Event) -> bool {
    first
        .state
        .as_ref()
        .zip(last.state.as_ref())
        .is_some_and(|(a, b)| {
            a.key_valid
                && b.key_valid
                && a.material != 0
                && a.material == b.material
                && a.ready
                && b.ready
                && pair(a.selector, b.selector)
        })
}

fn checked_result(rule: &Invariant, selected: &[&Event]) -> Option<bool> {
    let last = *selected.last()?;
    if selected[..selected.len() - 1]
        .iter()
        .any(|e| !e.succeeded())
    {
        return None;
    }
    let kind = rule.kind()?;
    match kind {
        RuleKind::Signature => {
            let sign = selected.iter().find(|e| e.kind == Kind::Sign)?;
            let verify = last;
            if !same_crypto_context(sign, verify)
                || sign.input != verify.input
                || verify.source_step != Some(sign.index)
            {
                return None;
            }
            if selected[0].kind == Kind::Generate
                && selected[0].key_material() != sign.key_material()
            {
                return None;
            }
            if selected[0].kind == Kind::Copy && selected[0].source_material != sign.key_material()
            {
                return None;
            }
            Some(verify.succeeded())
        }
        RuleKind::Encryption => {
            let encrypt = selected.iter().find(|e| e.kind == Kind::Encrypt)?;
            let encrypt_state = encrypt.state.as_ref()?;
            let decrypt_state = last.state.as_ref()?;
            if !same_crypto_context(encrypt, last)
                || last.source_step != Some(encrypt.index)
                || encrypt_state.iv != decrypt_state.iv
                || encrypt_state.cipher_offset != decrypt_state.cipher_offset
                || last.output_capacity < encrypt.input.len()
                || !encrypt.output_complete
                || !last.output_complete
            {
                return None;
            }
            if selected[0].kind == Kind::Copy
                && selected[0].source_material != encrypt.key_material()
            {
                return None;
            }
            Some(last.succeeded() && last.output == encrypt.input)
        }
        RuleKind::Aead => {
            let encrypt = selected[0];
            let encrypt_state = encrypt.state.as_ref()?;
            let decrypt_state = last.state.as_ref()?;
            if !same_crypto_context(encrypt, last)
                || last.source_step != Some(encrypt.index)
                || encrypt_state.iv != decrypt_state.iv
                || encrypt_state.aad != decrypt_state.aad
                || encrypt_state.tag_len != decrypt_state.tag_len
                || last.tag_len != decrypt_state.tag_len
                || encrypt_state.auth_lengths != decrypt_state.auth_lengths
                || encrypt_state.payload_updated
                || decrypt_state.payload_updated
                || last.output_capacity < encrypt.input.len()
                || !encrypt.output_complete
                || !last.output_complete
            {
                return None;
            }
            Some(last.succeeded() && last.output == encrypt.input)
        }
        RuleKind::SecretCopy => {
            let copy = selected[0];
            let secret = copy.source_secret.as_ref()?;
            if last.attribute_selector != 0
                || copy.source_kind == 3
                || copy.source_usage & 1 == 0
                || copy.destination_usage_before & 1 == 0
                || secret.len() > last.output_capacity
                || secret.len() > 256
                || copy.object_revision != last.object_revision
                || !last.output_complete
            {
                return None;
            }
            Some(last.succeeded() && &last.output == secret)
        }
        RuleKind::Reset => {
            if selected[1].object_revision != last.object_revision {
                return None;
            }
            Some(last.succeeded() && u32_at(&last.output, 24).is_some_and(|v| v & INITIALIZED == 0))
        }
        RuleKind::Usage => {
            let restrict = selected[1];
            if restrict.usage_before != DEFAULT_USAGE
                || (selected.len() == 3 && restrict.object_revision != last.object_revision)
            {
                return None;
            }
            let requested = u32_at(&restrict.input, 0)?;
            if selected.len() == 4 {
                let copy = selected[2];
                if copy.source_material == 0
                    || copy.source_usage != requested
                    || copy.destination_usage_before != DEFAULT_USAGE
                    || copy.object_revision != last.object_revision
                {
                    return None;
                }
            }
            Some(last.succeeded() && u32_at(&last.output, 12) == Some(requested))
        }
        RuleKind::UsageRestriction => {
            let restrict = selected[0];
            let state = last.state.as_ref()?;
            let expected_selector = match last.kind {
                Kind::Encrypt => 3,
                Kind::Decrypt => 4,
                _ => return None,
            };
            if state.selector != expected_selector
                || state.material == 0
                || state.material != restrict.material
                || state.key_revision != restrict.object_revision
                || state.allocated_at <= restrict.index
                || !state.ready
                || last.input.is_empty()
                || last.output_capacity < last.input.len()
                || !last.output_complete
                || (rule.expect == Expectation::Success && !state.key_valid)
            {
                return None;
            }
            Some(last.succeeded() == (rule.expect == Expectation::Success))
        }
    }
}

fn find_check<'a>(
    rule: &Invariant,
    events: &'a [Event],
    selected: &mut Vec<&'a Event>,
    start: usize,
    first_pass: &mut Option<Check>,
) -> Option<Check> {
    if selected.len() == rule.flow.len() {
        if !bindings_match(rule, selected) {
            return None;
        }
        if let Some(passed) = checked_result(rule, selected) {
            let check = Check {
                invariant: rule.id.clone(),
                steps: selected.iter().map(|e| e.index).collect(),
                passed,
                expected: rule.expect.as_str(),
            };
            if !passed {
                return Some(check);
            }
            if first_pass.is_none() {
                *first_pass = Some(check);
            }
        }
        return None;
    }
    let want = rule.flow[selected.len()];
    for (offset, event) in events[start..].iter().enumerate() {
        if event.kind != want {
            continue;
        }
        selected.push(event);
        if let Some(check) = find_check(rule, events, selected, start + offset + 1, first_pass) {
            return Some(check);
        }
        selected.pop();
    }
    None
}

/// Returns the first violation per invariant, or its first passing match.
/// Incomplete, unsupported or invalid flows are inapplicable.
#[must_use]
pub fn evaluate_checks(spec: &InvariantSpec, program: &Program, steps: &[Step<'_>]) -> Vec<Check> {
    if program.operations.len() != steps.len() {
        return Vec::new();
    }
    let events = trace(program, steps);
    spec.invariants
        .iter()
        .filter_map(|rule| {
            let mut first_pass = None;
            find_check(rule, &events, &mut Vec::new(), 0, &mut first_pass).or(first_pass)
        })
        .collect()
}

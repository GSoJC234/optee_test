// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Jaehun Lee
//! Trace matching and semantic checks for the declarative crypto invariants.
//!
//! A flow is an ordered subsequence. Object IDs survive unrelated calls and
//! distinguish a reused slot; material IDs distinguish a reset or new key.

use std::collections::BTreeMap;

use crate::{invariant_spec::Operation as Kind, program::Program, protocol::*, response::Step};

const INITIALIZED: u32 = 0x0002_0000;
const DEFAULT_USAGE: u32 = u32::MAX;

/// One applicable invariant flow in a trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    /// TOML invariant ID.
    pub invariant: String,
    /// Zero-based operation indices comprising the matched flow.
    pub steps: Vec<usize>,
    /// Whether the assertion held for the matched flow.
    pub passed: bool,
    /// Expected result from the TOML rule.
    pub expected: &'static str,
}

#[derive(Clone, Debug)]
struct Object {
    id: u64,
    kind: u8,
    revision: u64,
    material: u64,
    initialized: bool,
    secret: Option<Vec<u8>>,
    usage: u32,
}

#[derive(Clone, Debug)]
struct State {
    selector: u8,
    key: Option<u64>,
    material: u64,
    key_valid: bool,
    ready: bool,
    iv: Vec<u8>,
    aad: Vec<u8>,
    payload_updated: bool,
    tag_len: usize,
    auth_lengths: u16,
    cipher_offset: usize,
}

#[derive(Clone, Debug)]
struct Event {
    index: usize,
    kind: Kind,
    status: u32,
    ports: BTreeMap<&'static str, String>,
    input: Vec<u8>,
    output: Vec<u8>,
    source_step: Option<usize>,
    state: Option<State>,
    material: u64,
    tag_len: usize,
    object_revision: u64,
    source_secret: Option<Vec<u8>>,
    source_material: u64,
    destination_usage_before: u32,
    usage_before: u32,
    source_usage: u32,
    output_capacity: usize,
    source_kind: u8,
    output_complete: bool,
    attribute_selector: u8,
}

impl Event {
    fn new(index: usize, kind: Kind, step: &Step<'_>) -> Self {
        Self {
            index,
            kind,
            status: step.status,
            ports: BTreeMap::new(),
            input: Vec::new(),
            output: if step.succeeded() {
                step.data().to_vec()
            } else {
                Vec::new()
            },
            source_step: None,
            state: None,
            material: 0,
            tag_len: 0,
            object_revision: 0,
            source_secret: None,
            source_material: 0,
            destination_usage_before: 0,
            usage_before: 0,
            source_usage: 0,
            output_capacity: 0,
            source_kind: 0,
            output_complete: usize::from(step.reported_len) <= RESULT_DATA_SIZE,
            attribute_selector: 0,
        }
    }

    fn succeeded(&self) -> bool {
        self.status == TEE_SUCCESS
    }

    fn object(&mut self, port: &'static str, object: &Object) {
        self.ports.insert(port, object.id.to_string());
        self.object_revision = object.revision;
        self.material = object.material;
    }

    fn state(&mut self, state: &State) {
        if let Some(key) = state.key {
            self.ports.insert("key", key.to_string());
        }
        self.state = Some(state.clone());
    }

    fn key_material(&self) -> u64 {
        self.state
            .as_ref()
            .map_or(self.material, |state| state.material)
    }
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn pair(left: u8, right: u8) -> bool {
    matches!(
        (left, right),
        (3, 4) | (5, 6) | (8, 9) | (10, 11) | (12, 13) | (14, 15) | (16, 17)
    )
}

fn invalidate_states(states: &mut [Option<State>; SLOT_COUNT], object_id: u64) {
    for state in states.iter_mut().flatten() {
        if state.key == Some(object_id) {
            state.ready = false;
            state.key_valid = false;
        }
    }
}

fn source_index(
    selector: u8,
    aux: u16,
    data: &[u8],
    latest_asymm: Option<usize>,
    opcode: u8,
) -> Option<usize> {
    match opcode {
        OP_ASYMM_VERIFY if selector == 2 => Some(usize::from(aux)),
        OP_ASYMM_VERIFY | OP_ASYMM_OPERATE if selector == 1 => latest_asymm,
        OP_ASYMM_OPERATE if selector == 2 && data.len() == 1 => {
            data.first().copied().map(usize::from)
        }
        OP_CIPHER_UPDATE | OP_CIPHER_FINAL if selector == 0x80 && data.len() == 1 => {
            data.first().copied().map(usize::from)
        }
        OP_AUTHENC_DEC_FINAL if selector & 0x80 != 0 && data.len() == 1 => {
            data.first().copied().map(usize::from)
        }
        _ => None,
    }
}

fn trace(program: &Program, steps: &[Step<'_>]) -> Vec<Event> {
    let mut objects: [Option<Object>; SLOT_COUNT] = std::array::from_fn(|_| None);
    let mut states: [Option<State>; SLOT_COUNT] = std::array::from_fn(|_| None);
    let mut next_id = 1u64;
    let mut latest_asymm = None;
    let mut events = Vec::new();

    for (index, (op, step)) in program.operations.iter().zip(steps).enumerate() {
        if step.opcode != op.opcode || step.slot != op.slot {
            break;
        }
        let slot = usize::from(op.slot);
        let success = step.succeeded();
        let mut event = match op.opcode {
            OP_OBJ_ALLOC => {
                if success {
                    objects[slot] = Some(Object {
                        id: next_id,
                        kind: op.selector,
                        revision: 0,
                        material: 0,
                        initialized: false,
                        secret: None,
                        usage: DEFAULT_USAGE,
                    });
                    next_id += 1;
                }
                let mut e = Event::new(index, Kind::Allocate, step);
                if let Some(object) = &objects[slot] {
                    e.object("object", object);
                }
                Some(e)
            }
            OP_OBJ_POPULATE
            | OP_OBJ_GENERATE_KEY
            | OP_OBJ_RESET
            | OP_OBJ_RESTRICT_USAGE
            | OP_OBJ_GET_INFO
            | OP_OBJ_GET_ATTR => {
                let kind = match op.opcode {
                    OP_OBJ_POPULATE => Kind::Populate,
                    OP_OBJ_GENERATE_KEY => Kind::Generate,
                    OP_OBJ_RESET => Kind::Reset,
                    OP_OBJ_RESTRICT_USAGE => Kind::RestrictUsage,
                    OP_OBJ_GET_INFO => Kind::GetInfo,
                    _ => Kind::GetAttr,
                };
                let mut e = Event::new(index, kind, step);
                if let Some(object) = objects[slot].as_mut() {
                    if kind == Kind::RestrictUsage {
                        e.usage_before = object.usage;
                    }
                    if success {
                        match op.opcode {
                            OP_OBJ_POPULATE => {
                                object.initialized = true;
                                object.secret = Some(op.data.clone());
                                object.material = next_id;
                                next_id += 1;
                                object.revision += 1;
                            }
                            OP_OBJ_GENERATE_KEY => {
                                object.initialized = true;
                                object.secret = None;
                                object.material = next_id;
                                next_id += 1;
                                object.revision += 1;
                            }
                            OP_OBJ_RESET => {
                                object.initialized = false;
                                object.secret = None;
                                object.material = 0;
                                object.usage = DEFAULT_USAGE;
                                object.revision += 1;
                            }
                            OP_OBJ_RESTRICT_USAGE => {
                                object.usage &= u32::from(op.aux);
                                object.revision += 1;
                            }
                            OP_OBJ_GET_ATTR
                                if object.secret.is_none()
                                    && op.selector == 0
                                    && usize::from(step.reported_len) <= RESULT_DATA_SIZE =>
                            {
                                object.secret = Some(step.data().to_vec());
                            }
                            _ => {}
                        }
                        if matches!(
                            op.opcode,
                            OP_OBJ_POPULATE
                                | OP_OBJ_GENERATE_KEY
                                | OP_OBJ_RESET
                                | OP_OBJ_RESTRICT_USAGE
                        ) {
                            invalidate_states(&mut states, object.id);
                        }
                    }
                    e.object(
                        if kind == Kind::Generate {
                            "key"
                        } else {
                            "object"
                        },
                        object,
                    );
                    if kind == Kind::RestrictUsage {
                        e.input = u32::from(op.aux).to_le_bytes().to_vec();
                    }
                    if kind == Kind::GetAttr {
                        e.output_capacity = usize::from(op.aux);
                        e.attribute_selector = op.selector;
                    }
                }
                Some(e)
            }
            OP_OBJ_COPY => {
                let mut e = Event::new(index, Kind::Copy, step);
                let source = objects
                    .get(usize::from(op.selector))
                    .and_then(Option::as_ref)
                    .cloned();
                if let (Some(dst), Some(src)) = (objects[slot].as_mut(), source.as_ref()) {
                    e.ports.insert("source", src.id.to_string());
                    e.ports.insert("destination", dst.id.to_string());
                    e.ports.insert(
                        "destination_type",
                        match dst.kind {
                            5 => "public_key",
                            4 => "keypair",
                            2 => "aes",
                            _ => "secret",
                        }
                        .to_owned(),
                    );
                    e.source_secret.clone_from(&src.secret);
                    e.source_material = src.material;
                    e.source_kind = src.kind;
                    e.source_usage = src.usage;
                    e.destination_usage_before = dst.usage;
                    if success {
                        dst.initialized = src.initialized;
                        dst.secret.clone_from(&src.secret);
                        dst.material = src.material;
                        dst.usage &= src.usage;
                        dst.revision += 1;
                        invalidate_states(&mut states, dst.id);
                    }
                    e.object_revision = dst.revision;
                }
                Some(e)
            }
            OP_OBJ_CLOSE => {
                if success {
                    if let Some(object) = &objects[slot] {
                        invalidate_states(&mut states, object.id);
                    }
                    objects[slot] = None;
                }
                None
            }
            OP_ALLOC => {
                if let Some(selector) = (op.selector <= 17).then_some(op.selector) {
                    let key = objects.get(usize::from(op.aux)).and_then(Option::as_ref);
                    let required_usage = match selector {
                        3 | 5 | 10 | 12 | 16 => 0x02,
                        4 | 6 | 11 | 13 | 17 => 0x04,
                        8 | 14 => 0x10,
                        9 | 15 => 0x20,
                        _ => 0,
                    };
                    let compatible = key.is_some_and(|k| match selector {
                        3..=6 | 12..=13 => k.kind == 2,
                        8 | 11 | 14 | 17 => k.kind == 4,
                        9 | 10 | 15 | 16 => k.kind == 4 || k.kind == 5,
                        _ => true,
                    });
                    let key_valid = key.is_some_and(|k| {
                        k.initialized && k.usage & required_usage == required_usage
                    }) && compatible;
                    let state = State {
                        selector,
                        key: key.map(|k| k.id),
                        material: key.map_or(0, |k| k.material),
                        key_valid,
                        ready: success && !matches!(selector, 3..=6 | 12..=13),
                        iv: Vec::new(),
                        aad: Vec::new(),
                        payload_updated: false,
                        tag_len: 0,
                        auth_lengths: 0,
                        cipher_offset: 0,
                    };
                    if success {
                        states[slot] = Some(state);
                    }
                }
                None
            }
            OP_FREE => {
                if success {
                    if let Some(state) = states[slot].take() {
                        if let Some(key_id) = state.key {
                            for object in &mut objects {
                                if object.as_ref().is_some_and(|o| o.id == key_id) {
                                    *object = None;
                                }
                            }
                        }
                    }
                }
                None
            }
            OP_STATE_COPY => {
                if success {
                    if let Some(state) = states[slot].as_mut() {
                        state.ready = false;
                        state.key_valid = false;
                    }
                }
                None
            }
            OP_CIPHER_INIT
            | OP_AUTHENC_INIT
            | OP_AUTHENC_UPDATE_AAD
            | OP_AUTHENC_UPDATE_PAYLOAD => {
                if let Some(state) = states[slot].as_mut() {
                    if success {
                        match op.opcode {
                            OP_CIPHER_INIT | OP_AUTHENC_INIT => {
                                state.iv.clone_from(&op.data);
                                state.ready = true;
                                state.cipher_offset = 0;
                                if op.opcode == OP_AUTHENC_INIT {
                                    state.aad.clear();
                                    state.payload_updated = false;
                                    state.tag_len = if op.selector == 0 {
                                        16
                                    } else {
                                        usize::from(op.selector)
                                    };
                                    state.auth_lengths = op.aux;
                                }
                            }
                            OP_AUTHENC_UPDATE_AAD => state.aad.extend_from_slice(&op.data),
                            OP_AUTHENC_UPDATE_PAYLOAD => state.payload_updated = true,
                            _ => {}
                        }
                    } else if op.opcode == OP_CIPHER_INIT || op.opcode == OP_AUTHENC_INIT {
                        state.ready = false;
                    }
                }
                None
            }
            OP_ASYMM_OPERATE | OP_ASYMM_VERIFY | OP_CIPHER_UPDATE | OP_CIPHER_FINAL
            | OP_AUTHENC_ENC_FINAL | OP_AUTHENC_DEC_FINAL => {
                let state = states[slot].as_ref();
                let kind = match (op.opcode, state.map(|s| s.selector)) {
                    (OP_ASYMM_VERIFY, _) => Some(Kind::Verify),
                    (OP_ASYMM_OPERATE, Some(8 | 14)) => Some(Kind::Sign),
                    (OP_ASYMM_OPERATE, Some(10 | 16)) => Some(Kind::Encrypt),
                    (OP_ASYMM_OPERATE, Some(11 | 17)) => Some(Kind::Decrypt),
                    (OP_CIPHER_UPDATE | OP_CIPHER_FINAL, Some(3)) => Some(Kind::Encrypt),
                    (OP_CIPHER_UPDATE | OP_CIPHER_FINAL, Some(4)) => Some(Kind::Decrypt),
                    (OP_AUTHENC_ENC_FINAL, _) => Some(Kind::AuthEncrypt),
                    (OP_AUTHENC_DEC_FINAL, _) => Some(Kind::AuthDecrypt),
                    _ => None,
                };
                kind.map(|kind| {
                    let mut e = Event::new(index, kind, step);
                    if let Some(state) = state {
                        e.state(state);
                    }
                    e.source_step =
                        source_index(op.selector, op.aux, &op.data, latest_asymm, op.opcode);
                    e.input = if kind != Kind::Verify {
                        e.source_step
                            .filter(|&source| source < index)
                            .and_then(|source| steps.get(source))
                            .filter(|source| {
                                source.succeeded()
                                    && usize::from(source.reported_len) <= RESULT_DATA_SIZE
                            })
                            .map_or_else(|| op.data.clone(), |source| source.data().to_vec())
                    } else {
                        op.data.clone()
                    };
                    if kind == Kind::Verify {
                        e.input = if op.selector == 0 {
                            op.data
                                .get(..usize::from(op.aux))
                                .unwrap_or_default()
                                .to_vec()
                        } else {
                            op.data.clone()
                        };
                    }
                    e.output_capacity = usize::from(op.aux);
                    if kind == Kind::AuthEncrypt || kind == Kind::AuthDecrypt {
                        e.tag_len = usize::from(op.selector & 0x7f);
                        if e.tag_len == 0 {
                            e.tag_len = 16;
                        }
                    }
                    e
                })
            }
            _ => None,
        };
        if matches!(op.opcode, OP_CIPHER_UPDATE | OP_CIPHER_FINAL) {
            let referenced = source_index(op.selector, op.aux, &op.data, latest_asymm, op.opcode)
                .filter(|&source| source < index)
                .and_then(|source| steps.get(source))
                .filter(|step| step.succeeded());
            let consumed = referenced.map_or(op.data.len(), |step| step.data().len());
            if let Some(state) = states[slot].as_mut() {
                if success && state.ready {
                    state.cipher_offset = state.cipher_offset.saturating_add(consumed);
                }
                if !success || op.opcode == OP_CIPHER_FINAL {
                    state.ready = false;
                }
            }
        }
        if matches!(op.opcode, OP_AUTHENC_ENC_FINAL | OP_AUTHENC_DEC_FINAL) {
            if let Some(state) = states[slot].as_mut() {
                state.ready = false;
            }
        }
        if op.opcode == OP_ASYMM_OPERATE && success {
            latest_asymm = Some(index);
        }
        if let Some(e) = event.take() {
            events.push(e);
        }
    }
    events
}

mod matcher;

pub use matcher::evaluate_checks;

#[cfg(test)]
mod tests;

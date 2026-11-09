// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Jaehun Lee
//! Generates Rust constants from the C headers that define the TA wire format
//! and the coverage PTA, so the host runner and the TA share one definition.
//!
//! With the `runner` feature it also compiles `teec_shim.c` and links libteec.

use std::{
    env,
    error::Error,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

type BuildResult<T> = Result<T, Box<dyn Error>>;

/// Returns the replacement text of `#define NAME ...`, without comments.
fn define<'a>(header: &'a str, name: &str) -> BuildResult<&'a str> {
    header
        .lines()
        .find_map(|line| {
            let rest = line.trim_start().strip_prefix("#define")?.trim_start();
            let value = rest.strip_prefix(name)?;
            // Reject prefix matches such as FOO for FOO_SIZE.
            if !value.starts_with(char::is_whitespace) {
                return None;
            }
            let value = value.split("/*").next().unwrap_or_default();
            Some(value.split("//").next().unwrap_or_default().trim())
        })
        .ok_or_else(|| format!("missing #define {name}").into())
}

/// Parses `123`, `123U`, `0x7bU`, `(123U)` and OP-TEE's `U(123)` forms.
fn parse_uint(text: &str) -> Option<usize> {
    let mut text = text.trim();
    while let Some(inner) = text
        .strip_prefix("U(")
        .or_else(|| text.strip_prefix('('))
        .and_then(|inner| inner.strip_suffix(')'))
    {
        text = inner.trim();
    }
    let text = text.trim_end_matches(['U', 'u', 'L', 'l']);
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => usize::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

fn number(header: &str, name: &str) -> BuildResult<usize> {
    let value = define(header, name)?;
    parse_uint(value).ok_or_else(|| {
        format!("{name} must be an unsigned integer literal, found `{value}`").into()
    })
}

/// Evaluates a `#define` that is a product of integer literals, e.g. `(16 * 1024)`.
fn product(header: &str, name: &str) -> BuildResult<usize> {
    let value = define(header, name)?;
    let expression = value
        .strip_prefix('(')
        .and_then(|inner| inner.strip_suffix(')'))
        .unwrap_or(value);
    expression.split('*').try_fold(1usize, |acc, term| {
        let term =
            parse_uint(term).ok_or_else(|| format!("unsupported term `{term}` in {name}"))?;
        acc.checked_mul(term)
            .ok_or_else(|| format!("{name} overflows usize").into())
    })
}

/// Returns a four-character ASCII magic such as `FZP2`.
fn magic(header: &str, name: &str) -> BuildResult<String> {
    let value = define(header, name)?;
    let text = value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .ok_or_else(|| format!("{name} must be a quoted string"))?;
    if text.len() != 4 || !text.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(format!("{name} must be four ASCII letters or digits").into());
    }
    Ok(text.to_owned())
}

/// Reads `enum core_fuzz_ta_opcode` as `(OP_NAME, value)` pairs.
fn opcodes(header: &str) -> BuildResult<Vec<(String, u8)>> {
    let body = header
        .lines()
        .map(str::trim)
        .skip_while(|line| !line.starts_with("enum core_fuzz_ta_opcode {"))
        .skip(1)
        .take_while(|line| !line.starts_with("};"));
    let mut values = Vec::new();
    for line in body {
        let Some((name, value)) = line.trim_end_matches(',').split_once('=') else {
            continue;
        };
        let name = name.trim();
        let short = name
            .strip_prefix("CORE_FUZZ_TA_")
            .ok_or_else(|| format!("invalid opcode name: {name}"))?;
        let value = parse_uint(value)
            .and_then(|value| u8::try_from(value).ok())
            .ok_or_else(|| format!("opcode {name} must fit in a byte"))?;
        values.push((format!("OP_{short}"), value));
    }
    if values.is_empty() {
        return Err("missing enum core_fuzz_ta_opcode".into());
    }
    for (expected, (name, value)) in (1u8..).zip(&values) {
        if *value != expected {
            return Err(format!("opcodes must be contiguous from 1 ({name} = {value})").into());
        }
    }
    Ok(values)
}

fn read(path: &Path) -> BuildResult<String> {
    println!("cargo::rerun-if-changed={}", path.display());
    fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()).into())
}

/// Mirrors `CORE_FUZZ_TA_MAX_OUTPUT`, which is an expression rather than a literal.
fn max_output(header: &str) -> BuildResult<usize> {
    let records = number(header, "CORE_FUZZ_TA_MAX_OPS")?
        .checked_mul(number(header, "CORE_FUZZ_TA_RESULT_SIZE")?)
        .ok_or("CORE_FUZZ_TA_MAX_OUTPUT overflows usize")?;
    number(header, "CORE_FUZZ_TA_OUTPUT_HEADER_SIZE")?
        .checked_add(records)
        .ok_or_else(|| "CORE_FUZZ_TA_MAX_OUTPUT overflows usize".into())
}

fn protocol_constants(header: &str) -> BuildResult<String> {
    let version = u8::try_from(number(header, "CORE_FUZZ_TA_VERSION")?)?;
    let opcodes = opcodes(header)?;
    let max_opcode = opcodes.last().map_or(0, |(_, value)| *value);

    let sizes = [
        (
            "MAX_INPUT_SIZE",
            "CORE_FUZZ_TA_MAX_INPUT",
            "Largest accepted input program in bytes.",
        ),
        (
            "MAX_OPERATIONS",
            "CORE_FUZZ_TA_MAX_OPS",
            "Largest operation count in one input.",
        ),
        (
            "SLOT_COUNT",
            "CORE_FUZZ_TA_SLOTS",
            "Number of state slots and of object slots.",
        ),
        (
            "INPUT_HEADER_SIZE",
            "CORE_FUZZ_TA_INPUT_HEADER_SIZE",
            "Size of the input header.",
        ),
        (
            "OP_HEADER_SIZE",
            "CORE_FUZZ_TA_OP_HEADER_SIZE",
            "Size of one operation header.",
        ),
        (
            "OUTPUT_HEADER_SIZE",
            "CORE_FUZZ_TA_OUTPUT_HEADER_SIZE",
            "Size of the response header.",
        ),
        (
            "RESULT_SIZE",
            "CORE_FUZZ_TA_RESULT_SIZE",
            "Size of one result record.",
        ),
        (
            "RESULT_DATA_SIZE",
            "CORE_FUZZ_TA_RESULT_DATA_SIZE",
            "Output bytes kept per result record.",
        ),
        (
            "RESULT_TAG_SIZE",
            "CORE_FUZZ_TA_RESULT_TAG_SIZE",
            "Authenticated-encryption tag bytes kept per result record.",
        ),
    ];

    let mut out = String::from("// @generated by build.rs from core_fuzz_ta.h\n");
    writeln!(
        out,
        "/// Wire-format version byte (`CORE_FUZZ_TA_VERSION`)."
    )?;
    writeln!(out, "pub const TA_VERSION: u8 = {version};")?;
    for (rust, c, doc) in sizes {
        writeln!(out, "/// {doc} (`{c}`)")?;
        writeln!(out, "pub const {rust}: usize = {};", number(header, c)?)?;
    }
    writeln!(
        out,
        "/// Largest response the TA can return (`CORE_FUZZ_TA_MAX_OUTPUT`)."
    )?;
    writeln!(
        out,
        "pub const MAX_OUTPUT_SIZE: usize = {};",
        max_output(header)?
    )?;
    for (rust, c) in [
        ("INPUT_MAGIC", "CORE_FUZZ_TA_INPUT_MAGIC"),
        ("OUTPUT_MAGIC", "CORE_FUZZ_TA_OUTPUT_MAGIC"),
    ] {
        writeln!(out, "/// Four-byte magic (`{c}`).")?;
        writeln!(
            out,
            "pub const {rust}: [u8; 4] = *b\"{}\";",
            magic(header, c)?
        )?;
    }
    writeln!(
        out,
        "/// Number of defined opcodes; they are numbered `1..=OPCODE_COUNT`."
    )?;
    writeln!(out, "pub const OPCODE_COUNT: usize = {};", opcodes.len())?;
    writeln!(out, "/// Highest defined opcode.")?;
    writeln!(out, "pub const MAX_OPCODE: u8 = {max_opcode};")?;
    for (name, value) in &opcodes {
        let c_name = name.strip_prefix("OP_").unwrap_or(name);
        writeln!(out, "/// Opcode `CORE_FUZZ_TA_{c_name}`.")?;
        writeln!(out, "pub const {name}: u8 = {value};")?;
    }
    Ok(out)
}

/// Returns a required path from the environment; the Makefile sets these.
fn env_path(name: &str) -> BuildResult<PathBuf> {
    println!("cargo::rerun-if-env-changed={name}");
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| format!("{name} must be set to build the runner; use the Makefile").into())
}

/// Compiles the TEEC shim and returns the coverage constants for the runner.
///
/// The inputs are those host/xtest uses: the TA dev kit's `host_include` for
/// PTA headers and the optee_client export for libteec. The cross toolchain
/// prefix comes from `CORE_FUZZ_CROSS_COMPILE`.
fn build_runner(manifest: &Path, test_root: &Path, header: &str) -> BuildResult<String> {
    let host_include = env_path("TA_DEV_KIT_DIR")?.join("host_include");
    let client = env_path("OPTEE_CLIENT_EXPORT")?;
    let cov_header = read(&host_include.join("pta_core_fuzz_cov.h"))?;
    let coverage_size = product(&cov_header, "PTA_CORE_FUZZ_COV_MAP_SIZE")?;

    let max_output = max_output(header)?;

    let shim = manifest.join("teec_shim.c");
    println!("cargo::rerun-if-changed={}", shim.display());
    println!(
        "cargo::rerun-if-changed={}",
        manifest.join("teec_shim.h").display()
    );
    let mut build = cc::Build::new();
    println!("cargo::rerun-if-env-changed=CORE_FUZZ_CROSS_COMPILE");
    if let Some(prefix) = env::var("CORE_FUZZ_CROSS_COMPILE")
        .ok()
        .filter(|prefix| !prefix.is_empty())
    {
        build
            .compiler(format!("{prefix}gcc"))
            .archiver(format!("{prefix}ar"));
    }
    build
        .file(&shim)
        .include(test_root.join("ta/core_fuzz_ta/include"))
        .include(&host_include)
        .include(client.join("include"))
        .define(
            "CORE_FUZZ_TA_RUST_MAX_OUTPUT",
            max_output.to_string().as_str(),
        )
        .define(
            "CORE_FUZZ_TA_RUST_COVERAGE_SIZE",
            coverage_size.to_string().as_str(),
        )
        .warnings(true)
        .compile("core_fuzz_teec");
    println!(
        "cargo::rustc-link-search=native={}",
        client.join("lib").display()
    );
    println!("cargo::rustc-link-lib=dylib=teec");

    Ok(format!(
        "// @generated by build.rs from pta_core_fuzz_cov.h\n\
         /// Size of the secure-world coverage map (`PTA_CORE_FUZZ_COV_MAP_SIZE`).\n\
         pub const COVERAGE_SIZE: usize = {coverage_size};\n"
    ))
}

fn main() -> BuildResult<()> {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or("CARGO_MANIFEST_DIR")?);
    let test_root = manifest.join("../..");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").ok_or("OUT_DIR")?);

    let header = read(&test_root.join("ta/core_fuzz_ta/include/core_fuzz_ta.h"))?;
    fs::write(
        out_dir.join("core_fuzz_ta_protocol.rs"),
        protocol_constants(&header)?,
    )?;

    if env::var_os("CARGO_FEATURE_RUNNER").is_some() {
        fs::write(
            out_dir.join("core_fuzz_cov.rs"),
            build_runner(&manifest, &test_root, &header)?,
        )?;
    }
    Ok(())
}

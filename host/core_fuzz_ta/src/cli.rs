// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Jaehun Lee
//! Command-line interface of the runner.
//!
//! The two invocation forms are the ones `scripts/qemu_fuzz.exp` uses:
//!
//! ```text
//! core-fuzz-ta-libafl SEED_DIR OUTPUT_DIR ITERATIONS RNG_SEED [--duration-seconds=N] [--execution-timeout-seconds=N]
//! core-fuzz-ta-libafl --replay INPUT_FILE [REPEAT_COUNT]
//! ```

use std::{
    ffi::{OsStr, OsString},
    fmt::Display,
    path::PathBuf,
    time::Duration,
};

use clap::{ArgGroup, CommandFactory, Parser, error::ErrorKind};

/// Largest accepted `ITERATIONS`.
pub const MAX_ITERATIONS: u64 = 100_000_000;
/// Largest accepted `--duration-seconds` (one day).
pub const MAX_DURATION_SECONDS: u64 = 86_400;
/// Default per-input timeout for QEMU with core KASan and crypto coverage.
pub const DEFAULT_EXECUTION_TIMEOUT_SECONDS: u64 = 360;
/// Largest accepted per-input timeout (one hour).
pub const MAX_EXECUTION_TIMEOUT_SECONDS: u64 = 3_600;
/// Largest accepted replay `REPEAT_COUNT`.
pub const MAX_REPEATS: u64 = 10_000;

/// Settings for a fuzzing campaign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuzzConfig {
    /// Directory with the `.bin` seed inputs.
    pub seed_dir: PathBuf,
    /// Directory below which a fresh `run-*` directory is created.
    pub output_root: PathBuf,
    /// Upper bound on mutation iterations.
    pub max_iterations: u64,
    /// Non-zero seed for LibAFL's RNG.
    pub rng_seed: u64,
    /// Optional wall-clock limit, counted after seed loading.
    pub duration: Option<Duration>,
    /// Maximum wall-clock time for one TA invocation.
    pub execution_timeout: Duration,
}

/// Settings for replaying one saved input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayConfig {
    /// The input to execute.
    pub input_file: PathBuf,
    /// How many times to execute it, each in a fresh TA session.
    pub repeats: u64,
}

/// What the runner was asked to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunMode {
    /// Run a coverage-guided campaign.
    Fuzz(FuzzConfig),
    /// Execute one saved input.
    Replay(ReplayConfig),
}

/// Coverage-guided fuzzer and replayer for the OP-TEE core_fuzz_ta.
#[derive(Debug, Parser)]
#[command(
    name = "core-fuzz-ta-libafl",
    version,
    override_usage = "core-fuzz-ta-libafl SEED_DIR OUTPUT_DIR ITERATIONS RNG_SEED [--duration-seconds=N] [--execution-timeout-seconds=N]\n       \
                      core-fuzz-ta-libafl --replay INPUT_FILE [REPEAT_COUNT]",
    group(ArgGroup::new("mode").required(true).args(["seed_dir", "replay"]))
)]
struct Cli {
    /// Directory containing `.bin` seed inputs
    #[arg(requires_all = ["output_dir", "iterations", "rng_seed"])]
    seed_dir: Option<PathBuf>,

    /// Directory below which a fresh run-YYYYMMDDHHMMSS directory is created
    output_dir: Option<PathBuf>,

    /// Maximum number of mutation iterations
    #[arg(value_parser = clap::value_parser!(u64).range(1..=MAX_ITERATIONS))]
    iterations: Option<u64>,

    /// Non-zero RNG seed; the same seed reproduces the same campaign
    #[arg(value_parser = parse_rng_seed)]
    rng_seed: Option<u64>,

    /// Stop after N seconds of fuzzing (seed loading is not counted)
    #[arg(
        long,
        value_name = "N",
        conflicts_with = "replay",
        value_parser = clap::value_parser!(u64).range(1..=MAX_DURATION_SECONDS)
    )]
    duration_seconds: Option<u64>,

    /// Stop an input after N seconds; default 360 for QEMU with core KASan
    #[arg(
        long,
        value_name = "N",
        conflicts_with = "replay",
        value_parser = clap::value_parser!(u64).range(1..=MAX_EXECUTION_TIMEOUT_SECONDS)
    )]
    execution_timeout_seconds: Option<u64>,

    /// Execute INPUT_FILE REPEAT_COUNT times (default 1) instead of fuzzing
    #[arg(
        long,
        num_args = 1..=2,
        value_names = ["INPUT_FILE", "REPEAT_COUNT"],
        value_parser = clap::value_parser!(OsString)
    )]
    replay: Option<Vec<OsString>>,
}

impl Cli {
    fn into_mode(self) -> Result<RunMode, clap::Error> {
        if let Some(values) = self.replay {
            let mut values = values.into_iter();
            let input_file = values.next().map(PathBuf::from).ok_or_else(|| {
                usage_error(
                    ErrorKind::MissingRequiredArgument,
                    "--replay needs INPUT_FILE",
                )
            })?;
            let repeats = values.next().map_or(Ok(1), |count| parse_repeats(&count))?;
            return Ok(RunMode::Replay(ReplayConfig {
                input_file,
                repeats,
            }));
        }

        match (
            self.seed_dir,
            self.output_dir,
            self.iterations,
            self.rng_seed,
        ) {
            (Some(seed_dir), Some(output_root), Some(max_iterations), Some(rng_seed)) => {
                Ok(RunMode::Fuzz(FuzzConfig {
                    seed_dir,
                    output_root,
                    max_iterations,
                    rng_seed,
                    duration: self.duration_seconds.map(Duration::from_secs),
                    execution_timeout: Duration::from_secs(
                        self.execution_timeout_seconds
                            .unwrap_or(DEFAULT_EXECUTION_TIMEOUT_SECONDS),
                    ),
                }))
            }
            _ => Err(usage_error(
                ErrorKind::MissingRequiredArgument,
                "SEED_DIR, OUTPUT_DIR, ITERATIONS and RNG_SEED are required",
            )),
        }
    }
}

/// `scripts/run_qemu_fuzz.sh` documents the seed as a positive integer.
/// Zero used to be replaced by one without notice; it is now rejected.
fn parse_rng_seed(text: &str) -> Result<u64, String> {
    match text.parse::<u64>() {
        Ok(0) => Err("the RNG seed must be non-zero".to_owned()),
        Ok(seed) => Ok(seed),
        Err(error) => Err(error.to_string()),
    }
}

fn usage_error(kind: ErrorKind, message: impl Display) -> clap::Error {
    Cli::command().error(kind, message)
}

fn parse_repeats(value: &OsStr) -> Result<u64, clap::Error> {
    value
        .to_str()
        .and_then(|text| text.parse().ok())
        .filter(|count| (1..=MAX_REPEATS).contains(count))
        .ok_or_else(|| {
            usage_error(
                ErrorKind::ValueValidation,
                format!("REPEAT_COUNT must be in 1..={MAX_REPEATS}, got {value:?}"),
            )
        })
}

/// Parses command-line arguments, including the program name.
///
/// # Errors
///
/// Returns a [`clap::Error`] for invalid arguments and for `--help` or
/// `--version`; [`clap::Error::exit`] prints it with the right exit status.
pub fn parse<I, T>(args: I) -> Result<RunMode, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    Cli::try_parse_from(args)?.into_mode()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(args: &[&str]) -> RunMode {
        parse(std::iter::once("runner").chain(args.iter().copied())).unwrap()
    }

    fn parse_err(args: &[&str]) -> ErrorKind {
        parse(std::iter::once("runner").chain(args.iter().copied()))
            .unwrap_err()
            .kind()
    }

    fn fuzz(duration: Option<u64>) -> RunMode {
        RunMode::Fuzz(FuzzConfig {
            seed_dir: "seeds".into(),
            output_root: "out".into(),
            max_iterations: 200,
            rng_seed: 7,
            duration: duration.map(Duration::from_secs),
            execution_timeout: Duration::from_secs(DEFAULT_EXECUTION_TIMEOUT_SECONDS),
        })
    }

    #[test]
    fn command_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn accepts_the_forms_used_by_the_scripts() {
        assert_eq!(parse_ok(&["seeds", "out", "200", "7"]), fuzz(None));
        assert_eq!(
            parse_ok(&["seeds", "out", "200", "7", "--duration-seconds=60"]),
            fuzz(Some(60))
        );
        assert_eq!(
            parse_ok(&["seeds", "out", "200", "7", "--duration-seconds", "60"]),
            fuzz(Some(60))
        );
        let RunMode::Fuzz(custom) = parse_ok(&[
            "seeds",
            "out",
            "200",
            "7",
            "--execution-timeout-seconds=600",
        ]) else {
            panic!("expected fuzz mode");
        };
        assert_eq!(custom.execution_timeout, Duration::from_secs(600));
        assert_eq!(
            parse_ok(&["--replay", "in.bin"]),
            RunMode::Replay(ReplayConfig {
                input_file: "in.bin".into(),
                repeats: 1
            })
        );
        assert_eq!(
            parse_ok(&["--replay", "in.bin", "3"]),
            RunMode::Replay(ReplayConfig {
                input_file: "in.bin".into(),
                repeats: 3
            })
        );
    }

    #[test]
    fn rejects_out_of_range_values() {
        assert_eq!(
            parse_err(&["seeds", "out", "0", "7"]),
            ErrorKind::ValueValidation
        );
        assert_eq!(
            parse_err(&["seeds", "out", "100000001", "7"]),
            ErrorKind::ValueValidation
        );
        assert_eq!(
            parse_err(&["seeds", "out", "200", "0"]),
            ErrorKind::ValueValidation
        );
        assert_eq!(
            parse_err(&["seeds", "out", "200", "7", "--duration-seconds=0"]),
            ErrorKind::ValueValidation
        );
        assert_eq!(
            parse_err(&["seeds", "out", "200", "7", "--duration-seconds=86401"]),
            ErrorKind::ValueValidation
        );
        assert_eq!(
            parse_err(&["seeds", "out", "200", "7", "--execution-timeout-seconds=0"]),
            ErrorKind::ValueValidation
        );
        assert_eq!(
            parse_err(&[
                "seeds",
                "out",
                "200",
                "7",
                "--execution-timeout-seconds=3601"
            ]),
            ErrorKind::ValueValidation
        );
        assert_eq!(
            parse_err(&["--replay", "in.bin", "0"]),
            ErrorKind::ValueValidation
        );
        assert_eq!(
            parse_err(&["--replay", "in.bin", "10001"]),
            ErrorKind::ValueValidation
        );
        assert_eq!(
            parse_err(&["--replay", "in.bin", "x"]),
            ErrorKind::ValueValidation
        );
    }

    #[test]
    fn rejects_incomplete_or_mixed_invocations() {
        assert_eq!(parse_err(&[]), ErrorKind::MissingRequiredArgument);
        assert_eq!(
            parse_err(&["seeds", "out", "200"]),
            ErrorKind::MissingRequiredArgument
        );
        assert_eq!(
            parse_err(&["seeds", "out", "200", "7", "--replay", "in.bin"]),
            ErrorKind::ArgumentConflict
        );
        assert_eq!(
            parse_err(&["--replay", "in.bin", "--duration-seconds=5"]),
            ErrorKind::ArgumentConflict
        );
        assert_eq!(
            parse_err(&["--replay", "in.bin", "--execution-timeout-seconds=5"]),
            ErrorKind::ArgumentConflict
        );
        assert_eq!(
            parse_err(&[
                "seeds",
                "out",
                "200",
                "7",
                "--duration-seconds=5",
                "--duration-seconds=6"
            ]),
            ErrorKind::ArgumentConflict
        );
        assert_eq!(
            parse_err(&["seeds", "out", "200", "7", "--bogus"]),
            ErrorKind::UnknownArgument
        );
    }

    #[cfg(unix)]
    #[test]
    fn accepts_non_utf8_paths() {
        use std::os::unix::ffi::OsStrExt;
        let path = OsStr::from_bytes(b"seeds-\xff");
        let mode = parse([
            OsStr::new("runner"),
            path,
            "out".as_ref(),
            "1".as_ref(),
            "1".as_ref(),
        ])
        .unwrap();
        let RunMode::Fuzz(config) = mode else {
            panic!("expected fuzz mode");
        };
        assert_eq!(config.seed_dir.as_os_str(), path);
    }
}

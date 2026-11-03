// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Jaehun Lee
//! The coverage-guided campaign.

use std::{
    cell::{Cell, RefCell},
    error::Error,
    fs, io,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use core_fuzz_ta_libafl::{
    algorithms::AlgorithmSet,
    cli::FuzzConfig,
    mutator::CoreFuzzProgramMutator,
    output,
    protocol::MAX_OUTPUT_SIZE,
    response::{self, OpcodeStats},
    stats::CoverageStats,
};
use libafl::{
    corpus::{Corpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{ExitKind, InProcessExecutor},
    feedbacks::{MaxMapFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::scheduled::StdScheduledMutator,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasExecutions, StdState},
};
use libafl_bolts::{AsSlice, rands::StdRand, tuples::tuple_list};

use super::{coverage::CoverageMap, print_opcode_steps, print_opcode_totals, teec::TeecContext};

/// LibAFL version pinned in Cargo.toml, reported in the log header.
const LIBAFL_VERSION: &str = "0.15.2";
/// Iterations between `FUZZ_PROGRESS` lines.
const PROGRESS_INTERVAL: u64 = 25;

/// Counters updated by the harness and read between executions.
struct Totals {
    coverage: CoverageStats,
    opcodes: OpcodeStats,
    invoke_errors: u64,
    rejected_inputs: u64,
}

/// Directories of one campaign below the output root.
struct RunArtifacts {
    root: PathBuf,
    corpus: PathBuf,
    hangs: PathBuf,
}

impl RunArtifacts {
    fn create(output_root: &Path) -> io::Result<Self> {
        let root = output::create_run_dir(output_root)?;
        let artifacts = Self {
            corpus: root.join("corpus"),
            hangs: root.join("hangs"),
            root,
        };
        fs::create_dir(&artifacts.corpus)?;
        fs::create_dir(&artifacts.hangs)?;
        Ok(artifacts)
    }
}

/// Executes one input: records it, invokes the TA and updates `totals`.
fn execute(
    teec: &TeecContext,
    coverage: &mut CoverageMap,
    run_dir: &Path,
    input: &[u8],
    algorithms: AlgorithmSet,
    totals: &mut Totals,
    save_error: &Cell<Option<io::Error>>,
) -> ExitKind {
    if !algorithms.allows_bytes(input) {
        totals.rejected_inputs += 1;
        coverage.clear();
        return ExitKind::Ok;
    }
    if let Err(error) = output::write_current(run_dir, input) {
        // Keep the first error; the campaign loop stops after this call.
        let first = save_error.take().unwrap_or(error);
        save_error.set(Some(first));
        return ExitKind::Ok;
    }

    let mut response = [0u8; MAX_OUTPUT_SIZE];
    let invocation = teec.run(input, &mut response, coverage);
    if invocation.succeeded() {
        if let Some(Ok(steps)) = response.get(..invocation.response_len).map(response::parse) {
            print_opcode_steps(steps, &mut totals.opcodes);
        }
    }

    if invocation.input_rejected() {
        totals.rejected_inputs += 1;
        coverage.clear();
    } else if !invocation.succeeded() {
        totals.invoke_errors += 1;
        println!("FUZZ_INVOKE_ERROR=0x{:08x}", invocation.result);
        if invocation.target_dead() {
            totals.coverage.record_target_dead();
        }
        coverage.clear();
    } else if invocation.coverage_len == coverage.len() {
        totals.coverage.record(Some(coverage.as_slice()));
    } else {
        totals.coverage.record(None);
        coverage.clear();
    }
    ExitKind::Ok
}

fn exec_per_sec(executions: u64, elapsed: Duration) -> f64 {
    executions as f64 / elapsed.as_secs_f64().max(0.001)
}

fn report_progress(
    iteration: u64,
    executions: u64,
    elapsed: Duration,
    corpus_count: usize,
    coverage: &CoverageStats,
) {
    println!(
        "FUZZ_PROGRESS iteration={iteration} executions={executions} exec_per_sec={:.1} \
         corpus={corpus_count} secure_map_bytes={} last_map_bytes={} invalid_coverage={} \
         target_dead={}",
        exec_per_sec(executions, elapsed),
        coverage.seen_map_bytes(),
        coverage.last_map_bytes(),
        coverage.invalid_runs(),
        coverage.target_dead_runs(),
    );
}

fn report_completion(
    iterations: u64,
    executions: u64,
    elapsed: Duration,
    corpus_count: usize,
    totals: &Totals,
    status: u8,
) {
    print_opcode_totals(&totals.opcodes);
    println!(
        "FUZZ_DONE STATUS={status} ENGINE=libafl WORKERS=1 ITERATIONS={iterations} \
         EXECUTIONS={executions} EXEC_PER_SEC={:.1} CORPUS={corpus_count} SECURE_MAP_BYTES={} \
         INVALID_COVERAGE={} TARGET_DEAD={} INVOKE_ERRORS={} REJECTED_INPUTS={}",
        exec_per_sec(executions, elapsed),
        totals.coverage.seen_map_bytes(),
        totals.coverage.invalid_runs(),
        totals.coverage.target_dead_runs(),
        totals.invoke_errors,
        totals.rejected_inputs,
    );
}

/// Runs a campaign as described by `config`.
pub(crate) fn run(config: &FuzzConfig) -> Result<(), Box<dyn Error>> {
    let artifacts = RunArtifacts::create(&config.output_root)?;
    let selected_seed_dir = artifacts.root.join("selected-seeds");
    fs::create_dir(&selected_seed_dir)?;
    let mut seed_count = 0;
    for entry in fs::read_dir(&config.seed_dir)? {
        let entry = entry?;
        if !entry.path().extension().is_some_and(|ext| ext == "bin") {
            continue;
        }
        let bytes = fs::read(entry.path())?;
        if config.algorithms.allows_bytes(&bytes) {
            fs::write(selected_seed_dir.join(entry.file_name()), bytes)?;
            seed_count += 1;
        }
    }
    if seed_count == 0 {
        return Err(format!(
            "no seeds match algorithms={} in {}",
            config.algorithms,
            config.seed_dir.display()
        )
        .into());
    }
    println!("FUZZ_RUN_DIR={}", artifacts.root.display());
    println!("FUZZ_ENGINE=libafl VERSION={LIBAFL_VERSION} WORKERS=1");
    println!("FUZZ_RNG_SEED={}", config.rng_seed);
    println!("FUZZ_ALGORITHMS={}", config.algorithms);
    println!(
        "FUZZ_EXECUTION_TIMEOUT_SECONDS={}",
        config.execution_timeout.as_secs()
    );
    println!("FUZZ_MUTATOR=core_fuzz_program_structured_v1 structured_preferred=80%");

    let teec = TeecContext::new()?;
    let mut coverage_map = CoverageMap::new();
    let observer = coverage_map.observer();
    let mut feedback = MaxMapFeedback::new(&observer);
    // LibAFL timeouts are hang candidates; TEEC target death is a harness
    // diagnostic unless secure-console evidence independently shows a core bug.
    let mut objective = TimeoutFeedback::new();
    let mut state = StdState::new(
        StdRand::with_seed(config.rng_seed),
        OnDiskCorpus::new(&artifacts.corpus)?,
        OnDiskCorpus::new(&artifacts.hangs)?,
        &mut feedback,
        &mut objective,
    )?;
    let mut fuzzer = StdFuzzer::new(QueueScheduler::new(), feedback, objective);
    let mut manager = SimpleEventManager::new(SimpleMonitor::new(|message| println!("{message}")));

    let totals = RefCell::new(Totals {
        coverage: CoverageStats::new(coverage_map.len()),
        opcodes: OpcodeStats::default(),
        invoke_errors: 0,
        rejected_inputs: 0,
    });
    let save_error = Cell::new(None);
    let check_save_error = || match save_error.take() {
        Some(error) => Err(format!("could not save current input: {error}")),
        None => Ok(()),
    };
    let mut harness = |input: &BytesInput| {
        let bytes = input.target_bytes();
        execute(
            &teec,
            &mut coverage_map,
            &artifacts.root,
            bytes.as_slice(),
            config.algorithms,
            &mut totals.borrow_mut(),
            &save_error,
        )
    };
    let mut executor = InProcessExecutor::with_timeout(
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut manager,
        config.execution_timeout,
    )?;

    state.load_initial_inputs(
        &mut fuzzer,
        &mut executor,
        &mut manager,
        std::slice::from_ref(&selected_seed_dir),
    )?;
    check_save_error()?;
    let baseline_executions = *state.executions();
    println!(
        "FUZZ_BASELINE_SEEDS={seed_count} CORPUS={} SECURE_MAP_BYTES={}",
        state.corpus().count(),
        totals.borrow().coverage.seen_map_bytes(),
    );

    let mutator =
        StdScheduledMutator::new(tuple_list!(CoreFuzzProgramMutator::new(config.algorithms)));
    let mut stages = tuple_list!(StdMutationalStage::with_max_iterations(
        mutator,
        NonZeroUsize::MIN,
    ));
    let started = Instant::now();
    let mut iterations_done = 0;
    for iteration in 1..=config.max_iterations {
        if config
            .duration
            .is_some_and(|limit| started.elapsed() >= limit)
        {
            break;
        }
        fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut manager)?;
        check_save_error()?;
        iterations_done = iteration;
        if iteration % PROGRESS_INTERVAL == 0 || iteration == config.max_iterations {
            report_progress(
                iteration,
                state.executions().saturating_sub(baseline_executions),
                started.elapsed(),
                state.corpus().count(),
                &totals.borrow().coverage,
            );
        }
    }

    let harness_error = totals.borrow().invoke_errors > 0;
    report_completion(
        iterations_done,
        state.executions().saturating_sub(baseline_executions),
        started.elapsed(),
        state.corpus().count(),
        &totals.borrow(),
        if harness_error { 2 } else { 0 },
    );
    if harness_error {
        return Err("TEEC invocation failed without confirmed core evidence".into());
    }
    Ok(())
}

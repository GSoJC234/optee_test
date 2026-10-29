// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Jaehun Lee
//! Campaign output directory handling.

use std::{
    fs, io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

/// Attempts at a unique `run-<timestamp>[-N]` name before giving up.
const RUN_DIR_ATTEMPTS: u32 = 1000;

/// Records `input` as `current.bin` before it runs, so the input that brings
/// down the guest can be recovered from the host.
///
/// The write goes through a temporary file and a rename so a reader never
/// sees a partial input. No `fsync` is issued: the guest mounts the output
/// directory over 9p with the default `cache=none`, so data already reaches
/// the host on `write`, and a per-execution `fsync` would only add a host
/// disk flush.
///
/// # Errors
///
/// Returns any I/O error from writing or renaming the file.
pub fn write_current(run_dir: &Path, input: &[u8]) -> io::Result<()> {
    let temporary = run_dir.join("current.tmp");
    fs::write(&temporary, input)?;
    fs::rename(temporary, run_dir.join("current.bin"))
}

/// Creates a fresh `run-YYYYMMDDHHMMSS` directory (UTC) below `output_root`.
///
/// # Errors
///
/// Returns an I/O error if `output_root` cannot be created or no unique
/// directory name is available.
pub fn create_run_dir(output_root: &Path) -> io::Result<PathBuf> {
    fs::create_dir_all(output_root)?;
    let stem = format!("run-{}", utc_timestamp(SystemTime::now()));
    for suffix in 0..RUN_DIR_ATTEMPTS {
        let path = if suffix == 0 {
            output_root.join(&stem)
        } else {
            output_root.join(format!("{stem}-{suffix}"))
        };
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique run directory",
    ))
}

/// Counts the `.bin` files in `seed_dir`.
///
/// # Errors
///
/// Returns an I/O error if the directory cannot be read.
pub fn count_seed_files(seed_dir: &Path) -> io::Result<usize> {
    Ok(fs::read_dir(seed_dir)?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "bin"))
        .count())
}

/// Formats `time` as `YYYYMMDDHHMMSS` in UTC; times before 1970 clamp to the epoch.
#[must_use]
pub fn utc_timestamp(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (days, second_of_day) = (seconds / 86_400, seconds % 86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}{month:02}{day:02}{:02}{:02}{:02}",
        second_of_day / 3600,
        second_of_day / 60 % 60,
        second_of_day % 60
    )
}

/// Converts days since 1970-01-01 to a Gregorian `(year, month, day)`.
///
/// This is Howard Hinnant's `civil_from_days`, restricted to non-negative
/// day counts.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(seconds: u64) -> String {
        utc_timestamp(UNIX_EPOCH + Duration::from_secs(seconds))
    }

    #[test]
    fn timestamps_match_known_dates() {
        assert_eq!(at(0), "19700101000000");
        assert_eq!(at(951_782_400), "20000229000000");
        assert_eq!(at(1_700_000_000), "20231114221320");
        assert_eq!(at(4_102_444_799), "20991231235959");
    }

    #[test]
    fn run_directories_are_unique_and_current_input_is_replaced() {
        let root = std::env::temp_dir().join(format!("core-fuzz-output-{}", std::process::id()));
        let first = create_run_dir(&root).unwrap();
        let second = create_run_dir(&root).unwrap();
        assert_ne!(first, second);

        write_current(&first, b"one").unwrap();
        write_current(&first, b"two").unwrap();
        assert_eq!(fs::read(first.join("current.bin")).unwrap(), b"two");
        assert!(!first.join("current.tmp").exists());

        fs::write(first.join("seed.bin"), b"").unwrap();
        fs::write(first.join("notes.txt"), b"").unwrap();
        assert_eq!(count_seed_files(&first).unwrap(), 2);

        fs::remove_dir_all(root).unwrap();
    }
}

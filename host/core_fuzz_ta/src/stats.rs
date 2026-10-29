// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026, Jaehun Lee
//! Campaign-wide coverage statistics.

/// Running totals over all executions of a campaign.
///
/// Unlike LibAFL's map feedback, which only remembers inputs it keeps, this
/// counts every execution, including crashing ones.
#[derive(Clone, Debug)]
pub struct CoverageStats {
    seen: Vec<bool>,
    seen_map_bytes: usize,
    last_map_bytes: usize,
    invalid_runs: u64,
    target_dead_runs: u64,
}

impl CoverageStats {
    /// Creates empty statistics for a map of `map_len` bytes.
    #[must_use]
    pub fn new(map_len: usize) -> Self {
        Self {
            seen: vec![false; map_len],
            seen_map_bytes: 0,
            last_map_bytes: 0,
            invalid_runs: 0,
            target_dead_runs: 0,
        }
    }

    /// Accounts for one execution; `map` is `None` if it produced no usable
    /// coverage map.
    pub fn record(&mut self, map: Option<&[u8]>) {
        let Some(map) = map else {
            self.invalid_runs += 1;
            return;
        };
        let mut hit = 0;
        for (seen, &byte) in self.seen.iter_mut().zip(map) {
            if byte != 0 {
                hit += 1;
                if !*seen {
                    *seen = true;
                    self.seen_map_bytes += 1;
                }
            }
        }
        self.last_map_bytes = hit;
    }

    /// Accounts for an execution in which the TA died.
    pub fn record_target_dead(&mut self) {
        self.target_dead_runs += 1;
    }

    /// Map entries hit by at least one execution so far.
    #[must_use]
    pub fn seen_map_bytes(&self) -> usize {
        self.seen_map_bytes
    }

    /// Map entries hit by the most recent valid execution.
    #[must_use]
    pub fn last_map_bytes(&self) -> usize {
        self.last_map_bytes
    }

    /// Executions that returned no usable coverage map.
    #[must_use]
    pub fn invalid_runs(&self) -> u64 {
        self.invalid_runs
    }

    /// Executions in which the TA died.
    #[must_use]
    pub fn target_dead_runs(&self) -> u64 {
        self.target_dead_runs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_track_new_and_last_coverage() {
        let mut stats = CoverageStats::new(16);
        let mut map = [0u8; 16];
        map[1] = 3;
        map[7] = 1;
        stats.record(Some(&map));
        map[7] = 0;
        map[9] = 1;
        stats.record(Some(&map));
        stats.record(None);
        stats.record_target_dead();
        assert_eq!(stats.seen_map_bytes(), 3);
        assert_eq!(stats.last_map_bytes(), 2);
        assert_eq!(stats.invalid_runs(), 1);
        assert_eq!(stats.target_dead_runs(), 1);
    }
}

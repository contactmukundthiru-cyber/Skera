//! Phase pipeline — modular, parallelizable scan architecture
//!
//! Each detection module implements `ScanPhase`, returning violations
//! and evidence independently. The pipeline orchestrator groups phases
//! by dependency and runs independent phases in parallel via rayon.

use crate::analysis::source_scanner::SourceScan;
use crate::detection::Violation;
use crate::license::LicenseId;
use crate::SkeraResult;
use super::file_index::FileIndex;
use super::{PhaseStats, SkeraConfig};
use std::path::PathBuf;

// ─── Phase Output ──────────────────────────────────────────────────

/// Output from a single scan phase — violations + metadata
#[derive(Debug, Clone, Default)]
pub struct PhaseOutput {
    pub violations: Vec<Violation>,
    pub files_processed: usize,
    /// Optional: dependency list discovered by this phase
    pub dependencies: Vec<(String, LicenseId)>,
    /// Optional: project license discovered by this phase
    pub discovered_license: Option<LicenseId>,
    /// Optional: number of binaries analyzed
    pub binaries_analyzed: usize,
}

impl PhaseOutput {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_violations(violations: Vec<Violation>, files: usize) -> Self {
        Self {
            violations,
            files_processed: files,
            ..Default::default()
        }
    }
}

// ─── Scan Context ──────────────────────────────────────────────────

/// Immutable shared context available to all detection phases.
/// Constructed after Phase 1 (source scan) determines the project license.
pub struct ScanContext {
    pub config: SkeraConfig,
    pub file_index: FileIndex,
    pub source_dir: PathBuf,
    pub project_license: LicenseId,
    pub source_scan: SourceScan,
}

impl ScanContext {
    pub fn new(
        config: SkeraConfig,
        file_index: FileIndex,
        source_dir: PathBuf,
        project_license: LicenseId,
        source_scan: SourceScan,
    ) -> Self {
        Self {
            config,
            file_index,
            source_dir,
            project_license,
            source_scan,
        }
    }
}

// ─── Phase Trait ───────────────────────────────────────────────────

/// A single scan phase that can run independently.
///
/// Phases are:
/// - **Self-contained**: each owns its required scanners/databases
/// - **Immutable**: `run()` takes `&self` and `&ScanContext`
/// - **Parallelizable**: independent phases run concurrently via rayon
/// - **Panic-safe**: the pipeline catches panics and continues
pub trait ScanPhase: Send + Sync {
    /// Human-readable name for logging and stats
    fn name(&self) -> &str;

    /// Whether this phase should run given the current config
    fn should_run(&self, _config: &SkeraConfig) -> bool {
        true
    }

    /// Execute the phase and return findings
    fn run(&self, ctx: &ScanContext) -> SkeraResult<PhaseOutput>;
}

// ─── Pipeline Execution ────────────────────────────────────────────

/// Execute a single phase with timing, logging, and panic safety
pub fn run_phase_timed(
    phase: &dyn ScanPhase,
    ctx: &ScanContext,
) -> (PhaseStats, PhaseOutput) {
    let start = std::time::Instant::now();
    tracing::info!("→ {}", phase.name());

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| phase.run(ctx)));

    let duration_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok(Ok(output)) => {
            tracing::info!(
                "  ✓ {} completed in {}ms ({} violations, {} files)",
                phase.name(),
                duration_ms,
                output.violations.len(),
                output.files_processed
            );
            (
                PhaseStats {
                    name: phase.name().to_string(),
                    duration_ms,
                    violations_found: output.violations.len(),
                    files_processed: output.files_processed,
                },
                output,
            )
        }
        Ok(Err(e)) => {
            tracing::error!("  ✗ {} failed: {} ({}ms)", phase.name(), e, duration_ms);
            (
                PhaseStats {
                    name: format!("{} [ERROR]", phase.name()),
                    duration_ms,
                    violations_found: 0,
                    files_processed: 0,
                },
                PhaseOutput::default(),
            )
        }
        Err(e) => {
            tracing::error!("  ✗ {} panicked: {:?} ({}ms)", phase.name(), e, duration_ms);
            (
                PhaseStats {
                    name: format!("{} [PANIC]", phase.name()),
                    duration_ms,
                    violations_found: 0,
                    files_processed: 0,
                },
                PhaseOutput::default(),
            )
        }
    }
}

/// Execute multiple independent phases in parallel using rayon
pub fn run_phases_parallel(
    phases: &[&dyn ScanPhase],
    ctx: &ScanContext,
) -> Vec<(PhaseStats, PhaseOutput)> {
    use rayon::prelude::*;

    phases
        .par_iter()
        .filter(|p| p.should_run(&ctx.config))
        .map(|phase| run_phase_timed(*phase, ctx))
        .collect()
}

/// Merge all phase outputs into a single violation list
pub fn merge_outputs(outputs: Vec<(PhaseStats, PhaseOutput)>) -> (Vec<PhaseStats>, Vec<Violation>, usize) {
    let mut stats = Vec::new();
    let mut violations = Vec::new();
    let mut total_files = 0usize;

    for (stat, output) in outputs {
        stats.push(stat);
        violations.extend(output.violations);
        total_files += output.files_processed;
    }

    (stats, violations, total_files)
}

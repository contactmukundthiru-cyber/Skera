//! # Skera Engine — Lean Orchestrator
//!
//! The scan pipeline has been decomposed from a 2018-line monolith into:
//!
//! - `file_index` — single-pass directory walk shared by all phases
//! - `pipeline` — Phase trait, ScanContext, parallel execution
//! - `phases/` — 16 independent detection phase modules
//! - `correlation` — cross-module violation correlation
//! - `dedup` — violation deduplication
//! - `scoring` — context-aware risk scoring
//! - `cache` — incremental scan cache (SHA-256 content-addressed)
//! - `comparison` — two-target forensic comparison engine
//! - `repo_clone` — git shallow clone for remote scanning

pub mod file_index;
pub mod pipeline;
pub mod phases;
pub mod correlation;
pub mod dedup;
pub mod scoring;
pub mod cache;
pub mod comparison;
pub mod repo_clone;

use crate::analysis::source_scanner::SourceScanner;
use crate::detection::{DetectionResult, Severity};
use crate::evidence::{EvidenceBundle, EvidenceChain};
use crate::ingest::{Ingestor, InputSpec};
use crate::license::LicenseId;
use crate::{SkeraError, SkeraResult};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

// ─── Configuration ─────────────────────────────────────────────────

/// Engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkeraConfig {
    /// Enable AI-powered verification (requires API key)
    pub ai_verification: bool,
    /// Enable binary (ELF/PE/Mach-O) analysis
    pub binary_analysis: bool,
    /// Enable dependency graph analysis
    pub dependency_analysis: bool,
    /// Enable code fingerprinting
    pub fingerprinting: bool,
    /// Minimum confidence threshold (0.0-1.0)
    pub min_confidence: f64,
    /// Minimum severity to report
    pub min_severity: Severity,
    /// Path to Ghidra for deep binary analysis
    pub ghidra_path: Option<String>,
    /// Project's declared/known license
    pub known_license: Option<String>,
    /// Whether this is a commercial project
    pub commercial: bool,
    /// Whether this is a network/SaaS service (affects AGPL analysis)
    pub network_service: bool,
    /// Enable incremental caching
    pub use_cache: bool,
    /// Enable policy engine (.skera.toml)
    pub use_policy: bool,
}

impl Default for SkeraConfig {
    fn default() -> Self {
        Self {
            ai_verification: true,
            binary_analysis: true,
            dependency_analysis: true,
            fingerprinting: true,
            min_confidence: 0.3,
            min_severity: Severity::Low,
            ghidra_path: None,
            known_license: None,
            commercial: true,
            network_service: false,
            use_cache: false,
            use_policy: true,
        }
    }
}

// ─── Scan Target ───────────────────────────────────────────────────

/// What to scan
#[derive(Debug, Clone)]
pub enum ScanTarget {
    SourceDirectory(PathBuf),
    SingleFile(PathBuf),
    Repository(String),
    Package(crate::audit::PackageSpec),
    Url(String),
    Stdin { content: String, filename_hint: Option<String> },
    AutoDetect(String),
}

// ─── Phase Statistics ──────────────────────────────────────────────

/// Timing and stats for a single phase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseStats {
    pub name: String,
    pub duration_ms: u64,
    pub violations_found: usize,
    pub files_processed: usize,
}

// ─── Risk Level ────────────────────────────────────────────────────

/// Overall risk assessment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Clean,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clean => write!(f, "Clean"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

// ─── Scan Report ───────────────────────────────────────────────────

/// Complete scan report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub target: String,
    pub project_license: Option<LicenseId>,
    pub detection_result: DetectionResult,
    pub evidence: EvidenceBundle,
    pub total_dependencies: usize,
    pub binaries_analyzed: usize,
    pub risk_score: u32,
    pub risk_level: RiskLevel,
    pub duration_ms: u64,
    pub scanner_version: String,
    pub phase_stats: Vec<PhaseStats>,
    pub violations_filtered: usize,
    pub violations_deduplicated: usize,
    /// Cache hit rate (if caching was enabled)
    pub cache_hit_rate: Option<f64>,
    /// Policy violations (from .skera.toml)
    pub policy_violations: usize,
    /// Whether the risk score exceeded the policy threshold
    pub risk_threshold_exceeded: bool,
}

// ─── Engine ────────────────────────────────────────────────────────

/// The Skera forensic scanner
pub struct SkeraEngine {
    config: SkeraConfig,
    source_scanner: SourceScanner,
}

impl SkeraEngine {
    pub fn new(config: SkeraConfig) -> Self {
        Self {
            config,
            source_scanner: SourceScanner::new(),
        }
    }

    /// Main scan entry point — orchestrates the full pipeline
    pub async fn scan(&self, target: ScanTarget) -> SkeraResult<ScanReport> {
        let start = std::time::Instant::now();
        let target_str = format!("{:?}", target);
        tracing::info!("═══════════════════════════════════════════════════════");
        tracing::info!("Skera scan: {}", target_str);
        tracing::info!("═══════════════════════════════════════════════════════");

        let mut phase_stats: Vec<PhaseStats> = Vec::new();
        let mut evidence = EvidenceBundle::new(&target_str);
        let mut _temp_dir: Option<TempDir> = None;
        let mut scan_cache: Option<cache::ScanCache> = None;

        // ── Step 1: Resolve scan target to a directory ──
        let source_dir: PathBuf = match &target {
            ScanTarget::SourceDirectory(p) => p.clone(),
            ScanTarget::SingleFile(p) => p.parent().unwrap_or(Path::new(".")).to_path_buf(),
            ScanTarget::Repository(url) => {
                let (tmp, path) = repo_clone::RepoCloner::shallow_clone(url)
                    .map_err(|e| SkeraError::AnalysisError(e))?;
                _temp_dir = Some(tmp);
                path
            }
            ScanTarget::AutoDetect(input) => {
                match InputSpec::auto_detect(input) {
                    Ok(InputSpec::LocalPath(p)) => p,
                    Ok(InputSpec::GitRepo { url, .. }) => {
                        let (tmp, path) = repo_clone::RepoCloner::shallow_clone(&url)
                            .map_err(|e| SkeraError::AnalysisError(e))?;
                        _temp_dir = Some(tmp);
                        path
                    }
                    Ok(spec) => {
                        let ingested = Ingestor::ingest(spec).await
                            .map_err(|e| SkeraError::AnalysisError(e))?;
                        ingested.content_dir
                    }
                    Err(_e) => {
                        // Fall back to treating as path
                        PathBuf::from(input)
                    }
                }
            }
            ScanTarget::Package(spec) => {
                let ingested = Ingestor::ingest(InputSpec::Package(spec.clone())).await
                    .map_err(|e| SkeraError::AnalysisError(e))?;
                ingested.content_dir
            }
            ScanTarget::Url(url) => {
                let ingested = Ingestor::ingest(InputSpec::WebsiteUrl(url.clone())).await
                    .map_err(|e| SkeraError::AnalysisError(e))?;
                ingested.content_dir
            }
            ScanTarget::Stdin { content, filename_hint } => {
                let ingested = Ingestor::ingest(InputSpec::Stdin {
                    content: content.clone(),
                    filename_hint: filename_hint.clone(),
                }).await.map_err(|e| SkeraError::AnalysisError(e))?;
                ingested.content_dir
            }
        };

        if !source_dir.exists() {
            return Err(SkeraError::AnalysisError(format!(
                "Target directory does not exist: {}",
                source_dir.display()
            )));
        }

        // ── Step 2: Build FileIndex (single-pass directory walk) ──
        let index_start = std::time::Instant::now();
        let file_index = file_index::FileIndex::build(&source_dir);
        let index_ms = index_start.elapsed().as_millis() as u64;
        tracing::info!(
            "File index: {} files, {:.1} MB in {}ms",
            file_index.total_files(),
            file_index.total_bytes as f64 / 1_048_576.0,
            index_ms
        );
        phase_stats.push(PhaseStats {
            name: "FileIndex".into(),
            duration_ms: index_ms,
            violations_found: 0,
            files_processed: file_index.total_files(),
        });

        // ── Step 2b: Load scan cache ──
        if self.config.use_cache {
            let c = cache::ScanCache::load(&source_dir);
            tracing::info!("Scan cache loaded ({} entries)", c.hits() + c.misses());
            scan_cache = Some(c);
        }

        // ── Step 3: Load policy engine ──
        let policy = if self.config.use_policy {
            Some(crate::policy::PolicyEngine::from_project_root(&source_dir))
        } else {
            None
        };

        // ── Step 4: Phase 1 — Source scan (determines project license) ──
        let phase1_start = std::time::Instant::now();
        let source_scan = self.source_scanner.scan(&source_dir);
        let project_license = self.config.known_license
            .as_ref()
            .map(|l| LicenseId::new(l))
            .or_else(|| source_scan.project_license.as_ref().map(|p| p.license.clone()));
        let phase1_ms = phase1_start.elapsed().as_millis() as u64;
        tracing::info!(
            "Phase 1 (Source Scan): project_license={:?} ({}ms)",
            project_license, phase1_ms
        );
        phase_stats.push(PhaseStats {
            name: "Source Scan".into(),
            duration_ms: phase1_ms,
            violations_found: 0,
            files_processed: source_scan.total_files,
        });

        // ── Step 5: Build ScanContext ──
        let ctx = pipeline::ScanContext::new(
            self.config.clone(),
            file_index,
            source_dir.clone(),
            project_license.clone().unwrap_or_else(|| LicenseId::new("UNKNOWN")),
            source_scan,
        );

        // ── Step 6: Run all detection phases in parallel ──
        let detection_phases = phases::build_detection_phases();
        let phase_refs: Vec<&dyn pipeline::ScanPhase> = detection_phases
            .iter()
            .map(|p| p.as_ref())
            .collect();

        tracing::info!("Running {} detection phases in parallel...", phase_refs.len());
        let results = pipeline::run_phases_parallel(&phase_refs, &ctx);
        let (mut p_stats, all_outputs) = {
            let mut stats = Vec::new();
            let mut outputs = Vec::new();
            for (st, out) in results {
                stats.push(st);
                outputs.push(out);
            }
            (stats, outputs)
        };
        phase_stats.append(&mut p_stats);

        // Extract aggregate data from all phase outputs
        let mut all_violations = Vec::new();
        let mut all_deps: Vec<(String, LicenseId)> = Vec::new();
        let mut total_deps = 0usize;
        let mut binaries_analyzed = 0usize;
        for output in all_outputs {
            all_violations.extend(output.violations);
            if !output.dependencies.is_empty() {
                total_deps = output.dependencies.len();
                all_deps.extend(output.dependencies);
            }
            binaries_analyzed += output.binaries_analyzed;
        }

        // ── Step 7: Apply policy ──
        let mut policy_violations = 0usize;
        if let Some(ref pol) = policy {
            // Check blocked licenses from discovered deps
            if !all_deps.is_empty() {
                let blocked = pol.check_blocked_licenses(&all_deps);
                if !blocked.is_empty() {
                    tracing::info!("Policy: {} blocked-license violations", blocked.len());
                    all_violations.extend(blocked);
                }
            }

            let pre_count = all_violations.len();
            pol.apply(&mut all_violations);
            policy_violations = pre_count - all_violations.len();
            if policy_violations > 0 {
                tracing::info!("Policy filtered {} violations", policy_violations);
            }
        }

        // ── Step 8: Build DetectionResult ──
        let mut result = DetectionResult::default();
        result.violations = all_violations;
        result.files_scanned = ctx.file_index.total_files();
        result.dependencies_analyzed = total_deps;
        for (name, license) in &all_deps {
            result.record_dependency(name.clone(), license.clone());
        }
        dedup::recalculate_counts(&mut result);

        // ── Step 9: AI verification (optional, post-detection) ──
        if self.config.ai_verification {
            let ai_phase = phases::ai_verification::AiVerificationPhase::new(&self.config);
            if ai_phase.is_available() {
                tracing::info!(
                    "AI verification: {} violations to verify",
                    result.violations.len()
                );
                let ai_start = std::time::Instant::now();
                ai_phase.verify(&mut result.violations).await;
                let ai_ms = ai_start.elapsed().as_millis() as u64;
                phase_stats.push(PhaseStats {
                    name: "AI Verification".into(),
                    duration_ms: ai_ms,
                    violations_found: 0,
                    files_processed: 0,
                });
                dedup::recalculate_counts(&mut result);
            } else {
                tracing::info!(
                    "AI verification skipped (no API keys). \
                     Set OPENAI_API_KEY, GROQ_API_KEY, or SKERA_AI_KEY to enable."
                );
            }
        }

        // ── Step 10: Cross-module correlation ──
        tracing::info!("Correlation: cross-module analysis");
        correlation::correlate_violations(&mut result);

        // ── Step 11: Deduplication ──
        let pre_dedup_count = result.violations.len();
        dedup::deduplicate_violations(&mut result);
        let violations_deduplicated = pre_dedup_count - result.violations.len();
        if violations_deduplicated > 0 {
            tracing::info!(
                "Dedup: {} → {} ({} removed)",
                pre_dedup_count,
                result.violations.len(),
                violations_deduplicated
            );
        }

        // ── Step 12: Build evidence chains ──
        for violation in &result.violations {
            if violation.severity >= Severity::High && !violation.evidence.is_empty() {
                let chain = EvidenceChain::builder(format!(
                    "{:?}: {}",
                    violation.violation_type, violation.description
                ))
                .add_all(violation.evidence.clone())
                .finalize();
                evidence.add_chain(chain);
            }
        }
        evidence.finalize();

        // ── Step 13: Confidence/severity filtering ──
        let pre_filter_count = result.violations.len();
        result.violations.retain(|v| {
            v.confidence >= self.config.min_confidence
                && v.severity >= self.config.min_severity
        });
        let violations_filtered = pre_filter_count - result.violations.len();
        if violations_filtered > 0 {
            tracing::info!(
                "Filter: {} violations below confidence={:.2}/severity={:?}",
                violations_filtered,
                self.config.min_confidence,
                self.config.min_severity
            );
        }
        dedup::recalculate_counts(&mut result);

        // ── Step 14: Calculate risk score ──
        let risk_score = scoring::calculate_risk_score(&result, &self.config);
        let risk_level = scoring::risk_level_from_score(risk_score);

        // ── Step 14b: Check risk threshold ──
        let risk_threshold_exceeded = if let Some(ref pol) = policy {
            if pol.exceeds_risk_threshold(risk_score) {
                tracing::warn!(
                    "Policy: risk score {} exceeds threshold {} — scan FAILED",
                    risk_score,
                    pol.config().max_risk_score
                );
                true
            } else {
                false
            }
        } else {
            false
        };

        // ── Step 15: Save scan cache ──
        let cache_hit_rate = if let Some(ref mut c) = scan_cache {
            let rate = c.hit_rate();
            if let Err(e) = c.save() {
                tracing::warn!("Failed to save scan cache: {}", e);
            }
            Some(rate)
        } else {
            None
        };

        let total_ms = start.elapsed().as_millis() as u64;
        result.duration_ms = total_ms;

        tracing::info!(
            "═══════════════════════════════════════════════════════"
        );
        tracing::info!(
            "Scan complete: {} violations, risk={}/100 ({}), {}ms",
            result.violations.len(),
            risk_score,
            risk_level,
            total_ms
        );
        if total_deps > 0 || binaries_analyzed > 0 {
            tracing::info!(
                "  {} dependencies, {} binaries analyzed",
                total_deps, binaries_analyzed
            );
        }
        tracing::info!(
            "═══════════════════════════════════════════════════════"
        );

        Ok(ScanReport {
            target: target_str,
            project_license,
            detection_result: result,
            evidence,
            total_dependencies: total_deps,
            binaries_analyzed,
            risk_score,
            risk_level,
            duration_ms: total_ms,
            scanner_version: env!("CARGO_PKG_VERSION").to_string(),
            phase_stats,
            violations_filtered,
            violations_deduplicated,
            cache_hit_rate,
            policy_violations,
            risk_threshold_exceeded,
        })
    }
}

impl Default for SkeraEngine {
    fn default() -> Self {
        Self::new(SkeraConfig::default())
    }
}

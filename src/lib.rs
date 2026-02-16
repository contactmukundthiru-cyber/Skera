//! # skera — Universal Digital Copyright Forensics Engine
//!
//! Standalone copyright and license forensics scanner. Audits any digital asset
//! for violations of any copyrightable work — through obfuscation, concealment,
//! minification, bundling, and compilation.
//!
//! ## Architecture (v2 — Modular Pipeline)
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      SkeraEngine                            │
//! │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐   │
//! │  │FileIndex │ │Pipeline  │ │Policy    │ │ AI Verifier  │   │
//! │  │(1-pass)  │ │(parallel)│ │Engine    │ │ (optional)   │   │
//! │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └──────┬───────┘   │
//! │       │             │            │              │           │
//! │  ┌────▼─────────────▼────────────▼──────────────▼─────────┐ │
//! │  │  16 Independent Detection Phases (rayon parallel)      │ │
//! │  │  Header │ Deps │ Fingerprint │ JS │ Binary │ Supply... │ │
//! │  └────────────────────────┬───────────────────────────────┘ │
//! │                           │                                 │
//! │  ┌────────────────────────▼───────────────────────────────┐ │
//! │  │ Correlation → Dedup → Filter → Risk Score → Report    │ │
//! │  │             Evidence Collector (SHA-256 anchored)       │ │
//! │  └────────────────────────────────────────────────────────┘ │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Capabilities
//!
//! - **SPDX License Classification**: 500+ license types, compound SPDX expressions
//! - **License Compatibility Matrix**: Pairwise conflict detection across dependency DAGs
//! - **Source Code Scanning**: Header analysis, copyright blocks, attribution verification
//! - **Binary Forensics**: ELF/PE/Mach-O symbol analysis, GPL library signatures
//! - **Code Fingerprinting**: TLSH fuzzy hashing + AST structure matching
//! - **JS Bundle Analysis**: Library detection in minified/bundled/webpack output
//! - **Contamination Tracing**: Viral license propagation through transitive deps
//! - **Evidence Chain**: SHA-256 anchored evidence bundles for legal proceedings
//! - **AI Verification**: Multi-model consensus (optional, bring-your-own keys)
//! - **Policy Engine**: `.skera.toml` for allowed/blocked licenses and CI/CD gating
//! - **Incremental Cache**: Content-addressed caching for fast re-scans
//! - **Comparison Engine**: Two-target forensic diff for provenance analysis

pub mod license;
pub mod detection;
pub mod analysis;
pub mod evidence;
pub mod ai;
pub mod engine;
pub mod report;
pub mod audit;
pub mod ingest;
pub mod policy;

// Re-exports for convenience
pub use license::{LicenseId, LicenseFamily, LicenseObligation, LicenseDb};
pub use detection::{Violation, ViolationType, Severity, DetectionResult};
pub use analysis::{SourceScan, BinaryInspection, DependencyGraph};
pub use evidence::{EvidenceBundle, EvidenceItem, EvidenceChain};
pub use engine::{SkeraEngine, SkeraConfig, ScanTarget, ScanReport};
pub use report::{ReportFormat, write_report, render_report};
pub use policy::PolicyEngine;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SkeraError {
    #[error("License identification failed: {0}")]
    LicenseError(String),

    #[error("Detection error: {0}")]
    DetectionError(String),

    #[error("Analysis error: {0}")]
    AnalysisError(String),

    #[error("Evidence collection error: {0}")]
    EvidenceError(String),

    #[error("AI verification error: {0}")]
    AIError(String),

    #[error("Policy violation: {0}")]
    PolicyError(String),

    #[error("Cache error: {0}")]
    CacheError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerdeError(#[from] serde_json::Error),

    #[error("Comparison error: {0}")]
    ComparisonError(String),
}

pub type SkeraResult<T> = Result<T, SkeraError>;

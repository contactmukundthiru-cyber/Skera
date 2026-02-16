//! Phase 3b-iii: Cross-language provenance detection

use rayon::prelude::*;
use crate::detection::cross_language::ProvenanceDetector;
use crate::detection::{Violation, ViolationType, Severity};
use crate::engine::pipeline::{PhaseOutput, ScanContext, ScanPhase};
use crate::evidence::EvidenceItem;
use crate::SkeraResult;

pub struct CrossLanguagePhase;

impl CrossLanguagePhase {
    pub fn new() -> Self { Self }
}

impl ScanPhase for CrossLanguagePhase {
    fn name(&self) -> &str {
        "Cross-Language Provenance"
    }

    fn run(&self, ctx: &ScanContext) -> SkeraResult<PhaseOutput> {
        let candidates = ctx.file_index.provenance_candidates();

        let violations: Vec<Violation> = candidates
            .par_iter()
            .filter_map(|file| {
                let content = std::fs::read_to_string(&file.path).ok()?;
                let ext = file.path.extension()?.to_str()?;

                // ProvenanceDetector::analyze is an associated function, not a method
                let analysis = ProvenanceDetector::analyze(&content, ext);

                if analysis.evidence.is_empty() || analysis.port_confidence < ctx.config.min_confidence {
                    return None;
                }

                let source_lang = analysis.probable_source_language.as_deref().unwrap_or("unknown");
                
                Some(vec![Violation {
                    violation_type: ViolationType::CodeFingerprintMismatch,
                    severity: if analysis.port_confidence > 0.85 { Severity::High } else { Severity::Medium },
                    confidence: analysis.port_confidence,
                    description: format!(
                        "{} appears to be a port from {} ({:.0}% confidence)",
                        file.path.display(), source_lang, analysis.port_confidence * 100.0
                    ),
                    files: vec![file.path.clone()],
                    licenses: vec![],
                    obligations_violated: vec![],
                    evidence: vec![EvidenceItem::from_file(
                        &file.path, 0,
                        &format!("Cross-language: {} → {} ({} indicators)", 
                            source_lang, ext, analysis.evidence.len()),
                        "Algorithm-level structural match across languages",
                    )],
                    claimed_license: None,
                    actual_license: None,
                }])
            })
            .flatten()
            .collect();

        Ok(PhaseOutput::with_violations(violations, candidates.len()))
    }
}

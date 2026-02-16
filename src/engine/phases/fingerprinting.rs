//! Phase 3b: Code fingerprinting — snippet matching, structural fingerprinting
//!
//! Uses FileIndex to avoid redundant directory walks. Processes files via rayon.

use rayon::prelude::*;
use crate::detection::snippet_matcher::SnippetMatcher;
use crate::detection::structural_fingerprint;
use crate::detection::{Violation, ViolationType, Severity};
use crate::engine::pipeline::{PhaseOutput, ScanContext, ScanPhase};
use crate::evidence::EvidenceItem;
use crate::SkeraResult;

pub struct FingerprintingPhase {
    snippet_matcher: SnippetMatcher,
}

impl FingerprintingPhase {
    pub fn new() -> Self {
        Self {
            snippet_matcher: SnippetMatcher::new(),
        }
    }
}

impl ScanPhase for FingerprintingPhase {
    fn name(&self) -> &str {
        "Code Fingerprinting"
    }

    fn should_run(&self, config: &crate::engine::SkeraConfig) -> bool {
        config.fingerprinting
    }

    fn run(&self, ctx: &ScanContext) -> SkeraResult<PhaseOutput> {
        let candidates = ctx.file_index.fingerprintable();
        let files_processed = candidates.len();

        // Process fingerprinting in parallel with rayon
        let fp_violations: Vec<Violation> = candidates
            .par_iter()
            .filter_map(|file| {
                let content = std::fs::read_to_string(&file.path).ok()?;
                
                // Snippet fingerprinting
                let fp = self.snippet_matcher.fingerprint(&content, &file.path);
                let matches = self.snippet_matcher.find_matches(&fp);

                if matches.is_empty() {
                    return None;
                }

                // SnippetMatch fields: target_file, reference_file, reference_license,
                // reference_project, similarity, match_type, matched_chunks
                let violations: Vec<Violation> = matches
                    .into_iter()
                    .filter(|m| m.similarity >= ctx.config.min_confidence)
                    .map(|m| Violation {
                        violation_type: ViolationType::CodeFingerprintMismatch,
                        severity: if m.similarity > 0.90 { Severity::High } else { Severity::Medium },
                        confidence: m.similarity,
                        description: format!(
                            "Code in {} matches {} ({:.0}%, {:?})",
                            file.path.display(),
                            m.reference_project.as_deref().unwrap_or("known snippet"),
                            m.similarity * 100.0,
                            m.match_type
                        ),
                        files: vec![file.path.clone(), m.reference_file.clone()],
                        licenses: m.reference_license.clone().into_iter().collect(),
                        obligations_violated: vec![],
                        evidence: vec![EvidenceItem::from_file(
                            &file.path, 0,
                            &format!(
                                "Snippet match: {:?} ({:.0}%)",
                                m.match_type, m.similarity * 100.0
                            ),
                            format!(
                                "TLSH/fuzzy fingerprint match against {}",
                                m.reference_file.display()
                            ),
                        )],
                        claimed_license: None,
                        actual_license: m.reference_license.clone(),
                    })
                    .collect();

                if violations.is_empty() { None } else { Some(violations) }
            })
            .flatten()
            .collect();

        // Structural fingerprinting — uses different set of files
        let structural_candidates = ctx.file_index.provenance_candidates();
        let struct_violations: Vec<Violation> = structural_candidates
            .par_iter()
            .filter_map(|file| {
                let content = std::fs::read_to_string(&file.path).ok()?;
                let sfp = structural_fingerprint::extract_fingerprint(&content);

                if sfp.cfg_signature.len() < 10 {
                    return None;
                }

                // Build violations from structural patterns
                // StructuralFingerprint has `patterns: Vec<CodePattern>` (not `code_patterns`)
                let violations: Vec<Violation> = sfp.patterns.iter()
                    .filter(|p| p.confidence >= ctx.config.min_confidence)
                    .map(|p| Violation {
                        violation_type: ViolationType::CodeFingerprintMismatch,
                        severity: if p.confidence > 0.85 { Severity::High } else { Severity::Medium },
                        confidence: p.confidence,
                        description: format!(
                            "Structural fingerprint of {} matches pattern '{}' ({:.0}%)",
                            file.path.display(), p.description, p.confidence * 100.0
                        ),
                        files: vec![file.path.clone()],
                        licenses: vec![],
                        obligations_violated: vec![],
                        evidence: vec![EvidenceItem::from_file(
                            &file.path, 0,
                            &format!("CFG nodes={}, API calls={}", sfp.cfg_signature.len(), sfp.api_calls.len()),
                            "AST-level structural fingerprint analysis",
                        )],
                        claimed_license: None,
                        actual_license: None,
                    })
                    .collect();

                if violations.is_empty() { None } else { Some(violations) }
            })
            .flatten()
            .collect();

        let mut all_violations = fp_violations;
        all_violations.extend(struct_violations);

        Ok(PhaseOutput::with_violations(all_violations, files_processed + structural_candidates.len()))
    }
}

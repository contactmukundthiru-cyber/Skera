//! Phase 3b-vii: Advanced deobfuscation — control flow flattening,
//! opaque predicates, self-defending code neutralization
//!
//! This phase runs the advanced deobfuscation pipeline on large JS files
//! to reveal hidden library code that was deliberately obfuscated to evade
//! license compliance detection.

use crate::detection::advanced_deobfuscation::AdvancedDeobfuscator;
use crate::detection::{Violation, ViolationType, Severity};
use crate::engine::pipeline::{PhaseOutput, ScanContext, ScanPhase};
use crate::evidence::EvidenceItem;
use crate::SkeraResult;

pub struct DeobfuscationPhase;

impl DeobfuscationPhase {
    pub fn new() -> Self { Self }
}

impl ScanPhase for DeobfuscationPhase {
    fn name(&self) -> &str {
        "Advanced Deobfuscation"
    }

    fn run(&self, ctx: &ScanContext) -> SkeraResult<PhaseOutput> {
        // Target large JS files that are likely bundles (>10KB)
        let candidates = ctx.file_index.large_js(10_000);
        let mut violations = Vec::new();
        let mut files_processed = 0usize;

        for file in &candidates {
            let content = match std::fs::read_to_string(&file.path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let result = AdvancedDeobfuscator::deobfuscate(&content);
            files_processed += 1;

            let total_transforms = result.transformations.len();

            // Only report if significant obfuscation was detected
            if total_transforms < 3 {
                continue;
            }

            // Report self-defending code (most suspicious)
            if result.self_defending_traps_found > 0 {
                violations.push(Violation {
                    violation_type: ViolationType::ObfuscatedMatch,
                    severity: Severity::Critical,
                    confidence: 0.90,
                    description: format!(
                        "Self-defending obfuscation detected in {} — {} anti-tampering traps found. \
                         This is a strong indicator of deliberate license evasion.",
                        file.path.display(), result.self_defending_traps_found
                    ),
                    files: vec![file.path.clone()],
                    licenses: vec![],
                    obligations_violated: vec![],
                    evidence: vec![EvidenceItem::from_file(
                        &file.path, 0,
                        &format!(
                            "Deobfuscation: {} total transforms, {} self-defending traps, \
                             {} flattened blocks recovered",
                            total_transforms,
                            result.self_defending_traps_found,
                            result.flattened_blocks_recovered
                        ),
                        "Advanced deobfuscation revealed anti-analysis protections",
                    )],
                    claimed_license: None,
                    actual_license: None,
                });
            }

            // Report control flow flattening (strong obfuscation)
            if result.flattened_blocks_recovered > 0 {
                violations.push(Violation {
                    violation_type: ViolationType::ObfuscatedMatch,
                    severity: Severity::High,
                    confidence: 0.85,
                    description: format!(
                        "Control flow flattening detected in {} — {} switch-dispatch \
                         patterns reversed. Code was deliberately obfuscated.",
                        file.path.display(), result.flattened_blocks_recovered
                    ),
                    files: vec![file.path.clone()],
                    licenses: vec![],
                    obligations_violated: vec![],
                    evidence: vec![EvidenceItem::from_file(
                        &file.path, 0,
                        &format!(
                            "CFF reversal: {} blocks recovered, opaque predicates: {}, dead code: {} lines",
                            result.flattened_blocks_recovered,
                            result.opaque_predicates_eliminated,
                            result.dead_code_lines_removed
                        ),
                        "Control flow flattening is a strong obfuscation technique",
                    )],
                    claimed_license: None,
                    actual_license: None,
                });
            }
        }

        Ok(PhaseOutput::with_violations(violations, files_processed))
    }
}

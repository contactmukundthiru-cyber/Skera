//! ScanCode bridge phase — cross-validates with the ScanCode toolkit

use crate::detection::scancode_bridge::ScanCodeBridge;
use crate::detection::{Violation, ViolationType, Severity};
use crate::engine::pipeline::{PhaseOutput, ScanContext, ScanPhase};
use crate::evidence::EvidenceItem;
use crate::SkeraResult;
use std::path::PathBuf;

pub struct ScanCodePhase;

impl ScanCodePhase {
    pub fn new() -> Self { Self }
}

impl ScanPhase for ScanCodePhase {
    fn name(&self) -> &str {
        "ScanCode Cross-Validation"
    }

    fn should_run(&self, _config: &crate::engine::SkeraConfig) -> bool {
        // Only run if ScanCode is available on the system
        ScanCodeBridge::is_available()
    }

    fn run(&self, ctx: &ScanContext) -> SkeraResult<PhaseOutput> {
        let mut violations = Vec::new();

        match ScanCodeBridge::scan(&ctx.source_dir) {
            Ok(sc_result) => {
                let license_ids = ScanCodeBridge::to_license_ids(&sc_result);
                tracing::info!(
                    "  ScanCode: {} files, {} licenses detected",
                    sc_result.files.len(),
                    license_ids.len()
                );

                // Cross-validate with our detection
                for (file, license, score) in &license_ids {
                    if license != &ctx.project_license {
                        violations.push(Violation {
                            violation_type: ViolationType::ConflictingLicenseFiles,
                            severity: if *score > 0.90 {
                                Severity::High
                            } else {
                                Severity::Medium
                            },
                            confidence: *score as f64,
                            description: format!(
                                "ScanCode detected '{}' in {} but project declares '{}' (confidence: {:.0}%)",
                                license, file, ctx.project_license, score * 100.0
                            ),
                            files: vec![PathBuf::from(file)],
                            licenses: vec![license.clone(), ctx.project_license.clone()],
                            obligations_violated: vec![],
                            evidence: vec![EvidenceItem::from_file(
                                &PathBuf::from(file), 0,
                                &format!("ScanCode: {} (score: {:.2})", license, score),
                                format!("Cross-validated by ScanCode toolkit vs project license {}", ctx.project_license),
                            )],
                            claimed_license: Some(ctx.project_license.clone()),
                            actual_license: Some(license.clone()),
                        });
                    }
                }
            }
            Err(e) => tracing::warn!("ScanCode scan failed: {}", e),
        }

        Ok(PhaseOutput::with_violations(violations, 0))
    }
}

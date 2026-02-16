//! Phase 3e: Creative Commons compliance — CC-BY/NC/ND/SA detection

use crate::detection::creative_commons::{CcComplianceScanner, CcViolationType, CcViolationSeverity};
use crate::detection::{Violation, ViolationType, Severity};
use crate::engine::pipeline::{PhaseOutput, ScanContext, ScanPhase};
use crate::evidence::EvidenceItem;
use crate::SkeraResult;

pub struct CreativeCommonsPhase;

impl CreativeCommonsPhase {
    pub fn new() -> Self { Self }
}

impl ScanPhase for CreativeCommonsPhase {
    fn name(&self) -> &str {
        "Creative Commons Compliance"
    }

    fn run(&self, ctx: &ScanContext) -> SkeraResult<PhaseOutput> {
        let report = CcComplianceScanner::scan(&ctx.source_dir);
        let mut violations = Vec::new();

        for v in &report.violations {
            // Map CcViolationSeverity -> Severity
            let severity = match v.severity {
                CcViolationSeverity::Critical => Severity::Critical,
                CcViolationSeverity::Violation => Severity::High,
                CcViolationSeverity::Warning => Severity::Medium,
                CcViolationSeverity::Info => Severity::Low,
            };

            // Map CcViolationType -> ViolationType
            let vtype = match v.violation_type {
                CcViolationType::CommercialMisuse => ViolationType::CcNonCommercialViolation,
                CcViolationType::DerivativeViolation => ViolationType::CcNoDerivativesViolation,
                CcViolationType::ShareAlikeViolation => ViolationType::CcShareAlikeIncompatible,
                CcViolationType::MissingAttribution => ViolationType::CcMissingAttribution,
                CcViolationType::VersionIncompatible => ViolationType::IncompatibleLicenses,
                CcViolationType::Cc0Confusion => ViolationType::ManifestLicenseMismatch,
                CcViolationType::RetiredVersion => ViolationType::ManifestLicenseMismatch,
            };

            // Derive confidence from severity
            let confidence = match v.severity {
                CcViolationSeverity::Critical => 0.95,
                CcViolationSeverity::Violation => 0.85,
                CcViolationSeverity::Warning => 0.70,
                CcViolationSeverity::Info => 0.50,
            };

            violations.push(Violation {
                violation_type: vtype,
                severity,
                confidence,
                description: v.description.clone(),
                files: vec![v.content_path.clone()],
                licenses: vec![],
                obligations_violated: vec![],
                evidence: vec![EvidenceItem::from_file(
                    &v.content_path, 0,
                    &format!("CC license: {} ({:?})", v.license, v.violation_type),
                    &v.legal_reference,
                )],
                claimed_license: None,
                actual_license: None,
            });
        }

        Ok(PhaseOutput::with_violations(violations, report.cc_content.len()))
    }
}

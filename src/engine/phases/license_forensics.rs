//! Phase 3g: License text forensics — tampering, homoglyphs, chimera detection

use crate::detection::license_text_forensics;
use crate::detection::{Violation, ViolationType, Severity};
use crate::engine::pipeline::{PhaseOutput, ScanContext, ScanPhase};
use crate::evidence::EvidenceItem;
use crate::license::LicenseId;
use crate::SkeraResult;

pub struct LicenseForensicsPhase;

impl LicenseForensicsPhase {
    pub fn new() -> Self { Self }
}

impl ScanPhase for LicenseForensicsPhase {
    fn name(&self) -> &str {
        "License Text Forensics"
    }

    fn run(&self, ctx: &ScanContext) -> SkeraResult<PhaseOutput> {
        let reports = license_text_forensics::LicenseTextForensics::scan_directory(&ctx.source_dir);
        let mut violations = Vec::new();

        for report in &reports {
            // Homoglyph detection
            for anomaly in &report.unicode_anomalies {
                violations.push(Violation {
                    violation_type: ViolationType::HomoglyphTampering,
                    severity: Severity::Critical,
                    confidence: 0.95,
                    description: format!(
                        "Unicode {:?} detected in license at {}: {}",
                        anomaly.anomaly_type, report.file_path.display(), anomaly.description
                    ),
                    files: vec![report.file_path.clone()],
                    licenses: vec![],
                    obligations_violated: vec![],
                    evidence: vec![EvidenceItem::from_file(
                        &report.file_path, anomaly.position,
                        &anomaly.description,
                        "Unicode forensics — homoglyph/invisible character analysis",
                    )],
                    claimed_license: None,
                    actual_license: None,
                });
            }

            // Chimera licenses  
            if report.is_chimera {
                violations.push(Violation {
                    violation_type: ViolationType::ChimeraLicense,
                    severity: Severity::Critical,
                    confidence: 1.0 - report.trust_score,
                    description: format!(
                        "Chimera license detected in {}: {} forensic findings",
                        report.file_path.display(), report.findings.len()
                    ),
                    files: vec![report.file_path.clone()],
                    licenses: vec![],
                    obligations_violated: vec![],
                    evidence: vec![EvidenceItem::from_file(
                        &report.file_path, 0,
                        &format!("Trust score: {:.2}, findings: {}", report.trust_score, report.findings.len()),
                        "License text integrity analysis",
                    )],
                    claimed_license: report.declared_license.as_ref().map(|s| LicenseId::new(s)),
                    actual_license: report.detected_license.as_ref().map(|s| LicenseId::new(s)),
                });
            }

            // Custom additions / tampering
            for addition in &report.custom_additions {
                violations.push(Violation {
                    violation_type: ViolationType::LicenseTextTampering,
                    severity: Severity::High,
                    confidence: 0.85,
                    description: format!(
                        "Custom {:?} addition detected in license at {}",
                        addition.addition_type, report.file_path.display()
                    ),
                    files: vec![report.file_path.clone()],
                    licenses: vec![],
                    obligations_violated: vec![],
                    evidence: vec![],
                    claimed_license: None,
                    actual_license: None,
                });
            }
        }

        Ok(PhaseOutput::with_violations(violations, reports.len()))
    }
}

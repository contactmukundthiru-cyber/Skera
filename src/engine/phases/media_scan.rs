//! Phase 3b-iv: Media forensics — watermarks, DRM, duplicate media detection

use crate::detection::media_forensics;
use crate::detection::{Violation, ViolationType, Severity};
use crate::engine::pipeline::{PhaseOutput, ScanContext, ScanPhase};
use crate::evidence::EvidenceItem;
use crate::SkeraResult;

pub struct MediaScanPhase;

impl MediaScanPhase {
    pub fn new() -> Self { Self }
}

impl ScanPhase for MediaScanPhase {
    fn name(&self) -> &str {
        "Media Forensics"
    }

    fn run(&self, ctx: &ScanContext) -> SkeraResult<PhaseOutput> {
        let report = media_forensics::scan_media(&ctx.source_dir);
        let mut violations = Vec::new();

        // Convert stock indicators to violations  
        for fp in &report.fingerprints {
            for indicator in &fp.stock_indicators {
                violations.push(Violation {
                    violation_type: ViolationType::StockPhotoUsage,
                    severity: Severity::High,
                    confidence: 0.80,
                    description: format!(
                        "Stock media detected in {}: {} ({:?})",
                        fp.file_path.display(), indicator.provider, indicator.indicator_type
                    ),
                    files: vec![fp.file_path.clone()],
                    licenses: vec![],
                    obligations_violated: vec![],
                    evidence: vec![EvidenceItem::from_file(
                        &fp.file_path, 0,
                        &format!("Stock indicator: {} ({:?})", indicator.provider, indicator.indicator_type),
                        "Media fingerprint analysis detected stock asset signatures",
                    )],
                    claimed_license: None,
                    actual_license: None,
                });
            }
        }

        // Report duplicate groups
        for dup in &report.duplicates {
            if dup.files.len() > 1 {
                violations.push(Violation {
                    violation_type: ViolationType::Custom("Duplicate media assets".into()),
                    severity: Severity::Low,
                    confidence: 1.0,
                    description: format!(
                        "Duplicate media group: {} files with hash {}",
                        dup.files.len(), &dup.hash[..8.min(dup.hash.len())]
                    ),
                    files: dup.files.clone(),
                    licenses: vec![],
                    obligations_violated: vec![],
                    evidence: vec![],
                    claimed_license: None,
                    actual_license: None,
                });
            }
        }

        let files_processed = report.stats.total_files;
        Ok(PhaseOutput::with_violations(violations, files_processed))
    }
}

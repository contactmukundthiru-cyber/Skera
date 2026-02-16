//! Phase 2: Header analysis — SPDX headers, copyright blocks, manifest consistency

use crate::detection::header_detector::HeaderDetector;
use crate::engine::pipeline::{PhaseOutput, ScanContext, ScanPhase};
use crate::SkeraResult;

pub struct HeaderAnalysisPhase {
    detector: HeaderDetector,
}

impl HeaderAnalysisPhase {
    pub fn new() -> Self {
        Self {
            detector: HeaderDetector::new(),
        }
    }
}

impl ScanPhase for HeaderAnalysisPhase {
    fn name(&self) -> &str {
        "Header Analysis"
    }

    fn run(&self, ctx: &ScanContext) -> SkeraResult<PhaseOutput> {
        let mut violations = Vec::new();

        // Full header scan using the actual HeaderDetector API
        let scan_result = self.detector.full_scan(&ctx.source_dir, &ctx.project_license);
        violations.extend(scan_result.violations);

        // Also run tampering detection on discovered headers
        let tampering = self.detector.detect_tampering(&scan_result.headers, &ctx.project_license);
        violations.extend(tampering);

        // Filter by confidence threshold  
        violations.retain(|v| v.confidence >= ctx.config.min_confidence);

        let files_processed = scan_result.headers.len();
        Ok(PhaseOutput::with_violations(violations, files_processed))
    }
}

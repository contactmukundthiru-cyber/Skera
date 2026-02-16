//! Phase 3b-vi: YARA rule scanning

use crate::engine::pipeline::{PhaseOutput, ScanContext, ScanPhase};
use crate::SkeraResult;

pub struct YaraScanPhase;

impl YaraScanPhase {
    pub fn new() -> Self { Self }
}

impl ScanPhase for YaraScanPhase {
    fn name(&self) -> &str {
        "YARA Scanning"
    }

    fn should_run(&self, _config: &crate::engine::SkeraConfig) -> bool {
        #[cfg(feature = "yara")]
        { true }
        #[cfg(not(feature = "yara"))]
        { false }
    }

    fn run(&self, _ctx: &ScanContext) -> SkeraResult<PhaseOutput> {
        let violations = Vec::new();
        let files_processed = 0usize;

        #[cfg(feature = "yara")]
        {
            let scanner = crate::detection::yara_scanner::YaraScanner::new();
            for file in &ctx.file_index.files {
                files_processed += 1;
                if let Ok(data) = std::fs::read(&file.path) {
                    let matches = scanner.scan_bytes(&data, &file.path);
                    violations.extend(matches);
                }
            }
        }

        Ok(PhaseOutput::with_violations(violations, files_processed))
    }
}

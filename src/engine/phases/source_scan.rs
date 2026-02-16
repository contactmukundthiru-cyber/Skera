//! Phase 1: Source scanning — determines project license and scans source tree

use crate::analysis::source_scanner::SourceScanner;

/// Source scan phase — must run first to determine project license
pub struct SourceScanPhase {
    scanner: SourceScanner,
}

impl SourceScanPhase {
    pub fn new() -> Self {
        Self {
            scanner: SourceScanner::new(),
        }
    }

    /// Run source scan and return scan result + detected license
    pub fn run_initial(
        &self,
        dir: &std::path::Path,
    ) -> crate::analysis::source_scanner::SourceScan {
        self.scanner.scan(dir)
    }
}

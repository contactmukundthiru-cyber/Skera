//! Phase 4: Binary analysis — ELF/PE/Mach-O symbol analysis, GPL signatures

use crate::analysis::binary_inspector::BinaryInspector;
use crate::engine::pipeline::{PhaseOutput, ScanContext, ScanPhase};
use crate::engine::file_index::FileCategory;
use crate::SkeraResult;

pub struct BinaryAnalysisPhase {
    inspector: BinaryInspector,
}

impl BinaryAnalysisPhase {
    pub fn new() -> Self {
        Self {
            inspector: BinaryInspector::new(),
        }
    }
}

impl ScanPhase for BinaryAnalysisPhase {
    fn name(&self) -> &str {
        "Binary Analysis"
    }

    fn should_run(&self, config: &crate::engine::SkeraConfig) -> bool {
        config.binary_analysis
    }

    fn run(&self, ctx: &ScanContext) -> SkeraResult<PhaseOutput> {
        let binaries = ctx.file_index.category(FileCategory::BinaryExecutable);
        let mut all_violations = Vec::new();
        let mut binaries_analyzed = 0usize;

        for file in &binaries {
            if let Ok(inspection) = self.inspector.inspect(&file.path) {
                binaries_analyzed += 1;

                // Use BinaryInspector's built-in to_violations, which handles
                // GPL symbol detection, linking analysis, and license string matches
                let violations = self.inspector.to_violations(&inspection, &ctx.project_license);
                all_violations.extend(violations);
            }
        }

        let mut output = PhaseOutput::with_violations(all_violations, binaries.len());
        output.binaries_analyzed = binaries_analyzed;
        Ok(output)
    }
}

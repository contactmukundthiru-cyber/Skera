//! JSON report renderer

use crate::engine::ScanReport;
use crate::SkeraResult;

/// Render a scan report as pretty-printed JSON
pub fn render(report: &ScanReport) -> SkeraResult<String> {
    serde_json::to_string_pretty(report).map_err(crate::SkeraError::SerdeError)
}

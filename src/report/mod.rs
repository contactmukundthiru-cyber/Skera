//! Report generation — JSON, Markdown, and SARIF output
//!
//! Transforms a `ScanReport` into human-readable or machine-readable formats
//! suitable for CI/CD pipelines, legal review, and compliance dashboards.

pub mod json;
pub mod markdown;
pub mod sarif;
pub mod sbom;
pub mod comparison;

use crate::engine::ScanReport;
use crate::SkeraResult;
use std::path::Path;

/// Output format for the scan report
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    /// Structured JSON (machine-readable)
    Json,
    /// Human-readable Markdown with tables and summaries
    Markdown,
    /// OASIS SARIF v2.1 (for GitHub/GitLab code scanning integration)
    Sarif,
    /// CycloneDX SBOM (Software Bill of Materials)
    CycloneDxSbom,
    /// SPDX SBOM
    SpdxSbom,
}

/// Write a report in the specified format
pub fn write_report(
    report: &ScanReport,
    format: ReportFormat,
    output: &Path,
) -> SkeraResult<()> {
    let content = render_report(report, format)?;
    std::fs::write(output, content).map_err(crate::SkeraError::Io)?;
    Ok(())
}

/// Render a report to a string
pub fn render_report(
    report: &ScanReport,
    format: ReportFormat,
) -> SkeraResult<String> {
    match format {
        ReportFormat::Json => json::render(report),
        ReportFormat::Markdown => markdown::render(report),
        ReportFormat::Sarif => sarif::render(report),
        ReportFormat::CycloneDxSbom => sbom::render_cyclonedx(report),
        ReportFormat::SpdxSbom => sbom::render_spdx(report),
    }
}

//! Markdown report renderer
//!
//! Produces a litigation-ready Markdown document with executive summary,
//! violation tables, evidence chains, and risk assessment.

use crate::detection::Severity;
use crate::engine::{RiskLevel, ScanReport};
use crate::SkeraResult;

/// Render a scan report as Markdown
pub fn render(report: &ScanReport) -> SkeraResult<String> {
    let mut md = String::with_capacity(8192);

    // Title
    md.push_str("# Skera Copyright Forensics Report\n\n");

    // Metadata
    md.push_str("| Field | Value |\n|---|---|\n");
    md.push_str(&format!(
        "| **Target** | `{}` |\n",
        truncate(&report.target, 80)
    ));
    md.push_str(&format!(
        "| **Project License** | {} |\n",
        report
            .project_license
            .as_ref()
            .map(|l| l.to_string())
            .unwrap_or_else(|| "Not detected".to_string())
    ));
    md.push_str(&format!(
        "| **Risk Score** | **{}** / 100 |\n",
        report.risk_score
    ));
    md.push_str(&format!(
        "| **Risk Level** | {} |\n",
        risk_badge(report.risk_level)
    ));
    md.push_str(&format!(
        "| **Files Scanned** | {} |\n",
        report.detection_result.files_scanned
    ));
    md.push_str(&format!(
        "| **Dependencies Analyzed** | {} |\n",
        report.total_dependencies
    ));
    md.push_str(&format!(
        "| **Binaries Analyzed** | {} |\n",
        report.binaries_analyzed
    ));
    md.push_str(&format!(
        "| **Scan Duration** | {}ms |\n",
        report.duration_ms
    ));
    md.push_str(&format!(
        "| **Scanner Version** | {} |\n",
        report.scanner_version
    ));
    if let Some(rate) = report.cache_hit_rate {
        md.push_str(&format!(
            "| **Cache Hit Rate** | {:.1}% |\n",
            rate * 100.0
        ));
    }
    if report.risk_threshold_exceeded {
        md.push_str("| **Policy Status** | ❌ **THRESHOLD EXCEEDED** |\n");
    }
    md.push_str("\n");

    // Executive summary
    let dr = &report.detection_result;
    md.push_str("## Executive Summary\n\n");
    if dr.total_violations == 0 {
        md.push_str("✅ **No license violations detected.** The project appears to be in compliance.\n\n");
    } else {
        md.push_str(&format!(
            "⚠️ **{} license violation(s) detected** across {} scanned files.\n\n",
            dr.total_violations, dr.files_scanned
        ));
        md.push_str("| Severity | Count |\n|---|---:|\n");
        if dr.critical_count > 0 {
            md.push_str(&format!(
                "| 🔴 Critical | **{}** |\n",
                dr.critical_count
            ));
        }
        if dr.high_count > 0 {
            md.push_str(&format!("| 🟠 High | **{}** |\n", dr.high_count));
        }
        if dr.medium_count > 0 {
            md.push_str(&format!("| 🟡 Medium | {} |\n", dr.medium_count));
        }
        if dr.low_count > 0 {
            md.push_str(&format!("| 🔵 Low | {} |\n", dr.low_count));
        }
        md.push_str("\n");
    }

    // Violations table
    if !dr.violations.is_empty() {
        md.push_str("## Violations\n\n");
        md.push_str("| # | Severity | Type | Confidence | Description |\n");
        md.push_str("|--:|----------|------|----------:|-------------|\n");

        for (i, v) in dr.violations.iter().enumerate() {
            md.push_str(&format!(
                "| {} | {} | `{:?}` | {:.0}% | {} |\n",
                i + 1,
                severity_icon(v.severity),
                v.violation_type,
                v.confidence * 100.0,
                truncate(&v.description, 120),
            ));
        }
        md.push_str("\n");
    }

    // Detailed violations
    let critical_and_high: Vec<_> = dr
        .violations
        .iter()
        .filter(|v| v.severity >= Severity::High)
        .collect();

    if !critical_and_high.is_empty() {
        md.push_str("## Critical & High Findings (Detail)\n\n");
        for (i, v) in critical_and_high.iter().enumerate() {
            md.push_str(&format!(
                "### {}. {} `{:?}`\n\n",
                i + 1,
                severity_icon(v.severity),
                v.violation_type
            ));
            md.push_str(&format!("**Description:** {}\n\n", v.description));
            md.push_str(&format!("**Confidence:** {:.1}%\n\n", v.confidence * 100.0));

            if let (Some(claimed), Some(actual)) = (&v.claimed_license, &v.actual_license) {
                md.push_str(&format!(
                    "**Claimed License:** {} → **Actual License:** {}\n\n",
                    claimed, actual
                ));
            }

            if !v.files.is_empty() {
                md.push_str("**Files:**\n");
                for f in &v.files {
                    md.push_str(&format!("- `{}`\n", f.display()));
                }
                md.push_str("\n");
            }

            if !v.evidence.is_empty() {
                md.push_str("**Evidence:**\n");
                for ev in &v.evidence {
                    md.push_str(&format!("- {}", ev.description));
                    if let Some(ref path) = ev.file_path {
                        md.push_str(&format!(" (`{}`", path.display()));
                        if let Some(line) = ev.line_number {
                            md.push_str(&format!(":L{}", line));
                        }
                        md.push_str(")");
                    }
                    md.push_str("\n");
                    if let Some(ref excerpt) = ev.content_excerpt {
                        md.push_str(&format!(
                            "  ```\n  {}\n  ```\n",
                            truncate(excerpt, 300)
                        ));
                    }
                }
                md.push_str("\n");
            }

            md.push_str("---\n\n");
        }
    }

    // Evidence bundle info
    md.push_str("## Evidence Bundle\n\n");
    md.push_str(&format!(
        "- **Bundle ID:** `{}`\n",
        report.evidence.id
    ));
    md.push_str(&format!(
        "- **Bundle Hash:** `{}`\n",
        truncate(&report.evidence.bundle_hash, 16)
    ));
    md.push_str(&format!(
        "- **Total Evidence Items:** {}\n",
        report.evidence.total_items()
    ));
    md.push_str(&format!(
        "- **Evidence Chains:** {}\n\n",
        report.evidence.chains.len()
    ));

    // Phase timing breakdown
    if !report.phase_stats.is_empty() {
        md.push_str("## Phase Timing Breakdown\n\n");
        md.push_str("| Phase | Duration | Files | Violations |\n");
        md.push_str("|-------|-------:|------:|-----------:|\n");
        for ps in &report.phase_stats {
            md.push_str(&format!(
                "| {} | {}ms | {} | {} |\n",
                ps.name, ps.duration_ms, ps.files_processed, ps.violations_found
            ));
        }
        let total_phase_ms: u64 = report.phase_stats.iter().map(|p| p.duration_ms).sum();
        md.push_str(&format!(
            "| **Total** | **{}ms** | | |\n\n",
            total_phase_ms
        ));
    }

    // Dependency licenses
    if !report.detection_result.dependency_licenses.is_empty() {
        md.push_str("## Dependency Licenses\n\n");
        md.push_str("| Dependency | License |\n");
        md.push_str("|------------|---------|\n");
        for (name, license) in &report.detection_result.dependency_licenses {
            md.push_str(&format!("| `{}` | {} |\n", name, license));
        }
        md.push_str("\n");
    }

    // Footer
    md.push_str("---\n\n");
    md.push_str(&format!(
        "*Generated by Skera v{} — Santh Sentinel License Forensics Engine*\n",
        report.scanner_version
    ));

    Ok(md)
}

fn severity_icon(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "🔴 Critical",
        Severity::High => "🟠 High",
        Severity::Medium => "🟡 Medium",
        Severity::Low => "🔵 Low",
    }
}

fn risk_badge(r: RiskLevel) -> &'static str {
    match r {
        RiskLevel::Clean => "✅ Clean",
        RiskLevel::Low => "🟢 Low",
        RiskLevel::Medium => "🟡 Medium",
        RiskLevel::High => "🟠 High",
        RiskLevel::Critical => "🔴 Critical",
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

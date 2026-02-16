//! Comparison report rendering — Markdown and JSON output for `skera compare`
//!
//! Renders a `ComparisonReport` into human-readable or machine-readable formats
//! suitable for legal review, IP audits, and M&A due diligence.

use crate::engine::comparison::{ComparisonReport, ComparisonVerdict, MatchType};
use crate::SkeraResult;

/// Render comparison report as structured JSON
pub fn render_json(report: &ComparisonReport) -> SkeraResult<String> {
    serde_json::to_string_pretty(report).map_err(|e| {
        crate::SkeraError::AnalysisError(format!("JSON serialization failed: {}", e))
    })
}

/// Render comparison report as Markdown for legal/human review
pub fn render_markdown(report: &ComparisonReport) -> SkeraResult<String> {
    let mut md = String::with_capacity(8192);

    // ── Header ──
    md.push_str("# Skera Forensic Comparison Report\n\n");
    md.push_str("| | |\n|---|---|\n");
    md.push_str(&format!("| **Original** | `{}` |\n", report.original));
    md.push_str(&format!("| **Suspect** | `{}` |\n", report.suspect));
    md.push_str(&format!(
        "| **Overall Similarity** | **{:.1}%** |\n",
        report.overall_similarity * 100.0
    ));
    md.push_str(&format!("| **Verdict** | {} |\n\n", verdict_badge(&report.verdict)));

    // ── Verdict summary ──
    md.push_str("## Verdict\n\n");
    match &report.verdict {
        ComparisonVerdict::DefiniteInfringement => {
            md.push_str(
                "> ❌ **DEFINITE INFRINGEMENT** — Clear code theft with stripped attribution detected. \
                 This evidence is suitable for DMCA takedown or litigation.\n\n",
            );
        }
        ComparisonVerdict::LikelyInfringement => {
            md.push_str(
                "> ⚠️ **LIKELY INFRINGEMENT** — Significant overlap with license violations. \
                 Legal review is strongly recommended.\n\n",
            );
        }
        ComparisonVerdict::Suspicious => {
            md.push_str(
                "> 🔍 **SUSPICIOUS** — Notable code overlap detected. Further investigation required \
                 to determine if this is coincidental or derived.\n\n",
            );
        }
        ComparisonVerdict::LowRisk => {
            md.push_str(
                "> ✅ **LOW RISK** — Minor overlap detected, likely coincidental (common patterns, \
                 shared dependencies).\n\n",
            );
        }
        ComparisonVerdict::Clean => {
            md.push_str(
                "> ✅ **CLEAN** — No significant code overlap detected between the two codebases.\n\n",
            );
        }
    }

    // ── Exact/Fuzzy matches ──
    if !report.matches.is_empty() {
        md.push_str("## Code Matches\n\n");
        md.push_str("| Original File | Suspect File | Similarity | Match Type | License |\n");
        md.push_str("|---|---|---|---|---|\n");
        for m in &report.matches {
            let license = m
                .original_license
                .as_ref()
                .map(|l| l.as_str().to_string())
                .unwrap_or_else(|| "—".into());
            md.push_str(&format!(
                "| `{}` | `{}` | {:.0}% | {} | {} |\n",
                m.original_file.display(),
                m.suspect_file.display(),
                m.similarity * 100.0,
                m.match_type,
                license,
            ));
        }
        md.push('\n');
    }

    // ── Stripped headers ──
    if !report.stripped_headers.is_empty() {
        md.push_str("## Stripped License Headers\n\n");
        md.push_str(
            "These files have matching code but the license header present in the original \
             was removed in the suspect codebase:\n\n",
        );
        md.push_str("| Original File | Suspect File | Stripped Header |\n");
        md.push_str("|---|---|---|\n");
        for sh in &report.stripped_headers {
            let header_preview = sh.original_header.lines().next().unwrap_or("(empty)");
            md.push_str(&format!(
                "| `{}` | `{}` | `{}` |\n",
                sh.original_file.display(),
                sh.suspect_file.display(),
                header_preview,
            ));
        }
        md.push('\n');
    }

    // ── Structural matches ──
    if !report.structural_matches.is_empty() {
        md.push_str("## Structural Matches (AST-Level)\n\n");
        md.push_str("| Original File | Suspect File | CFG Sim | API Overlap | K-gram Sim |\n");
        md.push_str("|---|---|---|---|---|\n");
        for sm in &report.structural_matches {
            md.push_str(&format!(
                "| `{}` | `{}` | {:.0}% | {:.0}% | {:.0}% |\n",
                sm.original_file.display(),
                sm.suspect_file.display(),
                sm.cfg_similarity * 100.0,
                sm.api_overlap * 100.0,
                sm.kgram_similarity * 100.0,
            ));
        }
        md.push('\n');
    }

    // ── Summary statistics ──
    md.push_str("## Summary\n\n");
    let exact = report
        .matches
        .iter()
        .filter(|m| matches!(m.match_type, MatchType::ExactHash))
        .count();
    let fuzzy = report
        .matches
        .iter()
        .filter(|m| matches!(m.match_type, MatchType::FuzzyHash))
        .count();
    let snippet = report
        .matches
        .iter()
        .filter(|m| matches!(m.match_type, MatchType::SnippetMatch))
        .count();
    md.push_str(&format!("- **Exact hash matches**: {}\n", exact));
    md.push_str(&format!("- **Fuzzy hash matches**: {}\n", fuzzy));
    md.push_str(&format!("- **Snippet matches**: {}\n", snippet));
    md.push_str(&format!(
        "- **Structural matches**: {}\n",
        report.structural_matches.len()
    ));
    md.push_str(&format!(
        "- **Stripped headers**: {}\n",
        report.stripped_headers.len()
    ));

    md.push_str("\n---\n*Generated by Skera — Litigation-Grade License Forensics*\n");

    Ok(md)
}

fn verdict_badge(verdict: &ComparisonVerdict) -> String {
    match verdict {
        ComparisonVerdict::DefiniteInfringement => "❌ Definite Infringement".into(),
        ComparisonVerdict::LikelyInfringement => "⚠️ Likely Infringement".into(),
        ComparisonVerdict::Suspicious => "🔍 Suspicious".into(),
        ComparisonVerdict::LowRisk => "✅ Low Risk".into(),
        ComparisonVerdict::Clean => "✅ Clean".into(),
    }
}

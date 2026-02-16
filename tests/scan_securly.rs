//! Integration test: Run JS bundle forensics scanner against the Securly extension
//!
//! This test scans the unpacked Securly extension and outputs a forensic report.
//! It serves both as a test and as evidence generation for the paper.

use skera::detection::js_bundle_forensics::JsBundleScanner;
use std::path::Path;

#[test]
fn scan_securly_extension() {
    let unpacked_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("securly_test")
        .join("unpacked");

    if !unpacked_dir.exists() {
        eprintln!(
            "SKIP: Securly extension not found at {}",
            unpacked_dir.display()
        );
        return;
    }

    let scanner = JsBundleScanner::new();
    let reports = scanner
        .analyze_directory(&unpacked_dir)
        .expect("Failed to scan directory");

    println!("\n{}", "=".repeat(80));
    println!("SECURLY CHROME EXTENSION — FORENSIC SCAN REPORT");
    println!("{}\n", "=".repeat(80));

    let mut total_violations = 0;
    let mut total_libraries = 0;
    let mut all_reports_md = String::new();

    for report in &reports {
        if report.detected_libraries.is_empty() && report.copyright_claims.is_empty() {
            continue; // Skip boring files
        }

        println!(
            "─── {} ({} bytes) ───",
            report.file_path.file_name().unwrap().to_string_lossy(),
            report.file_size
        );
        println!("  SHA-256: {}", &report.file_sha256[..16]);
        println!("  Integrity: {:?}", report.integrity_assessment);
        println!(
            "  Composition: {:.1}% third-party, {:.1}% original",
            report.third_party_percentage, report.original_percentage
        );

        if !report.copyright_claims.is_empty() {
            println!("  Copyright claims:");
            for claim in &report.copyright_claims {
                println!(
                    "    Line {}: '{}' {}",
                    claim.line_number,
                    claim.holder,
                    if claim.all_rights_reserved {
                        "[ALL RIGHTS RESERVED]"
                    } else {
                        ""
                    }
                );
            }
        }

        if !report.detected_libraries.is_empty() {
            println!("  Detected libraries:");
            for lib in &report.detected_libraries {
                println!(
                    "    📦 {} {} ({}) — {:.0}% confidence, {:.1}% of file",
                    lib.name,
                    lib.version.as_deref().unwrap_or(""),
                    lib.true_license,
                    lib.confidence * 100.0,
                    lib.percentage_of_bundle
                );
                println!(
                    "       Copyright preserved: {} | Attribution file: {}",
                    if lib.copyright_preserved { "✅" } else { "❌ STRIPPED" },
                    if lib.attribution_file_present { "✅" } else { "❌ MISSING" }
                );
                if let Some(ref r) = lib.commercial_restriction {
                    println!("       ⚠️  COMMERCIAL RESTRICTION: {}", r);
                }
                for fp in &lib.matched_fingerprints {
                    let loc = fp
                        .line_number
                        .map(|l| format!("line {}", l))
                        .unwrap_or_else(|| format!("byte {}", fp.byte_offset));
                    println!("       → {} at {} ({:.0}%)", fp.description, loc, fp.confidence * 100.0);
                }
            }
        }

        if !report.violations.is_empty() {
            println!("  🚨 VIOLATIONS:");
            for v in &report.violations {
                println!("    [{:?}] {:?}: {}", v.severity, v.violation_type, v.description);
            }
        }

        total_violations += report.violations.len();
        total_libraries += report.detected_libraries.len();
        all_reports_md.push_str(&report.to_markdown());
        all_reports_md.push_str("\n---\n\n");
        println!();
    }

    println!("\n{}", "=".repeat(80));
    println!("SUMMARY");
    println!("{}", "=".repeat(80));
    println!("Files scanned: {}", reports.len());
    println!("Third-party libraries detected: {}", total_libraries);
    println!("Total violations: {}", total_violations);
    println!();

    // Write markdown report to file
    let report_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("SCANNER_FORENSIC_REPORT.md");

    let report_header = format!(
        "# Securly Extension — Automated Forensic Scan Report\n\n\
         **Scanner**: Skera JS Bundle Forensics v{}\n\
         **Date**: {}\n\
         **Target**: Securly for Chromebooks v3.0.7\n\
         **Files scanned**: {}\n\
         **Libraries detected**: {}\n\
         **Violations found**: {}\n\n---\n\n",
        env!("CARGO_PKG_VERSION"),
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
        reports.len(),
        total_libraries,
        total_violations,
    );

    let final_report = format!("{}{}", report_header, all_reports_md);
    std::fs::write(&report_path, &final_report).expect("Failed to write report");
    println!("📄 Full report written to: {}", report_path.display());

    // The test should flag if we found violations
    assert!(total_violations > 0, "Expected to find violations in Securly extension");
    assert!(total_libraries > 0, "Expected to detect third-party libraries");
}

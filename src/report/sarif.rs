//! SARIF v2.1 report renderer
//!
//! Produces OASIS SARIF (Static Analysis Results Interchange Format) output
//! compatible with GitHub Code Scanning, GitLab SAST, and Azure DevOps.
//! https://sarifweb.azurewebsites.net/

use crate::detection::Severity;
use crate::engine::ScanReport;
use crate::SkeraResult;
use serde_json::{json, Value};

/// Render a scan report in SARIF v2.1 format
pub fn render(report: &ScanReport) -> SkeraResult<String> {
    let rules: Vec<Value> = report
        .detection_result
        .violations
        .iter()
        .map(|v| {
            json!({
                "id": format!("skera/{:?}", v.violation_type),
                "shortDescription": {
                    "text": format!("{:?}", v.violation_type)
                },
                "fullDescription": {
                    "text": &v.description
                },
                "helpUri": "https://santh.io/sentinel/docs/rules",
                "defaultConfiguration": {
                    "level": severity_to_sarif(v.severity)
                }
            })
        })
        .collect();

    // Deduplicate rules by ID
    let mut seen_rules = std::collections::HashSet::new();
    let unique_rules: Vec<Value> = rules
        .into_iter()
        .filter(|r| {
            let id = r["id"].as_str().unwrap_or("").to_string();
            seen_rules.insert(id)
        })
        .collect();

    let results: Vec<Value> = report
        .detection_result
        .violations
        .iter()
        .map(|v| {
            let mut result = json!({
                "ruleId": format!("skera/{:?}", v.violation_type),
                "level": severity_to_sarif(v.severity),
                "message": {
                    "text": v.description
                },
                "properties": {
                    "confidence": v.confidence,
                }
            });

            // Add file location if available
            if let Some(first_file) = v.files.first() {
                result["locations"] = json!([{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": first_file.display().to_string().replace('\\', "/")
                        }
                    }
                }]);
            }

            // Add related locations for multi-file violations
            if v.files.len() > 1 {
                let related: Vec<serde_json::Value> = v.files[1..].iter().enumerate().map(|(i, f)| {
                    json!({
                        "id": i,
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.display().to_string().replace('\\', "/")
                            }
                        },
                        "message": {
                            "text": "Related file"
                        }
                    })
                }).collect();
                result["relatedLocations"] = json!(related);
            }

            result
        })
        .collect();

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Skera",
                    "organization": "Santh",
                    "version": report.scanner_version,
                    "semanticVersion": report.scanner_version,
                    "informationUri": "https://santh.io/sentinel",
                    "rules": unique_rules
                }
            },
            "results": results,
            "properties": {
                "riskScore": report.risk_score,
                "riskLevel": format!("{:?}", report.risk_level),
                "filesScanned": report.detection_result.files_scanned,
                "dependenciesAnalyzed": report.total_dependencies,
                "durationMs": report.duration_ms,
                "riskThresholdExceeded": report.risk_threshold_exceeded,
            }
        }]
    });

    serde_json::to_string_pretty(&sarif).map_err(crate::SkeraError::SerdeError)
}

fn severity_to_sarif(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

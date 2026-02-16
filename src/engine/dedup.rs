//! Violation deduplication
//!
//! Merges violations on the same file+type, keeping the highest severity
//! and merging evidence chains.

use crate::detection::{DetectionResult, Severity};
use std::collections::HashMap;

/// Deduplicate violations by (file, violation_type), merging evidence
pub fn deduplicate_violations(result: &mut DetectionResult) {
    // Group by (file_path, violation_type)
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, v) in result.violations.iter().enumerate() {
        let file_key = v
            .files
            .first()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();
        let key = format!("{}|{:?}", file_key, v.violation_type);
        groups.entry(key).or_default().push(i);
    }

    let mut to_remove: Vec<usize> = Vec::new();
    for indices in groups.values() {
        if indices.len() <= 1 {
            continue;
        }

        // Keep the first, merge the rest into it
        let keep = indices[0];
        for &remove_idx in &indices[1..] {
            to_remove.push(remove_idx);

            let dup_evidence = result.violations[remove_idx].evidence.clone();
            let dup_confidence = result.violations[remove_idx].confidence;
            let dup_severity = result.violations[remove_idx].severity.clone();

            if let Some(kept) = result.violations.get_mut(keep) {
                kept.evidence.extend(dup_evidence);
                kept.confidence = kept.confidence.max(dup_confidence);
                if dup_severity > kept.severity {
                    kept.severity = dup_severity;
                }
            }
        }
    }

    // Remove duplicates in reverse order to preserve indices
    to_remove.sort_unstable();
    to_remove.dedup();
    for idx in to_remove.into_iter().rev() {
        result.violations.remove(idx);
    }

    // Recalculate counts
    recalculate_counts(result);
}

/// Recalculate severity counts after any mutation
pub fn recalculate_counts(result: &mut DetectionResult) {
    result.total_violations = result.violations.len();
    result.critical_count = result
        .violations
        .iter()
        .filter(|v| v.severity == Severity::Critical)
        .count();
    result.high_count = result
        .violations
        .iter()
        .filter(|v| v.severity == Severity::High)
        .count();
    result.medium_count = result
        .violations
        .iter()
        .filter(|v| v.severity == Severity::Medium)
        .count();
    result.low_count = result
        .violations
        .iter()
        .filter(|v| v.severity == Severity::Low)
        .count();
}

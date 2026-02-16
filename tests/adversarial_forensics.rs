//! Adversarial forensics test suite
//!
//! Tests the detection pipeline against the most sophisticated evasion
//! techniques: homoglyph attacks, RTL overrides, chimera licenses,
//! clause stripping, context confusion, and advanced obfuscation.
//!
//! These are the exact techniques a sophisticated license launderer
//! or IP thief would use. If Skera passes all of these, it is hardened
//! against real-world attack vectors.

use skera::detection::license_text_forensics::{
    FindingCategory, LicenseTextForensics,
};
use skera::detection::{DetectionResult, Severity, Violation, ViolationType};
use skera::engine::correlation::correlate_violations;
use skera::detection::advanced_deobfuscation::AdvancedDeobfuscator;
use std::path::{Path, PathBuf};

// ─── Helper ─────────────────────────────────────────────────────────

fn make_violation(
    vtype: ViolationType,
    file: &str,
    severity: Severity,
    confidence: f64,
) -> Violation {
    Violation {
        violation_type: vtype,
        severity,
        confidence,
        description: "adversarial test".to_string(),
        files: vec![PathBuf::from(file)],
        licenses: vec![],
        obligations_violated: vec![],
        evidence: vec![],
        claimed_license: None,
        actual_license: None,
    }
}

fn make_result(violations: Vec<Violation>) -> DetectionResult {
    let mut r = DetectionResult::default();
    r.violations = violations;
    r
}

// ═══════════════════════════════════════════════════════════════════
// Section 1: Unicode and Encoding Attacks
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_cyrillic_homoglyph_in_key_word() {
    // Replace 'a' in "granted" with Cyrillic 'а' (U+0430)
    // A human cannot see this difference, but it changes the legal text
    let poisoned = "Permission is hereby gr\u{0430}nted, free of charge";
    let anomalies = LicenseTextForensics::detect_unicode_anomalies(poisoned);
    assert!(
        !anomalies.is_empty(),
        "Must detect Cyrillic 'а' substituted for Latin 'a'"
    );
    assert!(anomalies.iter().any(|a| a.description.contains("Cyrillic")));
}

#[test]
fn test_multiple_homoglyphs_scattered() {
    // Scatter multiple Cyrillic homoglyphs across the text
    // 'е' (U+0435) for 'e', 'о' (U+043E) for 'o', 'р' (U+0440) for 'p'
    let poisoned = "P\u{0435}rmission is h\u{0435}r\u{0435}by grant\u{0435}d, fr\u{0435}\u{0435} \u{043E}f charg\u{0435}";
    let anomalies = LicenseTextForensics::detect_unicode_anomalies(poisoned);
    assert!(
        anomalies.len() >= 5,
        "Must detect all scattered homoglyphs, found {}",
        anomalies.len()
    );
}

#[test]
fn test_greek_homoglyphs() {
    // Greek ν (nu, U+03BD) for Latin 'v'
    let poisoned = "Pro\u{03BD}ided \"AS IS\", without warranty";
    let anomalies = LicenseTextForensics::detect_unicode_anomalies(poisoned);
    assert!(
        !anomalies.is_empty(),
        "Must detect Greek ν substituted for Latin v"
    );
}

#[test]
fn test_zero_width_characters_hiding_text() {
    // Inject zero-width spaces to break machine-readable license detection
    // "MIT" becomes "M\u{200B}I\u{200B}T" — invisible to humans
    let poisoned = "M\u{200B}I\u{200B}T License\n\nPermission is hereby granted";
    let anomalies = LicenseTextForensics::detect_unicode_anomalies(poisoned);
    assert!(
        anomalies.len() >= 2,
        "Must detect zero-width space injections"
    );
}

#[test]
fn test_zero_width_joiner_in_clause() {
    // Zero-width joiner (U+200D) injected inside critical clause text
    // This could cause regex-based clause matching to fail
    let poisoned = "The above copyright\u{200D} notice and this permission\u{200D} notice \
                    shall be included in all copies";
    let anomalies = LicenseTextForensics::detect_unicode_anomalies(poisoned);
    assert!(
        !anomalies.is_empty(),
        "Must detect zero-width joiners breaking clause continuity"
    );
}

#[test]
fn test_bidi_override_hiding_clause() {
    // Right-to-left override (U+202E) can make text appear reversed
    // An attacker could use this to hide a restrictive clause
    let poisoned = "MIT License\n\n\u{202E}ylno esu laicremmoC\u{202C}\nPermission is hereby granted";
    let anomalies = LicenseTextForensics::detect_unicode_anomalies(poisoned);
    assert!(
        anomalies.iter().any(|a| a.description.contains("Bidirectional")),
        "Must detect RTL override characters"
    );
}

#[test]
fn test_bom_at_start_of_license() {
    // BOM (U+FEFF) at start of file — sometimes used to confuse parsers
    let poisoned = "\u{FEFF}MIT License\n\nPermission is hereby granted";
    let anomalies = LicenseTextForensics::detect_unicode_anomalies(poisoned);
    assert!(
        anomalies.iter().any(|a| a.character.contains("FEFF")),
        "Must detect BOM character"
    );
}

#[test]
fn test_non_breaking_space_substitution() {
    // Non-breaking space (U+00A0) instead of regular space
    // This breaks string matching for clause detection
    let poisoned = "Permission\u{00A0}is\u{00A0}hereby\u{00A0}granted";
    let anomalies = LicenseTextForensics::detect_unicode_anomalies(poisoned);
    assert!(
        anomalies.len() >= 3,
        "Must detect non-breaking space substitutions"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Section 2: Clause Stripping and Tampering
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_mit_with_attribution_stripped() {
    // MIT license with the attribution clause surgically removed
    let stripped_mit = r#"MIT License

Copyright (c) 2024 Acme Corp

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND."#;

    let report = LicenseTextForensics::analyze(stripped_mit, Path::new("LICENSE"), Some("MIT"));
    assert!(
        !report.clause_analysis.missing_clauses.is_empty(),
        "Must detect missing attribution clause"
    );
    assert!(
        report.trust_score < 0.95,
        "Trust score must be reduced for stripped clause, got {}",
        report.trust_score
    );
}

#[test]
fn test_gpl_with_source_disclosure_stripped() {
    // GPL-3.0 text with the Corresponding Source clause removed
    // This is the most dangerous form of GPL laundering
    let stripped_gpl = r#"GNU GENERAL PUBLIC LICENSE
Version 3, 29 June 2007

Everyone is permitted to copy and distribute verbatim copies
of this license document, but changing it is not allowed.

The licenses for most software and other practical works are designed
to take away your freedom to share and change the works.  By contrast,
the GNU General Public License is intended to guarantee your freedom
to run the program as you wish, for any purpose.

You may convey a work based on the Program, or the modifications to
produce it from the Program.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY."#;

    let report = LicenseTextForensics::analyze(stripped_gpl, Path::new("COPYING"), Some("GPL-3.0"));
    // Should detect missing "Corresponding Source" clause
    assert!(
        report.clause_analysis.missing_clauses.iter().any(|c| {
            c.name.contains("Source") || c.canonical_snippet.contains("Corresponding")
        }),
        "Must detect stripped source disclosure clause"
    );
}

#[test]
fn test_apache_with_patent_grant_stripped() {
    // Apache-2.0 with patent grant clause removed — this is a sneaky attack
    // because the remaining text still looks like a valid Apache license
    let stripped_apache = r#"Apache License
Version 2.0, January 2004

TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

Subject to the terms and conditions of this License, each Contributor hereby
grants to You a perpetual, worldwide, non-exclusive, no-charge, royalty-free,
irrevocable copyright license to reproduce, prepare Derivative Works of,
publicly display, publicly perform, sublicense, and distribute the Work.

You must cause any modified files to carry prominent notices stating
that You changed the files.

You may add Your own copyright statement to Your modifications.

NOTICE preservation required."#;

    let report =
        LicenseTextForensics::analyze(stripped_apache, Path::new("LICENSE"), Some("Apache-2.0"));
    assert!(
        report.clause_analysis.missing_clauses.iter().any(|c| {
            c.name.contains("Patent") || c.obligation == skera::detection::license_text_forensics::ClauseObligation::PatentGrant
        }),
        "Must detect missing patent grant clause in Apache-2.0"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Section 3: Chimera / Frankensteined Licenses
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_mit_gpl_apache_chimera() {
    // The classic 3-way chimera: MIT header + GPL body + Apache patent
    let chimera = r#"MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy.

You may redistribute it and/or modify it under the terms of the GNU General
Public License as published by the Free Software Foundation.

Subject to the terms and conditions of this License, each Contributor hereby
grants to You a perpetual, worldwide, non-exclusive patent license.
Licensed under the Apache License, Version 2.0."#;

    let report = LicenseTextForensics::analyze(chimera, Path::new("LICENSE"), None);
    assert!(
        report.is_chimera,
        "Must detect MIT+GPL+Apache chimera license"
    );
    assert!(
        report.trust_score < 0.7,
        "Trust score must be severely reduced for chimera, got {}",
        report.trust_score
    );
}

#[test]
fn test_openrail_gpl_mit_chimera() {
    // AI/ML-specific chimera: OpenRAIL + GPL + MIT
    let chimera = r#"OpenRAIL License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this model and its weights.

This model is released under the OpenRAIL license terms with the following
use restrictions.

Under the terms of the GNU General Public License, you must make source
available.

THE SOFTWARE IS PROVIDED "AS IS"."#;

    let report = LicenseTextForensics::analyze(chimera, Path::new("LICENSE"), None);
    assert!(
        report.is_chimera,
        "Must detect OpenRAIL+GPL+MIT chimera license"
    );
}

#[test]
fn test_two_family_suspicious_mix() {
    // GPL + MIT — only 2 families, but these are fundamentally incompatible
    let mix = r#"
Permission is hereby granted, free of charge, to any person obtaining a copy.
Under the terms of the GNU General Public License as published by the
Free Software Foundation, either version 3 of the License.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND."#;

    let report = LicenseTextForensics::analyze(mix, Path::new("LICENSE"), None);
    // Should at minimum flag as suspicious (warning-level chimera)
    assert!(
        report.findings.iter().any(|f| f.category == FindingCategory::ChimeraLicense),
        "Must flag GPL+MIT mix as suspicious chimera"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Section 4: Version Confusion Attacks
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_gpl2_header_gpl3_body() {
    // Declares GPL-2.0 but includes GPL-3.0 text
    // This matters because GPL-2.0 doesn't have anti-tivoization
    let confused = r#"GNU GENERAL PUBLIC LICENSE
Version 3, 29 June 2007

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later version.

When we speak of free software, we are referring to freedom, not price.

You must give any recipient of the Corresponding Source.
Installation Information for a User Product."#;

    let report = LicenseTextForensics::analyze(confused, Path::new("COPYING"), Some("GPL-2.0"));
    let has_version_confusion = report.version_confusion.is_some()
        || report.findings.iter().any(|f| f.category == FindingCategory::VersionConfusion);
    assert!(
        has_version_confusion,
        "Must detect GPL-2.0 declared but GPL-3.0 text"
    );
}

#[test]
fn test_bsd2_declared_bsd3_text() {
    // Declares BSD-2-Clause but includes BSD-3-Clause text
    let confused = r#"Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice.
2. Redistributions in binary form must reproduce the above copyright notice.
3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software."#;

    let report =
        LicenseTextForensics::analyze(confused, Path::new("LICENSE"), Some("BSD-2-Clause"));
    // The detect_license_from_text should identify this as BSD-3-Clause
    assert_eq!(
        report.detected_license,
        Some("BSD-3-Clause".to_string()),
        "Should detect BSD-3-Clause text when BSD-2-Clause is declared"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Section 5: Hidden Restrictions / License Poisoning
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_mit_with_hidden_commercial_restriction() {
    // MIT license with a hidden commercial restriction clause
    let poisoned = r#"MIT License

Copyright (c) 2024 SneakyCorp

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

This software may not be used for commercial purposes without a separate
commercial license from SneakyCorp. Evaluation purposes only.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND."#;

    let report = LicenseTextForensics::analyze(poisoned, Path::new("LICENSE"), Some("MIT"));
    assert!(
        !report.custom_additions.is_empty(),
        "Must detect hidden commercial restriction in MIT"
    );
    assert!(
        report.findings.iter().any(|f| f.category == FindingCategory::HiddenObligation),
        "Must flag as hidden obligation"
    );
}

#[test]
fn test_mit_with_non_compete_poison() {
    // MIT license with a non-compete clause injected
    let poisoned = r#"MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software, subject to the following conditions:

The above copyright notice and this permission notice shall be included.

Licensee shall not compete with or create a competing product based on
this Software for a period of 24 months.

THE SOFTWARE IS PROVIDED "AS IS"."#;

    let report = LicenseTextForensics::analyze(poisoned, Path::new("LICENSE"), Some("MIT"));
    assert!(
        report.custom_additions.iter().any(|a| {
            a.addition_type == skera::detection::license_text_forensics::AdditionType::NonCompete
        }),
        "Must detect non-compete clause in MIT license"
    );
}

#[test]
fn test_mit_with_telemetry_requirement() {
    // MIT license with a hidden data collection requirement
    let poisoned = r#"MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software.

The above copyright notice and this permission notice shall be included.

This software includes telemetry and usage data collection.
By using this software, you agree to the collection of analytics.

THE SOFTWARE IS PROVIDED "AS IS"."#;

    let report = LicenseTextForensics::analyze(poisoned, Path::new("LICENSE"), Some("MIT"));
    assert!(
        report.custom_additions.iter().any(|a| {
            a.addition_type == skera::detection::license_text_forensics::AdditionType::DataCollection
        }),
        "Must detect telemetry/data collection in MIT license"
    );
}

#[test]
fn test_mit_with_field_of_use_restriction() {
    // MIT license with military/surveillance use restriction
    // This is the OpenRAIL-style restriction placed on an MIT license
    let poisoned = r#"MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software.

The above copyright notice and this permission notice shall be included.

This software may not be used for military or surveillance purposes.

THE SOFTWARE IS PROVIDED "AS IS"."#;

    let report = LicenseTextForensics::analyze(poisoned, Path::new("LICENSE"), Some("MIT"));
    assert!(
        report.custom_additions.iter().any(|a| {
            a.addition_type == skera::detection::license_text_forensics::AdditionType::FieldOfUseRestriction
        }),
        "Must detect field-of-use restriction in MIT license"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Section 6: Suspicious Patterns and Edge Cases
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_extremely_short_license() {
    let short = "Copyright 2024. All rights reserved.";
    let report = LicenseTextForensics::analyze(short, Path::new("LICENSE"), None);
    assert!(
        report.trust_score < 0.9,
        "Extremely short license should have reduced trust score, got {}",
        report.trust_score
    );
}

#[test]
fn test_template_placeholders_unfilled() {
    let template = r#"MIT License

Copyright (c) [year] [fullname]

Permission is hereby granted, free of charge, to any person obtaining a copy."#;

    let report = LicenseTextForensics::analyze(template, Path::new("LICENSE"), Some("MIT"));
    assert!(
        report.findings.iter().any(|f| {
            f.description.contains("placeholder") || f.description.contains("template")
        }),
        "Must detect unfilled template placeholders"
    );
}

#[test]
fn test_all_rights_reserved_in_oss() {
    // "All rights reserved" contradicts the open-source grant
    let contradicted = r#"MIT License

Copyright (c) 2024 Example Corp. All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software.

THE SOFTWARE IS PROVIDED "AS IS"."#;

    let report = LicenseTextForensics::analyze(contradicted, Path::new("LICENSE"), Some("MIT"));
    assert!(
        report.findings.iter().any(|f| {
            f.description.contains("All rights reserved")
        }),
        "Must detect 'All rights reserved' contradicting OSS grant"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Section 7: Correlation Engine Adversarial Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_triple_correlation_same_file() {
    // Three violations on the same file — two are correlated, one is not
    let mut result = make_result(vec![
        make_violation(ViolationType::MissingAttribution, "src/lib.rs", Severity::Medium, 0.6),
        make_violation(ViolationType::StrippedLicense, "src/lib.rs", Severity::Medium, 0.5),
        make_violation(ViolationType::LockfileStaleness, "src/lib.rs", Severity::Low, 0.4),
    ]);
    correlate_violations(&mut result);
    // First two should be corroborated, third should not
    assert!(result.violations[0].description.contains("CORROBORATED"));
    assert!(result.violations[1].description.contains("CORROBORATED"));
    assert!(!result.violations[2].description.contains("CORROBORATED"));
}

#[test]
fn test_severity_cascade_high_to_critical() {
    // High-severity violations correlated should escalate to Critical
    let mut result = make_result(vec![
        make_violation(ViolationType::DrmCircumvention, "assets/video.mp4", Severity::High, 0.8),
        make_violation(ViolationType::UnlicensedVideoUsage, "assets/video.mp4", Severity::High, 0.7),
    ]);
    correlate_violations(&mut result);
    assert_eq!(
        result.violations[0].severity,
        Severity::Critical,
        "DRM + unlicensed video on same file must escalate to Critical"
    );
}

#[test]
fn test_confidence_boost_clamp_at_one() {
    // Even with high initial confidence, boosted confidence must not exceed 1.0
    let mut result = make_result(vec![
        make_violation(ViolationType::ChimeraLicense, "LICENSE", Severity::Medium, 0.9),
        make_violation(ViolationType::HomoglyphTampering, "LICENSE", Severity::Medium, 0.95),
    ]);
    correlate_violations(&mut result);
    assert!(
        result.violations[0].confidence <= 1.0,
        "Confidence must never exceed 1.0, got {}",
        result.violations[0].confidence
    );
    assert!(
        result.violations[1].confidence <= 1.0,
        "Confidence must never exceed 1.0, got {}",
        result.violations[1].confidence
    );
}

#[test]
fn test_ai_model_triple_signal() {
    // AI model violation + training data contamination + unauthorized fine-tuning
    // Only the directly-correlated pairs should fire
    let mut result = make_result(vec![
        make_violation(ViolationType::AiModelLicenseViolation, "model.bin", Severity::High, 0.8),
        make_violation(ViolationType::TrainingDataContamination, "model.bin", Severity::High, 0.7),
        make_violation(ViolationType::UnauthorizedFineTuning, "model.bin", Severity::Medium, 0.6),
    ]);
    correlate_violations(&mut result);
    // All three should be boosted (AI model ↔ training data, AI model ↔ fine-tuning)
    assert!(result.violations[0].description.contains("CORROBORATED"));
    assert!(result.violations[1].description.contains("CORROBORATED"));
    assert!(result.violations[2].description.contains("CORROBORATED"));
}

// ═══════════════════════════════════════════════════════════════════
// Section 8: Advanced Deobfuscation Adversarial Tests
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_deeply_nested_control_flow_flattening() {
    // More realistic CFF pattern with state machine
    let obfuscated = r#"
var _0x12 = "0";
while(true) {
    switch(_0x12) {
        case "0": var x = 1; _0x12 = "1"; break;
        case "1": var y = 2; _0x12 = "2"; break;
        case "2": console.log(x + y); _0x12 = "3"; break;
        case "3": return;
    }
}
"#;
    let result = AdvancedDeobfuscator::deobfuscate(obfuscated);
    assert!(
        result.flattened_blocks_recovered > 0,
        "Must recover control flow from state machine"
    );
    // The recovered code should contain the functional statements
    // (state-variable assignments are filtered out during recovery)
    assert!(
        result.cleaned_content.contains("console.log")
            || result.cleaned_content.contains("recovered control flow"),
        "Recovered code should contain original logic or recovery marker"
    );
}

#[test]
fn test_anti_debugging_traps() {
    let code = r#"
setInterval(function() { debugger }, 100);
console["log"] = function() {};
console["warn"] = function() {};
var start = Date.now();
doWork();
var end = Date.now();
if (end - start > 100) { throw new Error("debugger detected"); }
"#;
    let result = AdvancedDeobfuscator::deobfuscate(code);
    assert!(
        result.self_defending_traps_found > 0,
        "Must detect self-defending traps"
    );
    assert!(
        result.cleaned_content.contains("neutralized"),
        "Traps should be neutralized in output"
    );
}

#[test]
fn test_combined_obfuscation_techniques() {
    // Multiple obfuscation techniques layered together
    let code = r#"
setInterval(function() { debugger }, 500);
if (typeof undefined === "undefined") {
    if ((x * x + x) % 2 === 0) {
        var _0x1 = "0";
        while(true) {
            switch(_0x1) {
                case "0": var real = doSomething(); _0x1 = "1"; break;
                case "1": processResult(real); _0x1 = "2"; break;
                case "2": return real;
            }
        }
    }
}
function(){}
"#;
    let result = AdvancedDeobfuscator::deobfuscate(code);
    assert!(
        result.transformations.len() >= 2,
        "Must apply multiple deobfuscation passes, got {}",
        result.transformations.len()
    );
}

// ═══════════════════════════════════════════════════════════════════
// Section 9: License Detection Under Obfuscation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_detect_license_with_noise() {
    // License text surrounded by noise — should still detect MIT
    let noisy = r#"
/* PROPRIETARY NOTICE - DO NOT REMOVE */
/* Generated by Code Minifier v3.2 */
/* Build: 20241215-abc123 */

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction.

/* END OF LICENSE SECTION */
var x = 42;
"#;
    let report = LicenseTextForensics::analyze(noisy, Path::new("bundle.min.js"), None);
    assert_eq!(
        report.detected_license,
        Some("MIT".to_string()),
        "Must detect MIT license even with surrounding noise"
    );
}

#[test]
fn test_detect_busl_license() {
    let text = "Licensed under the Business Source License 1.1 with a change date of 2027.";
    let report = LicenseTextForensics::analyze(text, Path::new("LICENSE"), None);
    assert_eq!(
        report.detected_license,
        Some("BUSL-1.1".to_string()),
        "Must detect Business Source License"
    );
}

#[test]
fn test_detect_elastic_license() {
    let text = "Licensed under the Elastic License 2.0. You may not provide the software to third parties as a hosted or managed service.";
    let report = LicenseTextForensics::analyze(text, Path::new("LICENSE"), None);
    assert_eq!(
        report.detected_license,
        Some("Elastic-2.0".to_string()),
        "Must detect Elastic License"
    );
}

#[test]
fn test_detect_openrail_license() {
    let text = "This model is subject to the OpenRAIL-M license with use restrictions.";
    let report = LicenseTextForensics::analyze(text, Path::new("LICENSE"), None);
    assert_eq!(
        report.detected_license,
        Some("OpenRAIL".to_string()),
        "Must detect OpenRAIL license"
    );
}

#[test]
fn test_detect_sspl_license() {
    let text = "Licensed under the Server Side Public License, v 1. You must make the complete source code of all programs that you make for the purpose of offering the licensed program available.";
    let report = LicenseTextForensics::analyze(text, Path::new("LICENSE"), None);
    assert_eq!(
        report.detected_license,
        Some("SSPL-1.0".to_string()),
        "Must detect SSPL license"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Section 10: Stress Tests — Multiple Attack Vectors Combined
// ═══════════════════════════════════════════════════════════════════

#[test]
fn test_chimera_with_homoglyphs_and_hidden_restriction() {
    // The ultimate adversarial license: chimera + homoglyphs + hidden restriction
    let nightmare = "MIT Lic\u{0435}nse\n\n\
        P\u{0435}rmission is hereby gr\u{0430}nted, fre\u{0435} \u{043E}f charge.\n\
        Under the terms of the GNU General Public License.\n\
        Licensed under the Apache License, Version 2.0.\n\
        This software may not be used for commercial purposes.\n\
        THE SOFTWARE IS PROVIDED \"AS IS\".";

    let report = LicenseTextForensics::analyze(nightmare, Path::new("LICENSE"), Some("MIT"));

    // Should detect ALL of: homoglyphs, chimera, and commercial restriction
    assert!(
        !report.unicode_anomalies.is_empty(),
        "Must detect homoglyphs in nightmare license"
    );
    assert!(
        report.is_chimera,
        "Must detect chimera in nightmare license"
    );
    assert!(
        !report.custom_additions.is_empty(),
        "Must detect commercial restriction in nightmare license"
    );
    assert!(
        report.trust_score < 0.3,
        "Trust score must be very low for nightmare license, got {}",
        report.trust_score
    );
}

#[test]
fn test_massive_correlation_burst() {
    // 6 violations on the same file — tests that correlation doesn't double-boost
    let mut result = make_result(vec![
        make_violation(ViolationType::DrmCircumvention, "x.bin", Severity::High, 0.8),
        make_violation(ViolationType::StockWatermarkDetected, "x.bin", Severity::High, 0.7),
        make_violation(ViolationType::UnlicensedAudioUsage, "x.bin", Severity::High, 0.6),
        make_violation(ViolationType::UnlicensedVideoUsage, "x.bin", Severity::Medium, 0.5),
        make_violation(ViolationType::ImageLicenseScopeExceeded, "x.bin", Severity::Medium, 0.7),
        make_violation(ViolationType::StockPhotoUsage, "x.bin", Severity::Medium, 0.6),
    ]);
    correlate_violations(&mut result);
    // Verify no confidence exceeds 1.0
    for v in &result.violations {
        assert!(
            v.confidence <= 1.0,
            "Confidence exceeded 1.0 after massive correlation burst: {} for {:?}",
            v.confidence,
            v.violation_type
        );
    }
    // At least some should be corroborated
    let corroborated_count = result
        .violations
        .iter()
        .filter(|v| v.description.contains("CORROBORATED"))
        .count();
    assert!(
        corroborated_count >= 2,
        "At least 2 violations should be corroborated in massive burst, got {}",
        corroborated_count
    );
}

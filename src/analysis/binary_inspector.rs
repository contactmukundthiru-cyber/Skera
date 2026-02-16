//! Binary inspection for license forensics
//!
//! Detects:
//! - Statically linked GPL libraries (symbol analysis)
//! - Embedded license strings in binaries
//! - Known copyleft library function signatures
//! - Ghidra decompilation bridge for deep analysis (future)

use crate::detection::{Violation, ViolationType, Severity};
use crate::evidence::EvidenceItem;
use crate::license::LicenseId;
use goblin::Object;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Binary inspection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryInspection {
    pub file_path: PathBuf,
    pub format: BinaryFormat,
    /// Imported libraries (dynamically linked)
    pub dynamic_imports: Vec<String>,
    /// Exported symbols
    pub exports: Vec<String>,
    /// All symbols (including static)
    pub all_symbols: Vec<String>,
    /// Strings that look like license text
    pub license_strings: Vec<LicenseString>,
    /// Known GPL function signatures detected
    pub gpl_signatures: Vec<GplSignature>,
    /// Linking mode detected
    pub linking_mode: LinkingEvidence,
    /// Ghidra decompilation available?
    pub ghidra_available: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryFormat {
    Elf,
    Pe,
    MachO,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseString {
    pub text: String,
    pub offset: usize,
    pub likely_license: Option<LicenseId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GplSignature {
    pub symbol_name: String,
    pub known_library: String,
    pub known_license: LicenseId,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkingEvidence {
    /// Is dynamically linked?
    pub has_dynamic_linking: bool,
    /// Is statically linked?
    pub has_static_linking: bool,
    /// Specific libraries detected as statically linked
    pub statically_linked_libs: Vec<String>,
    /// Specific libraries detected as dynamically linked
    pub dynamically_linked_libs: Vec<String>,
}

/// Known GPL library symbol prefixes
const GPL_SYMBOL_PATTERNS: &[(&str, &str, &str)] = &[
    // (pattern, library_name, license)
    ("g_", "GLib", "LGPL-2.1-only"),
    ("gtk_", "GTK", "LGPL-2.1-only"),
    ("gst_", "GStreamer", "LGPL-2.1-only"),
    ("avcodec_", "FFmpeg/libavcodec", "LGPL-2.1-only"),
    ("avformat_", "FFmpeg/libavformat", "LGPL-2.1-only"),
    ("avutil_", "FFmpeg/libavutil", "LGPL-2.1-only"),
    ("swscale_", "FFmpeg/libswscale", "LGPL-2.1-only"),
    ("swresample_", "FFmpeg/libswresample", "LGPL-2.1-only"),
    ("av_", "FFmpeg", "LGPL-2.1-only"),
    ("x264_", "x264", "GPL-2.0-only"),
    ("x265_", "x265", "GPL-2.0-only"),
    ("lame_", "LAME", "LGPL-2.1-only"),
    ("mp3lame_", "LAME", "LGPL-2.1-only"),
    ("opus_", "Opus", "BSD-3-Clause"),
    ("vorbis_", "Vorbis", "BSD-3-Clause"),
    ("FLAC__", "FLAC", "BSD-3-Clause"),
    ("sqlite3_", "SQLite", "Public Domain"),
    ("curl_", "libcurl", "MIT"),
    ("SSL_", "OpenSSL", "Apache-2.0"),
    ("EVP_", "OpenSSL", "Apache-2.0"),
    ("OPENSSL_", "OpenSSL", "Apache-2.0"),
    ("gcry_", "Libgcrypt", "LGPL-2.1-only"),
    ("gpg_", "GnuPG", "GPL-3.0-only"),
    ("readline", "GNU Readline", "GPL-3.0-only"),
    ("rl_", "GNU Readline", "GPL-3.0-only"),
    ("ncurses", "ncurses", "MIT"),
    ("BZ2_", "bzip2", "BSD-3-Clause"),
    ("ZSTD_", "Zstandard", "BSD-3-Clause"),
    ("LZ4_", "LZ4", "BSD-2-Clause"),
    ("png_", "libpng", "Libpng"),
    ("jpeg_", "libjpeg", "IJG"),
    ("tiff_", "libtiff", "MIT"),
    ("FT_", "FreeType", "FTL"),
    ("hb_", "HarfBuzz", "MIT"),
    ("cairo_", "Cairo", "LGPL-2.1-only"),
    ("pango_", "Pango", "LGPL-2.1-only"),
    ("xml", "libxml2", "MIT"),
    ("pcre", "PCRE", "BSD-3-Clause"),
    ("lua_", "Lua", "MIT"),
    ("Py", "CPython", "PSF-2.0"),
    ("rb_", "Ruby", "BSD-2-Clause"),
];

/// License-related string patterns to search in binaries
const LICENSE_STRING_PATTERNS: &[&str] = &[
    "GNU General Public License",
    "Free Software Foundation",
    "LGPL",
    "GPL",
    "MIT License",
    "Permission is hereby granted",
    "Apache License",
    "BSD License",
    "Redistribution and use",
    "Mozilla Public License",
    "Creative Commons",
    "SPDX-License-Identifier",
    "Copyright (C)",
    "All rights reserved",
    "This program is free software",
    "under the terms of",
];

/// Binary inspector engine
pub struct BinaryInspector;

impl BinaryInspector {
    pub fn new() -> Self {
        Self
    }

    /// Inspect a binary file
    pub fn inspect(&self, path: &Path) -> crate::SkeraResult<BinaryInspection> {
        let data = std::fs::read(path)
            .map_err(|e| crate::SkeraError::Io(e))?;

        let (format, dynamic_imports, exports, all_symbols) = match Object::parse(&data) {
            Ok(Object::Elf(elf)) => {
                let imports: Vec<String> = elf
                    .libraries
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
                let dynsyms: Vec<String> = elf
                    .dynsyms
                    .iter()
                    .filter_map(|s| elf.dynstrtab.get_at(s.st_name))
                    .map(String::from)
                    .collect();
                let syms: Vec<String> = elf
                    .syms
                    .iter()
                    .chain(elf.dynsyms.iter())
                    .filter_map(|s| {
                        elf.strtab.get_at(s.st_name)
                            .or_else(|| elf.dynstrtab.get_at(s.st_name))
                    })
                    .map(String::from)
                    .collect();
                (BinaryFormat::Elf, imports, dynsyms, syms)
            }
            Ok(Object::PE(pe)) => {
                let imports: Vec<String> = pe
                    .imports
                    .iter()
                    .map(|i| i.dll.to_string())
                    .collect();
                let exports: Vec<String> = pe
                    .exports
                    .iter()
                    .filter_map(|e| e.name.map(String::from))
                    .collect();
                (BinaryFormat::Pe, imports, exports, Vec::new())
            }
            Ok(Object::Mach(_)) => {
                (BinaryFormat::MachO, Vec::new(), Vec::new(), Vec::new())
            }
            _ => (BinaryFormat::Unknown, Vec::new(), Vec::new(), Vec::new()),
        };

        // Detect license strings in binary
        let license_strings = self.find_license_strings(&data);

        // Check for known GPL library symbols
        let gpl_signatures = self.detect_gpl_symbols(&all_symbols, &exports);

        // Determine linking mode
        let linking_mode = self.analyze_linking(
            &dynamic_imports,
            &all_symbols,
            &gpl_signatures,
        );

        Ok(BinaryInspection {
            file_path: path.to_path_buf(),
            format,
            dynamic_imports,
            exports,
            all_symbols,
            license_strings,
            gpl_signatures,
            linking_mode,
            ghidra_available: false, // Set by caller if Ghidra is available
        })
    }

    /// Search binary data for license-related strings
    fn find_license_strings(&self, data: &[u8]) -> Vec<LicenseString> {
        use aho_corasick::AhoCorasick;

        let ac = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(LICENSE_STRING_PATTERNS)
            .expect("Failed to build license string matcher");

        let mut results = Vec::new();
        for mat in ac.find_iter(data) {
            // Extract surrounding context
            let start = mat.start().saturating_sub(20);
            let end = (mat.end() + 80).min(data.len());
            let context = String::from_utf8_lossy(&data[start..end]).to_string();

            results.push(LicenseString {
                text: context,
                offset: mat.start(),
                likely_license: None, // Could be enhanced with classifier
            });
        }

        results
    }

    /// Detect known GPL library function signatures
    fn detect_gpl_symbols(
        &self,
        symbols: &[String],
        exports: &[String],
    ) -> Vec<GplSignature> {
        let mut signatures = Vec::new();

        for symbol in symbols.iter().chain(exports.iter()) {
            for &(pattern, lib, license) in GPL_SYMBOL_PATTERNS {
                if symbol.starts_with(pattern) && symbol.len() > pattern.len() + 2 {
                    signatures.push(GplSignature {
                        symbol_name: symbol.clone(),
                        known_library: lib.to_string(),
                        known_license: LicenseId::new(license),
                        confidence: 0.85,
                    });
                }
            }
        }

        // Deduplicate by library
        signatures.sort_by(|a, b| a.known_library.cmp(&b.known_library));
        signatures.dedup_by(|a, b| a.known_library == b.known_library);

        signatures
    }

    /// Analyze linking mode from symbols and imports
    fn analyze_linking(
        &self,
        dynamic_imports: &[String],
        _all_symbols: &[String],
        gpl_sigs: &[GplSignature],
    ) -> LinkingEvidence {
        let mut statically_linked = Vec::new();
        let mut dynamically_linked = Vec::new();

        for sig in gpl_sigs {
            let lib_lower = sig.known_library.to_lowercase();
            let is_dynamic = dynamic_imports.iter().any(|imp| {
                imp.to_lowercase().contains(&lib_lower)
            });

            if is_dynamic {
                dynamically_linked.push(sig.known_library.clone());
            } else {
                statically_linked.push(sig.known_library.clone());
            }
        }

        statically_linked.sort();
        statically_linked.dedup();
        dynamically_linked.sort();
        dynamically_linked.dedup();

        LinkingEvidence {
            has_dynamic_linking: !dynamically_linked.is_empty() || !dynamic_imports.is_empty(),
            has_static_linking: !statically_linked.is_empty(),
            statically_linked_libs: statically_linked,
            dynamically_linked_libs: dynamically_linked,
        }
    }

    /// Convert inspection to violations
    pub fn to_violations(
        &self,
        inspection: &BinaryInspection,
        claimed_license: &LicenseId,
    ) -> Vec<Violation> {
        let mut violations = Vec::new();

        // Check for GPL symbols in proprietary binary
        if !claimed_license.is_copyleft() {
            for sig in &inspection.gpl_signatures {
                if sig.known_license.is_copyleft() {
                    // Check if statically linked
                    let is_static = inspection
                        .linking_mode
                        .statically_linked_libs
                        .contains(&sig.known_library);

                    let violation_type = if is_static {
                        ViolationType::BinaryContainsGplSymbols
                    } else {
                        // Dynamic linking of LGPL is OK, GPL is not
                        if sig.known_license.family() == crate::license::LicenseFamily::StrongCopyleft {
                            ViolationType::GplDynamicLinking
                        } else {
                            continue; // LGPL dynamic linking is fine
                        }
                    };

                    violations.push(Violation {
                        violation_type,
                        severity: Severity::Critical,
                        confidence: sig.confidence,
                        description: format!(
                            "Binary contains {} symbols from {} ({}) but claims {}",
                            if is_static { "statically linked" } else { "dynamically linked" },
                            sig.known_library,
                            sig.known_license,
                            claimed_license
                        ),
                        files: vec![inspection.file_path.clone()],
                        licenses: vec![sig.known_license.clone(), claimed_license.clone()],
                        obligations_violated: vec![],
                        evidence: vec![EvidenceItem {
                            description: format!(
                                "Symbol '{}' matches {} pattern",
                                sig.symbol_name, sig.known_library
                            ),
                            file_path: Some(inspection.file_path.clone()),
                            line_number: None,
                            byte_offset: None,
                            sha256: None,
                            content_excerpt: Some(sig.symbol_name.clone()),
                            timestamp: chrono::Utc::now(),
                        }],
                        claimed_license: Some(claimed_license.clone()),
                        actual_license: Some(sig.known_license.clone()),
                    });
                }
            }
        }

        violations
    }
}

impl Default for BinaryInspector {
    fn default() -> Self {
        Self::new()
    }
}

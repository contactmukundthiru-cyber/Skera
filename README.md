<p align="center">
  <h1 align="center">⚔️ Skera</h1>
  <p align="center"><strong>Universal Digital Copyright Forensics Engine</strong></p>
  <p align="center"><em>Carves through obfuscation to prove origin</em></p>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#why-skera">Why Skera</a> •
  <a href="#detection-modules">Modules</a> •
  <a href="#usage">Usage</a> •
  <a href="#license">License</a>
</p>

---

## Why Skera

Software vendors routinely ship code taken from open-source projects without attribution or license compliance — stripped copyright headers, minified bundles hiding stolen libraries, opaque WASM binaries embedding dozens of dependencies with zero documentation. Existing tools catch some of this; Skera catches what they miss.

Built to audit browser extensions, enterprise software, firmware, and web applications at forensic depth. If there's stolen code in a binary, Skera will find it.

## Features

### 🔍 25 Detection Modules

| Category | Modules |
|----------|---------|
| **JS Bundle Forensics** | Identifies 80+ libraries inside minified bundles using fingerprints that survive minification (error messages, API names, crypto constants) |
| **WASM Binary Analysis** | Extracts strings, Go dependencies, function names, and endpoints from compiled WebAssembly binaries |
| **Attribution Checking** | Verifies LICENSE files, NOTICE files, copyright headers, and THIRD_PARTY_NOTICES against actual dependencies |
| **License Identification** | SPDX identification using fuzzy matching, TLSH, and the askalono engine |
| **Deobfuscation** | Advanced and standard JavaScript deobfuscation to recover original code patterns |
| **Supply Chain Audit** | Typosquatting detection, version pinning risks, scope confusion, lockfile analysis |
| **License Text Forensics** | Chimera license detection, homoglyph tampering, clause extraction, license mutation tracking |
| **Creative Commons** | CC-NC/ND/BY/SA compliance checking with commercial context detection |
| **Data Rights** | PII exposure, exposed secrets, GDPR/CCPA sensitive data detection |
| **Media Forensics** | Audio fingerprinting, video deduplication, stock watermark detection |
| **Cross-Language** | Detects code translated between languages (JS→Python, etc.) |
| **Code Embeddings** | Semantic similarity using structural code embeddings |
| **Web Asset Scanner** | CDN library auditing, font licensing, SRI hash verification |

### 📋 60+ Violation Types

Organized into categories:
- **Attribution** — missing copyright, missing NOTICE, incorrect attribution
- **Copyleft** — GPL in proprietary, missing source disclosure, AGPL network use
- **License Laundering** — text tampering, license swapping, typosquatted identifiers
- **Commercial Misuse** — NC content in commercial, ND content modified
- **Code Provenance** — fingerprint mismatch, binary GPL symbols, decompiled matches
- **Supply Chain** — typosquatting, deprecated deps, scope confusion
- **Binary Forensics** — opaque distribution without license documentation
- **AI & Model Rights** — model license violations, training data contamination
- **Digital Media** — unlicensed audio/video/sampling, DRM circumvention

### 🗄️ Data-Driven Signature Database

All library signatures live in external TOML files — no hardcoding:

```toml
[[lib]]
name = "jQuery"
author = "OpenJS Foundation and other contributors"
license = "MIT"
family = "permissive"
min_hits = 2
strings = [
  { p = "jQuery requires a window with a document", d = "core error message", c = 0.99 },
  { p = "jQuery.noConflict", d = "noConflict API", c = 0.95 },
]
```

Add your own signatures by creating TOML files — Skera loads them at startup.

### 🦀 Built in Rust

- Zero-copy binary parsing with `goblin` and `object`
- Parallel scanning with `rayon`
- TLSH and ssdeep fuzzy hashing for similarity detection
- YARA pattern matching (optional)
- Perceptual image hashing (optional)

## Detection Modules

<details>
<summary><strong>Full Module List (25 modules)</strong></summary>

1. `header_detector` — License header detection in source files
2. `snippet_matcher` — Code snippet matching against known databases
3. `attribution_checker` — Deep attribution verification
4. `contamination` — License contamination tracing through dependency graphs
5. `js_bundle_forensics` — JavaScript bundle piracy detection
6. `js_analysis` — JavaScript-specific code analysis
7. `js_signatures` — Data-driven TOML signature loading
8. `similarity` — Fuzzy hash similarity (TLSH, ssdeep)
9. `license_identifier` — SPDX license identification
10. `structural_fingerprint` — AST-level code fingerprinting
11. `yara_scanner` — YARA pattern-based detection
12. `asset_fingerprint` — Perceptual image/asset hashing
13. `media_forensics` — Audio/video forensics
14. `deobfuscation` — Standard JS deobfuscation
15. `advanced_deobfuscation` — Control flow and string deobfuscation
16. `scancode_bridge` — ScanCode-toolkit integration
17. `code_embeddings` — Structural code embedding similarity
18. `cross_language` — Cross-language code translation detection
19. `license_text_forensics` — License text mutation and chimera detection
20. `supply_chain_audit` — Supply chain risk assessment
21. `web_asset_scanner` — Web asset and CDN auditing
22. `creative_commons` — Creative Commons compliance
23. `data_rights` — PII and data rights compliance
24. `wasm_forensics` — WebAssembly binary forensics

</details>

## Usage

### As a Library

```rust
use skera::detection::js_bundle_forensics::JsBundleScanner;
use skera::detection::wasm_forensics::WasmForensicScanner;
use std::path::Path;

// Scan a JavaScript bundle for embedded libraries
let scanner = JsBundleScanner::new();
let report = scanner.analyze_file(Path::new("extension/background.js"))?;

for lib in &report.detected_libraries {
    println!("Found: {} ({}) — {}", lib.name, lib.license, lib.integrity);
}

// Scan a WASM binary for hidden dependencies
let wasm_scanner = WasmForensicScanner::new();
let wasm_report = wasm_scanner.analyze_file(Path::new("extension/client.wasm"))?;

for dep in &wasm_report.go_dependencies {
    println!("Go dep: {} — License: {} — Attribution: {}",
        dep.package,
        dep.known_license.as_deref().unwrap_or("Unknown"),
        if dep.attribution_found { "✅" } else { "❌" }
    );
}

println!("{}", wasm_report.to_markdown());
```

### Scanning a Chrome Extension

```rust
use skera::detection::js_bundle_forensics::JsBundleScanner;
use std::path::Path;
use walkdir::WalkDir;

let scanner = JsBundleScanner::new();

for entry in WalkDir::new("path/to/extracted/extension")
    .into_iter()
    .filter_map(|e| e.ok())
    .filter(|e| e.path().extension().map_or(false, |ext| ext == "js"))
{
    let report = scanner.analyze_file(entry.path())?;
    if !report.detected_libraries.is_empty() {
        println!("\n=== {} ===", entry.path().display());
        println!("{}", report.to_markdown());
    }
}
```

## Building

```bash
# Basic build
cargo build -p skera

# With all features
cargo build -p skera --all-features

# Run tests
cargo test -p skera
```

### Feature Flags

| Feature | Description | Dependencies |
|---------|-------------|-------------|
| `yara` | YARA pattern matching | `yara-x` |
| `asset-fingerprint` | Perceptual image hashing | `blockhash`, `image` |
| `media-forensics` | Audio/video forensics | `vid_dup_finder_lib`, `rusty-chromaprint` |

## Architecture

```
skera/
├── src/
│   ├── lib.rs              — Public API
│   ├── detection/          — 25 detection modules
│   ├── engine/             — Orchestration, correlation, pipeline
│   ├── analysis/           — Deep analysis (AST, dependency graph)
│   ├── audit/              — Audit trail and evidence collection
│   ├── evidence/           — Evidence item types
│   ├── ingest/             — File ingestion and format handling
│   ├── license/            — License database and classification
│   ├── policy/             — Policy configuration
│   └── report/             — Report generation (JSON, Markdown, SARIF)
├── data/
│   └── signatures/         — TOML signature databases
│       ├── libraries.toml  — 80+ JS library signatures
│       └── assets.toml     — Font, CSS, icon signatures
├── tests/                  — Integration tests
├── THIRD_PARTY_NOTICES.md  — Full dependency attribution
└── Cargo.toml
```

## Contributing

Skera is open source under MIT. Contributions welcome:

1. **Add library signatures** — Create entries in `data/signatures/libraries.toml`
2. **Add Go package licenses** — Extend the known licenses in `wasm_forensics.rs`
3. **Report false positives** — Open an issue with the file that triggered it
4. **Add detection modules** — Follow the pattern in existing modules

## Legal Basis

Skera performs static analysis of software you lawfully possess. The right to analyze, reverse engineer, and audit software for license compliance is well-established:

| Authority | Jurisdiction | What It Protects |
|-----------|-------------|-----------------|
| **17 U.S.C. § 107** (Fair Use) | 🇺🇸 US | Analysis for research, criticism, and commentary is fair use — especially when examining factual elements (function names, strings, dependencies) rather than creative expression |
| **17 U.S.C. § 117(a)** | 🇺🇸 US | Owner of a copy may make copies "as an essential step in the utilization of the computer program" — including for analysis |
| **17 U.S.C. § 1201(f)** | 🇺🇸 US | DMCA explicitly permits reverse engineering "for the sole purpose of identifying and analyzing those elements of the program that are necessary to achieve interoperability" |
| ***Sega v. Accolade*, 977 F.2d 1510 (9th Cir. 1992)** | 🇺🇸 US | Reverse engineering of object code is fair use when it is the only way to access unprotected functional elements |
| ***Oracle v. Google*, 593 U.S. 1 (2021)** | 🇺🇸 US | Supreme Court held that reimplementation of APIs constitutes fair use; factual elements of programs (APIs, interfaces) are not strongly protected |
| **EU Directive 2009/24/EC, Art. 5-6** | 🇪🇺 EU | Permits decompilation for interoperability and error correction without authorization of the rightholder |
| **UK Copyright, Designs and Patents Act 1988, §§ 50A-50C** | 🇬🇧 UK | Permits decompilation for interoperability and observing/studying/testing program behavior |

Skera examines **factual elements** — function names, string literals, package paths, cryptographic constants, API endpoints — not creative expression. These elements are the metadata that proves provenance, and analyzing them is protected activity.

> *"Where disassembly is the only way to gain access to the ideas and functional elements embodied in a copyrighted computer program and where there is a legitimate reason for seeking such access, disassembly is a fair use of the copyrighted work."*  
> — *Sega Enterprises Ltd. v. Accolade, Inc.*, 977 F.2d 1510 (9th Cir. 1992)

## License

**MIT** — Use it however you want. Build on it. Ship it. We don't restrict our tools like the companies we audit restrict their code.

See [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md) for all dependency attributions.

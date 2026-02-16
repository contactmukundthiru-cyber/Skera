# Skera Upgrade Plan

> **Skera** — Old Norse: *to carve*. Universal digital copyright forensics engine.
>
> **Core thesis**: Skera detects *violated license terms* and *stripped attribution*,
> not "copied functions." License violations and DMCA §1202 CMI removal are
> independently enforceable regardless of whether individual code snippets
> are copyrightable.

---

## Phase 1: De-obfuscation Pipeline 🔴 CRITICAL
**Why**: Our string fingerprinting is defeated by ANY basic JS obfuscator.
`"jQuery"` → `_0x4a2f("0x1b")` and our signatures never fire.

### Modules to build:
- `detection/deobfuscation.rs` — Pre-processing pipeline that runs before fingerprinting
  - **String decoding**: Detect and decode Base64, hex, RC4, XOR encoded strings
  - **Array rotation reversal**: Detect `[].push([].shift())` patterns and resolve string arrays
  - **Hex/Unicode escape resolution**: `\x6a\x51\x75\x65\x72\x79` → `"jQuery"`
  - **Control flow de-flattening**: Detect switch-case state machines (future)
  - **Dead code heuristic removal**: Code with no reachable path (future)

### Test case:
Run javascript-obfuscator against known jQuery → scan with Skera → must still detect

---

## Phase 2: ScanCode License Engine Bridge
**Why**: ScanCode has 1000+ license templates with near 100% accuracy.
We have ~500 via askalono. Integrate their engine as a subprocess.

### Modules:
- `detection/scancode_bridge.rs` — Shell out to `scancode` CLI
  - Parse ScanCode JSON output
  - Map ScanCode results to Skera's LicenseId type
  - Fallback to askalono if scancode not installed
  - Feature-gated: `scancode` feature flag

---

## Phase 3: Internet-Scale Auditing
**Why**: The differentiator. `skera audit npm:lodash@4.17.21`

### Modules:
- `audit/mod.rs` — Package fetcher and unpacker
  - `npm.rs` — Download from npm registry, unpack tarball
  - `pypi.rs` — Download from PyPI, unpack wheel/sdist
  - `crates.rs` — Download from crates.io, unpack
  - `crx.rs` — Download Chrome extension from CWS or .crx URL, unpack
  - `url.rs` — Download arbitrary URL, detect type, unpack
- Each fetcher: download → temp dir → run full Skera scan → report

---

## Phase 4: Git Timeline Forensics
**Why**: Proves INTENT, not just act. "Header was stripped in commit X by user Y."

### Modules:
- `analysis/git_forensics.rs` — Git history analysis
  - Walk commits reverse-chronologically
  - Detect when LICENSE/NOTICE files were deleted
  - Detect when copyright headers were removed from specific files
  - Detect when third-party code was first introduced
  - Generate timeline evidence with commit hashes, authors, dates
  - Requires git binary or libgit2

---

## Phase 5: CLI Binary
**Why**: Makes Skera usable. `skera scan ./project`

### Structure:
- `crates/skera-cli/` — Separate crate, depends on skera-core
  - `skera scan <path>` — Full scan, markdown report
  - `skera scan <path> --json` — JSON output
  - `skera scan <path> --sarif` — SARIF for GitHub Advanced Security
  - `skera audit <package-spec>` — Fetch and scan remote package
  - `skera compare <original> <suspect>` — Side-by-side comparison
  - `skera watch <path>` — File watcher mode
  - Config file: `skera.toml` in project root

---

## Phase 6: SSO Architecture Similarity
**Why**: Structure, Sequence, Organization is copyrightable.

### Modules:
- `detection/sso_analyzer.rs`
  - Parse project structure (directory layout, module organization)
  - Extract architectural fingerprint (module graph, API surface shape)
  - Compare against known project architectures
  - Detect cloned project skeletons

---

## Implementation Order

| # | Module | Impact | Effort | Status |
|---|--------|--------|--------|--------|
| 1 | De-obfuscation pipeline | 🔴 Critical — existing detectors are blind | Medium | ✅ DONE — 10 tests passing |
| 2 | ScanCode bridge | 🟡 High — doubles license coverage | Small | ✅ DONE — graceful fallback |
| 3 | Internet-scale auditing | 🟡 High — unique differentiator | Medium | ✅ DONE — npm/pypi/crates/crx/url |
| 4 | Git timeline forensics | 🟡 High — proves intent | Medium | ✅ DONE — timeline + markdown evidence |
| 5 | CLI binary (skera-cli) | 🔴 Critical — nothing is usable without it | Medium | ⏳ Next |
| 6 | SSO architecture similarity | 🟢 Medium — frontier capability | Large | ⏳ Queued |

//! WASM decompiler — extracts scannable content from WebAssembly modules

use std::path::{Path, PathBuf};

pub struct WasmDecompileResult {
    pub output_dir: PathBuf,
    pub total_bytes: u64,
    pub _temp_dir: tempfile::TempDir,
}

/// Decompile/analyze a WASM module for scanning
///
/// Extracts:
/// - WAT (WebAssembly Text) representation
/// - String constants embedded in data sections
/// - Export/import names
/// - Custom section contents
pub async fn decompile(path: &Path) -> Result<WasmDecompileResult, String> {
    let temp_dir = tempfile::TempDir::new()
        .map_err(|e| format!("Failed to create temp dir: {}", e))?;

    let output_dir = temp_dir.path().join("wasm_analysis");
    std::fs::create_dir_all(&output_dir)
        .map_err(|e| format!("Failed to create output dir: {}", e))?;

    let total_bytes = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let wasm_bytes = std::fs::read(path)
        .map_err(|e| format!("Failed to read WASM: {}", e))?;

    // Try wasm2wat (from wabt) for WAT output
    let wat_path = output_dir.join("module.wat");
    if let Ok(result) = std::process::Command::new("wasm2wat")
        .args([path.to_str().unwrap_or(""), "-o", wat_path.to_str().unwrap_or("")])
        .output()
    {
        if !result.status.success() {
            // WAT conversion failed — not critical, continue
            tracing::debug!("wasm2wat not available: {}", String::from_utf8_lossy(&result.stderr));
        }
    }

    // Try wasm-decompile for more readable output
    let decompiled_path = output_dir.join("decompiled.dcmp");
    let _ = std::process::Command::new("wasm-decompile")
        .args([path.to_str().unwrap_or(""), "-o", decompiled_path.to_str().unwrap_or("")])
        .output();

    // Extract strings from data sections (always works, no tools needed)
    let strings_path = output_dir.join("strings.txt");
    let strings = extract_wasm_strings(&wasm_bytes);
    let _ = std::fs::write(&strings_path, strings.join("\n"));

    // Extract imports and exports
    let imports_exports_path = output_dir.join("imports_exports.txt");
    let ie = extract_imports_exports(&wasm_bytes);
    let _ = std::fs::write(&imports_exports_path, ie);

    // Copy original for deep analysis
    let copy_path = output_dir.join(path.file_name().unwrap_or_default());
    let _ = std::fs::copy(path, &copy_path);

    Ok(WasmDecompileResult {
        output_dir,
        total_bytes,
        _temp_dir: temp_dir,
    })
}

/// Extract printable strings from WASM data sections
fn extract_wasm_strings(bytes: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = String::new();

    for &byte in bytes {
        if byte >= 0x20 && byte < 0x7F {
            current.push(byte as char);
        } else {
            if current.len() >= 6 {
                strings.push(current.clone());
            }
            current.clear();
        }
    }
    if current.len() >= 6 {
        strings.push(current);
    }

    strings
}

/// Extract import/export function names from WASM binary
fn extract_imports_exports(bytes: &[u8]) -> String {
    let mut result = String::new();
    result.push_str("# WASM Imports and Exports\n\n");

    // Simple WASM parsing — look for the import and export sections
    // WASM section IDs: import=2, export=7
    // This is a simplified parser that just extracts strings

    // Collect all strings that look like function/module names
    let strings = extract_wasm_strings(bytes);
    let import_related: Vec<&String> = strings
        .iter()
        .filter(|s| {
            s.contains("import") || s.contains("export")
            || s.contains("__wasm") || s.contains("__wbg")
            || s.starts_with("env.") || s.starts_with("wasi_")
            || s.contains("emscripten") || s.contains("Go.")
        })
        .collect();

    result.push_str("## Detected module/function names:\n\n");
    for s in &import_related {
        result.push_str(&format!("- {}\n", s));
    }

    // Also look for common toolchain indicators
    result.push_str("\n## Toolchain indicators:\n\n");
    for s in &strings {
        if s.contains("rustc") || s.contains("clang") || s.contains("emcc")
            || s.contains("assemblyscript") || s.contains("tinygo")
            || s.contains("wasm-pack") || s.contains("wasm-bindgen")
        {
            result.push_str(&format!("- {}\n", s));
        }
    }

    result
}

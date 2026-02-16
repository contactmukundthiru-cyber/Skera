//! Binary format handlers — ELF, PE, Mach-O string extraction

use std::path::{Path, PathBuf};

pub struct BinaryExtractResult {
    pub output_dir: PathBuf,
    pub symbols_extracted: usize,
    pub strings_extracted: usize,
    pub total_bytes: u64,
    pub _temp_dir: tempfile::TempDir,
}

/// Extract scannable content from a binary executable
///
/// Dumps strings, symbol tables, and linked library references
/// into text files for the detection pipeline to scan.
pub async fn extract_binary(path: &Path) -> Result<BinaryExtractResult, String> {
    let temp_dir = tempfile::TempDir::new()
        .map_err(|e| format!("Failed to create temp dir: {}", e))?;

    let output_dir = temp_dir.path().join("binary_analysis");
    std::fs::create_dir_all(&output_dir)
        .map_err(|e| format!("Failed to create output dir: {}", e))?;

    let total_bytes = std::fs::metadata(path)
        .map(|m| m.len())
        .unwrap_or(0);

    // Extract printable strings (minimum length 6 to avoid noise)
    let strings_file = output_dir.join("strings.txt");
    let strings_count = extract_strings(path, &strings_file)?;

    // Extract symbols if possible
    let symbols_file = output_dir.join("symbols.txt");
    let symbols_count = extract_symbols(path, &symbols_file);

    // Extract linked library references
    let libs_file = output_dir.join("linked_libraries.txt");
    extract_linked_libs(path, &libs_file);

    // Copy the original binary for deep analysis
    let binary_copy = output_dir.join(
        path.file_name().unwrap_or_default()
    );
    let _ = std::fs::copy(path, &binary_copy);

    Ok(BinaryExtractResult {
        output_dir,
        symbols_extracted: symbols_count,
        strings_extracted: strings_count,
        total_bytes,
        _temp_dir: temp_dir,
    })
}

/// Extract printable strings from a binary
fn extract_strings(path: &Path, output: &Path) -> Result<usize, String> {
    let data = std::fs::read(path)
        .map_err(|e| format!("Failed to read binary: {}", e))?;

    let mut strings = Vec::new();
    let mut current = String::new();

    for &byte in &data {
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

    let count = strings.len();
    let content = strings.join("\n");
    std::fs::write(output, &content)
        .map_err(|e| format!("Failed to write strings: {}", e))?;

    Ok(count)
}

/// Extract symbol table entries
fn extract_symbols(path: &Path, output: &Path) -> usize {
    // Try nm (available on Unix, sometimes on Windows via MSYS2/Git)
    if let Ok(result) = std::process::Command::new("nm")
        .args(["-C", path.to_str().unwrap_or("")]) // -C for demangling
        .output()
    {
        if result.status.success() {
            let symbols = String::from_utf8_lossy(&result.stdout);
            let count = symbols.lines().count();
            let _ = std::fs::write(output, symbols.as_bytes());
            return count;
        }
    }

    // Fallback: try objdump
    if let Ok(result) = std::process::Command::new("objdump")
        .args(["-t", path.to_str().unwrap_or("")])
        .output()
    {
        if result.status.success() {
            let symbols = String::from_utf8_lossy(&result.stdout);
            let count = symbols.lines().count();
            let _ = std::fs::write(output, symbols.as_bytes());
            return count;
        }
    }

    0
}

/// Extract linked library references
fn extract_linked_libs(path: &Path, output: &Path) {
    // Try ldd (Linux)
    if let Ok(result) = std::process::Command::new("ldd")
        .arg(path.to_str().unwrap_or(""))
        .output()
    {
        if result.status.success() {
            let _ = std::fs::write(output, &result.stdout);
            return;
        }
    }

    // Try otool (macOS)
    if let Ok(result) = std::process::Command::new("otool")
        .args(["-L", path.to_str().unwrap_or("")])
        .output()
    {
        if result.status.success() {
            let _ = std::fs::write(output, &result.stdout);
            return;
        }
    }

    // Try dumpbin (Windows MSVC)
    if let Ok(result) = std::process::Command::new("dumpbin")
        .args(["/DEPENDENTS", path.to_str().unwrap_or("")])
        .output()
    {
        if result.status.success() {
            let _ = std::fs::write(output, &result.stdout);
        }
    }
}

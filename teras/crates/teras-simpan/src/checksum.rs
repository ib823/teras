//! BLAKE3 checksum utilities for data integrity verification.
//!
//! Provides checksum calculation and verification for stored data.

use std::path::Path;
use teras_core::error::{TerasError, TerasResult};

/// BLAKE3 hash output size in bytes.
pub const BLAKE3_OUTPUT_SIZE: usize = 32;

/// BLAKE3 hash output size in hex characters.
pub const BLAKE3_HEX_SIZE: usize = 64;

/// Calculate BLAKE3 hash of data.
#[must_use]
pub fn calculate_blake3(data: &[u8]) -> String {
    let hash = blake3::hash(data);
    hash.to_hex().to_string()
}

/// Calculate BLAKE3 hash of data and return raw bytes.
#[must_use]
pub fn calculate_blake3_bytes(data: &[u8]) -> [u8; BLAKE3_OUTPUT_SIZE] {
    *blake3::hash(data).as_bytes()
}

/// Verify data against a BLAKE3 checksum.
#[must_use]
pub fn verify_blake3(data: &[u8], expected: &str) -> bool {
    let actual = calculate_blake3(data);
    // Use constant-time comparison
    constant_time_compare(actual.as_bytes(), expected.as_bytes())
}

/// Verify data against raw BLAKE3 bytes.
#[must_use]
pub fn verify_blake3_bytes(data: &[u8], expected: &[u8; BLAKE3_OUTPUT_SIZE]) -> bool {
    let actual = calculate_blake3_bytes(data);
    constant_time_compare(&actual, expected)
}

/// Constant-time byte comparison.
///
/// Prevents timing attacks during checksum verification.
#[must_use]
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Calculate and write checksum file for given data file.
///
/// # Errors
///
/// Returns error if file operations fail.
pub fn write_checksum_file(data_path: &Path, data: &[u8]) -> TerasResult<()> {
    let checksum = calculate_blake3(data);
    let checksum_path = checksum_path_for(data_path);
    crate::atomic::atomic_write(&checksum_path, checksum.as_bytes())
}

/// Verify a data file against its checksum file.
///
/// # Errors
///
/// Returns error if checksum doesn't match or files can't be read.
pub fn verify_checksum_file(data_path: &Path) -> TerasResult<()> {
    let checksum_path = checksum_path_for(data_path);

    if !checksum_path.exists() {
        return Err(TerasError::StorageCorruption {
            path: data_path.display().to_string(),
            reason: "Checksum file missing".to_string(),
        });
    }

    let data = std::fs::read(data_path).map_err(TerasError::IoError)?;
    let expected = std::fs::read_to_string(&checksum_path).map_err(TerasError::IoError)?;

    if !verify_blake3(&data, expected.trim()) {
        return Err(TerasError::StorageCorruption {
            path: data_path.display().to_string(),
            reason: "Checksum mismatch".to_string(),
        });
    }

    Ok(())
}

/// Get the checksum file path for a data file.
#[must_use]
pub fn checksum_path_for(data_path: &Path) -> std::path::PathBuf {
    let mut path = data_path.to_path_buf();
    let new_ext = format!(
        "{}.blake3",
        path.extension().unwrap_or_default().to_string_lossy()
    );
    path.set_extension(new_ext);
    path
}

/// Checksum a file and return the hash.
///
/// # Errors
///
/// Returns error if file cannot be read.
pub fn checksum_file(path: &Path) -> TerasResult<String> {
    let data = std::fs::read(path).map_err(TerasError::IoError)?;
    Ok(calculate_blake3(&data))
}

/// Checksum multiple files and return a combined hash.
///
/// Useful for creating backup manifests.
///
/// # Errors
///
/// Returns error if any file cannot be read.
pub fn checksum_files(paths: &[&Path]) -> TerasResult<String> {
    let mut hasher = blake3::Hasher::new();

    for path in paths {
        let data = std::fs::read(path).map_err(TerasError::IoError)?;
        hasher.update(&data);
    }

    Ok(hasher.finalize().to_hex().to_string())
}

/// Checksum a directory's contents recursively.
///
/// # Errors
///
/// Returns error if directory cannot be read.
pub fn checksum_directory(dir: &Path) -> TerasResult<String> {
    let mut hasher = blake3::Hasher::new();
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(TerasError::IoError)?
        .filter_map(|e| e.ok())
        .collect();

    // Sort for deterministic ordering
    entries.sort_by_key(|e| e.path());

    for entry in entries {
        let path = entry.path();
        if path.is_file() {
            // Include filename in hash for integrity
            hasher.update(path.file_name().unwrap_or_default().as_encoded_bytes());
            let data = std::fs::read(&path).map_err(TerasError::IoError)?;
            hasher.update(&data);
        } else if path.is_dir() {
            // Recurse into subdirectories
            let subhash = checksum_directory(&path)?;
            hasher.update(subhash.as_bytes());
        }
    }

    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_calculate_blake3() {
        let hash = calculate_blake3(b"hello world");
        assert_eq!(hash.len(), BLAKE3_HEX_SIZE);

        // Known hash for "hello world"
        assert_eq!(
            hash,
            "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"
        );
    }

    #[test]
    fn test_calculate_blake3_bytes() {
        let hash = calculate_blake3_bytes(b"test");
        assert_eq!(hash.len(), BLAKE3_OUTPUT_SIZE);
    }

    #[test]
    fn test_verify_blake3() {
        let data = b"test data";
        let hash = calculate_blake3(data);

        assert!(verify_blake3(data, &hash));
        assert!(!verify_blake3(b"different", &hash));
    }

    #[test]
    fn test_verify_blake3_bytes() {
        let data = b"test data";
        let hash = calculate_blake3_bytes(data);

        assert!(verify_blake3_bytes(data, &hash));
        assert!(!verify_blake3_bytes(b"different", &hash));
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare(b"hello", b"hello"));
        assert!(!constant_time_compare(b"hello", b"world"));
        assert!(!constant_time_compare(b"hello", b"hi"));
    }

    #[test]
    fn test_checksum_path_for() {
        let data_path = Path::new("/some/path/file.identity");
        let checksum = checksum_path_for(data_path);
        assert!(checksum.to_string_lossy().ends_with(".identity.blake3"));
    }

    #[test]
    fn test_write_and_verify_checksum_file() {
        let temp = TempDir::new().unwrap();
        let data_path = temp.path().join("data.bin");
        let data = b"important data";

        // Write data file
        std::fs::write(&data_path, data).unwrap();

        // Write checksum
        write_checksum_file(&data_path, data).unwrap();

        // Verify checksum exists
        let checksum_path = checksum_path_for(&data_path);
        assert!(checksum_path.exists());

        // Verify passes
        verify_checksum_file(&data_path).unwrap();
    }

    #[test]
    fn test_verify_checksum_file_detects_corruption() {
        let temp = TempDir::new().unwrap();
        let data_path = temp.path().join("data.bin");
        let data = b"original data";

        // Write data and checksum
        std::fs::write(&data_path, data).unwrap();
        write_checksum_file(&data_path, data).unwrap();

        // Corrupt the data
        std::fs::write(&data_path, b"corrupted").unwrap();

        // Verification should fail
        let result = verify_checksum_file(&data_path);
        assert!(result.is_err());

        if let Err(TerasError::StorageCorruption { reason, .. }) = result {
            assert!(reason.contains("mismatch"));
        } else {
            panic!("Expected StorageCorruption error");
        }
    }

    #[test]
    fn test_verify_checksum_file_missing() {
        let temp = TempDir::new().unwrap();
        let data_path = temp.path().join("data.bin");

        std::fs::write(&data_path, b"data").unwrap();
        // Don't write checksum file

        let result = verify_checksum_file(&data_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_checksum_file() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("file.txt");
        std::fs::write(&path, b"content").unwrap();

        let hash = checksum_file(&path).unwrap();
        assert_eq!(hash.len(), BLAKE3_HEX_SIZE);
    }

    #[test]
    fn test_checksum_files_multiple() {
        let temp = TempDir::new().unwrap();
        let p1 = temp.path().join("f1.txt");
        let p2 = temp.path().join("f2.txt");

        std::fs::write(&p1, b"file1").unwrap();
        std::fs::write(&p2, b"file2").unwrap();

        let hash = checksum_files(&[&p1, &p2]).unwrap();
        assert_eq!(hash.len(), BLAKE3_HEX_SIZE);

        // Should be deterministic
        let hash2 = checksum_files(&[&p1, &p2]).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_checksum_directory() {
        let temp = TempDir::new().unwrap();

        std::fs::write(temp.path().join("a.txt"), b"aaa").unwrap();
        std::fs::write(temp.path().join("b.txt"), b"bbb").unwrap();

        let hash = checksum_directory(temp.path()).unwrap();
        assert_eq!(hash.len(), BLAKE3_HEX_SIZE);

        // Should be deterministic
        let hash2 = checksum_directory(temp.path()).unwrap();
        assert_eq!(hash, hash2);
    }
}

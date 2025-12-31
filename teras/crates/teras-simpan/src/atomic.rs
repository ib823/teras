//! Atomic file operations for safe storage updates.
//!
//! Ensures data integrity by using write-to-temp-then-rename pattern.
//! This prevents partial writes and data corruption on crash.

use std::path::Path;
use teras_core::error::{TerasError, TerasResult};

/// Atomically write data to a file.
///
/// Uses the write-to-temp-then-rename pattern:
/// 1. Write to a temporary file in the same directory
/// 2. Sync the data to disk
/// 3. Rename to the final path (atomic on POSIX)
///
/// # Errors
///
/// Returns error if any step fails.
pub fn atomic_write(path: &Path, data: &[u8]) -> TerasResult<()> {
    // Create temp file in the same directory for atomic rename
    let parent = path.parent().ok_or_else(|| TerasError::ConfigError {
        message: "Cannot determine parent directory".to_string(),
    })?;

    // Generate unique temp file name
    let temp_name = format!(
        ".{}.tmp.{}",
        path.file_name()
            .map(|s| s.to_string_lossy())
            .unwrap_or_default(),
        std::process::id()
    );
    let temp_path = parent.join(&temp_name);

    // Write to temp file
    std::fs::write(&temp_path, data).map_err(TerasError::IoError)?;

    // Sync to disk
    let file = std::fs::File::open(&temp_path).map_err(TerasError::IoError)?;
    file.sync_all().map_err(TerasError::IoError)?;

    // Atomic rename
    std::fs::rename(&temp_path, path).map_err(|e| {
        // Try to clean up temp file on failure
        let _ = std::fs::remove_file(&temp_path);
        TerasError::IoError(e)
    })?;

    // Sync parent directory (POSIX requirement for durability)
    #[cfg(unix)]
    {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(())
}

/// Atomically write data to a file with checksum.
///
/// Writes both the data file and a companion checksum file atomically.
///
/// # Errors
///
/// Returns error if any step fails.
pub fn atomic_write_with_checksum(path: &Path, data: &[u8]) -> TerasResult<()> {
    // First write the data
    atomic_write(path, data)?;

    // Calculate and write checksum
    let checksum = crate::checksum::calculate_blake3(data);
    let checksum_path =
        crate::path::StoragePaths::new(path.parent().unwrap_or(Path::new(""))).checksum_file(path);

    atomic_write(&checksum_path, checksum.as_bytes())?;

    Ok(())
}

/// Atomically append data to a file.
///
/// For append-only files like audit logs:
/// 1. Read existing content
/// 2. Append new data
/// 3. Atomically write entire file
///
/// Note: This is not efficient for large files. For high-frequency
/// appends, consider using `append_with_lock` instead.
///
/// # Errors
///
/// Returns error if any step fails.
pub fn atomic_append(path: &Path, data: &[u8]) -> TerasResult<()> {
    let existing = if path.exists() {
        std::fs::read(path).map_err(TerasError::IoError)?
    } else {
        Vec::new()
    };

    let mut combined = existing;
    combined.extend_from_slice(data);

    atomic_write(path, &combined)
}

/// Append data to a file with file locking.
///
/// Uses file locking to ensure concurrent appends are safe.
/// More efficient than `atomic_append` for frequent operations.
///
/// # Errors
///
/// Returns error if any step fails.
pub fn append_with_lock(path: &Path, data: &[u8]) -> TerasResult<()> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(TerasError::IoError)?;

    // Platform-specific locking
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        unsafe {
            libc::flock(fd, libc::LOCK_EX);
        }
    }

    file.write_all(data).map_err(TerasError::IoError)?;
    file.sync_all().map_err(TerasError::IoError)?;

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        unsafe {
            libc::flock(fd, libc::LOCK_UN);
        }
    }

    Ok(())
}

/// Atomically delete a file.
///
/// Renames the file to a temporary name first, then removes it.
/// This prevents partial deletes from corrupting directory state.
///
/// # Errors
///
/// Returns error if deletion fails.
pub fn atomic_delete(path: &Path) -> TerasResult<()> {
    if !path.exists() {
        return Ok(());
    }

    let parent = path.parent().ok_or_else(|| TerasError::ConfigError {
        message: "Cannot determine parent directory".to_string(),
    })?;

    // Rename to temp name first
    let temp_name = format!(
        ".deleted.{}.{}",
        path.file_name()
            .map(|s| s.to_string_lossy())
            .unwrap_or_default(),
        std::process::id()
    );
    let temp_path = parent.join(&temp_name);

    std::fs::rename(path, &temp_path).map_err(TerasError::IoError)?;

    // Now delete the renamed file
    std::fs::remove_file(&temp_path).map_err(TerasError::IoError)?;

    Ok(())
}

/// Atomically delete a file and its checksum.
///
/// # Errors
///
/// Returns error if deletion fails.
pub fn atomic_delete_with_checksum(path: &Path) -> TerasResult<()> {
    // Delete checksum first
    let checksum_path =
        crate::path::StoragePaths::new(path.parent().unwrap_or(Path::new(""))).checksum_file(path);

    if checksum_path.exists() {
        atomic_delete(&checksum_path)?;
    }

    // Then delete data file
    atomic_delete(path)
}

/// Safe file copy with verification.
///
/// Copies a file and verifies the copy matches the original.
///
/// # Errors
///
/// Returns error if copy fails or verification fails.
pub fn safe_copy(src: &Path, dst: &Path) -> TerasResult<()> {
    let data = std::fs::read(src).map_err(TerasError::IoError)?;
    atomic_write(dst, &data)?;

    // Verify
    let written = std::fs::read(dst).map_err(TerasError::IoError)?;
    if data != written {
        atomic_delete(dst)?;
        return Err(TerasError::StorageCorruption {
            path: dst.display().to_string(),
            reason: "Copy verification failed".to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_atomic_write() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("test.dat");

        atomic_write(&path, b"test data").unwrap();

        let content = std::fs::read(&path).unwrap();
        assert_eq!(content, b"test data");
    }

    #[test]
    fn test_atomic_write_overwrites() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("test.dat");

        atomic_write(&path, b"original").unwrap();
        atomic_write(&path, b"updated").unwrap();

        let content = std::fs::read(&path).unwrap();
        assert_eq!(content, b"updated");
    }

    #[test]
    fn test_atomic_append() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("append.dat");

        atomic_append(&path, b"line1\n").unwrap();
        atomic_append(&path, b"line2\n").unwrap();

        let content = std::fs::read(&path).unwrap();
        assert_eq!(content, b"line1\nline2\n");
    }

    #[test]
    fn test_append_with_lock() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("locked.dat");

        append_with_lock(&path, b"line1\n").unwrap();
        append_with_lock(&path, b"line2\n").unwrap();

        let content = std::fs::read(&path).unwrap();
        assert_eq!(content, b"line1\nline2\n");
    }

    #[test]
    fn test_atomic_delete() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("delete.dat");

        std::fs::write(&path, b"data").unwrap();
        assert!(path.exists());

        atomic_delete(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn test_atomic_delete_nonexistent() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("nonexistent.dat");

        // Should not error
        atomic_delete(&path).unwrap();
    }

    #[test]
    fn test_safe_copy() {
        let temp = TempDir::new().unwrap();
        let src = temp.path().join("src.dat");
        let dst = temp.path().join("dst.dat");

        std::fs::write(&src, b"copy me").unwrap();

        safe_copy(&src, &dst).unwrap();

        let content = std::fs::read(&dst).unwrap();
        assert_eq!(content, b"copy me");
    }

    #[test]
    fn test_no_leftover_temp_files() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("test.dat");

        atomic_write(&path, b"data").unwrap();

        // Check no temp files remain
        let entries: Vec<_> = std::fs::read_dir(temp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with('.'))
            .collect();

        assert!(entries.is_empty(), "Temp files should be cleaned up");
    }
}

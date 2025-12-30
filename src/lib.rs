#![allow(clippy::useless_conversion)]

use ::path_jail::{Jail as RustJail, JailError};
use pyo3::exceptions::{PyIOError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyString;
use std::path::PathBuf;

/// Maximum path length before we keep the \\?\ prefix on Windows.
/// Windows MAX_PATH is 260, but we use 250 to leave room for filenames.
#[cfg(windows)]
const LONG_PATH_THRESHOLD: usize = 250;

/// Normalize a path for user-friendly output at the Python boundary.
/// On Windows, converts extended-length paths to standard format:
/// - \\?\C:\path → C:\path
/// - \\?\UNC\server\share → \\server\share
///
/// For paths longer than 250 characters, keeps the \\?\ prefix to
/// maintain long path support on Windows.
///
/// Note: This is only for Python-facing output. Internal Rust logic
/// should use the original PathBuf to preserve starts_with consistency.
fn normalize_path(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        let s = path.to_string_lossy();

        // Handle UNC paths: \\?\UNC\server\share → \\server\share
        if let Some(stripped) = s.strip_prefix(r"\\?\UNC\") {
            let normalized = format!(r"\\{}", stripped);
            // Keep prefix for long paths
            if normalized.len() > LONG_PATH_THRESHOLD {
                return path;
            }
            return PathBuf::from(normalized);
        }

        // Handle regular paths: \\?\C:\path → C:\path
        if let Some(stripped) = s.strip_prefix(r"\\?\") {
            // Keep prefix for long paths
            if stripped.len() > LONG_PATH_THRESHOLD {
                return path;
            }
            return PathBuf::from(stripped);
        }
    }
    path
}

/// Convert a PathBuf to a String for Python.
/// Uses lossy conversion which replaces invalid UTF-8 with replacement character.
fn path_to_string(path: PathBuf) -> String {
    path.to_string_lossy().into_owned()
}

/// Extract a path from a Python object (str or os.PathLike).
///
/// Rejects paths containing null bytes. While Python's open() would also reject them,
/// we catch it early to provide a clear error and prevent any downstream issues
/// with C libraries that might truncate at the null byte.
fn extract_path(obj: &Bound<'_, PyAny>) -> PyResult<PathBuf> {
    // Helper to validate and convert string to PathBuf
    fn validate_path(s: &str) -> PyResult<PathBuf> {
        if s.contains('\0') {
            return Err(PyValueError::new_err(
                "path contains null byte (security risk)",
            ));
        }
        Ok(PathBuf::from(s))
    }

    // Try str first
    if let Ok(s) = obj.downcast::<PyString>() {
        return validate_path(&s.to_cow()?);
    }

    // Try os.PathLike via __fspath__
    if let Ok(fspath) = obj.call_method0("__fspath__") {
        if let Ok(s) = fspath.downcast::<PyString>() {
            return validate_path(&s.to_cow()?);
        }
        // Could be bytes, but we only support str paths
        if let Ok(s) = fspath.extract::<String>() {
            return validate_path(&s);
        }
    }

    Err(PyTypeError::new_err("expected str or os.PathLike object"))
}

/// Convert JailError to Python exception
fn to_py_err(err: JailError) -> PyErr {
    match err {
        JailError::EscapedRoot { attempted, root } => PyValueError::new_err(format!(
            "path '{}' escapes jail root '{}'",
            attempted.display(),
            root.display()
        )),
        JailError::BrokenSymlink(path) => PyValueError::new_err(format!(
            "broken symlink at '{}' (cannot verify target)",
            path.display()
        )),
        JailError::InvalidPath(reason) => {
            PyValueError::new_err(format!("invalid path: {}", reason))
        }
        JailError::Io(err) => PyIOError::new_err(err.to_string()),
        // Handle future error variants from path_jail crate
        _ => PyValueError::new_err(format!("path_jail error: {}", err)),
    }
}

/// A filesystem sandbox that restricts paths to a root directory.
///
/// Example:
///     >>> jail = Jail("/var/uploads")
///     >>> safe_path = jail.join("user/file.txt")
///     >>> jail.join("../../etc/passwd")  # Raises ValueError
#[pyclass]
struct Jail {
    inner: RustJail,
}

#[pymethods]
impl Jail {
    /// Create a jail rooted at the given directory.
    ///
    /// Args:
    ///     root: Path to the jail root directory (must exist)
    ///
    /// Raises:
    ///     IOError: If root does not exist or is not a directory
    #[new]
    fn new(root: &Bound<'_, PyAny>) -> PyResult<Self> {
        let path = extract_path(root)?;
        let inner = RustJail::new(&path).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Returns the canonicalized root path.
    #[getter]
    fn root(&self) -> String {
        path_to_string(normalize_path(self.inner.root().to_owned()))
    }

    /// Safely join a relative path to the jail root.
    ///
    /// Args:
    ///     path: Relative path to join
    ///
    /// Returns:
    ///     Absolute path inside the jail
    ///
    /// Raises:
    ///     ValueError: If path would escape the jail or is absolute
    fn join(&self, path: &Bound<'_, PyAny>) -> PyResult<String> {
        let path = extract_path(path)?;
        self.inner
            .join(&path)
            .map(normalize_path)
            .map(path_to_string)
            .map_err(to_py_err)
    }

    /// Verify an absolute path is inside the jail.
    ///
    /// Args:
    ///     path: Absolute path to verify (must exist)
    ///
    /// Returns:
    ///     Canonicalized path if inside the jail
    ///
    /// Raises:
    ///     ValueError: If path is outside the jail or not absolute
    fn contains(&self, path: &Bound<'_, PyAny>) -> PyResult<String> {
        let path = extract_path(path)?;
        self.inner
            .contains(&path)
            .map(normalize_path)
            .map(path_to_string)
            .map_err(to_py_err)
    }

    /// Get the relative path from an absolute path inside the jail.
    ///
    /// Args:
    ///     path: Absolute path inside the jail (must exist)
    ///
    /// Returns:
    ///     Relative path from the jail root
    ///
    /// Raises:
    ///     ValueError: If path is outside the jail
    fn relative(&self, path: &Bound<'_, PyAny>) -> PyResult<String> {
        let path = extract_path(path)?;
        self.inner
            .relative(&path)
            .map(normalize_path)
            .map(path_to_string)
            .map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        format!(
            "Jail('{}')",
            normalize_path(self.inner.root().to_owned()).display()
        )
    }

    fn __str__(&self) -> String {
        normalize_path(self.inner.root().to_owned())
            .to_string_lossy()
            .into_owned()
    }
}

/// One-shot path validation.
///
/// This is a convenience function for validating a single path.
/// For multiple paths, create a Jail and reuse it.
///
/// Args:
///     root: Path to the jail root directory (must exist)
///     path: Relative path to validate and join
///
/// Returns:
///     Absolute path inside the jail
///
/// Raises:
///     ValueError: If path would escape the jail
///     IOError: If root does not exist
///
/// Example:
///     >>> from path_jail import join
///     >>> safe = join("/var/uploads", "user/file.txt")
///     >>> join("/var/uploads", "../../etc/passwd")  # Raises ValueError
#[pyfunction]
fn join(root: &Bound<'_, PyAny>, path: &Bound<'_, PyAny>) -> PyResult<String> {
    let root = extract_path(root)?;
    let path = extract_path(path)?;
    ::path_jail::join(&root, &path)
        .map(normalize_path)
        .map(path_to_string)
        .map_err(to_py_err)
}

/// Secure filesystem sandbox for Python.
///
/// Restricts paths to a root directory, preventing traversal attacks
/// while supporting files that don't exist yet.
///
/// Example:
///     >>> from path_jail import Jail, join
///     >>>
///     >>> # One-shot validation
///     >>> safe = join("/var/uploads", "user/file.txt")
///     >>>
///     >>> # Reusable jail
///     >>> jail = Jail("/var/uploads")
///     >>> path = jail.join("report.pdf")
#[pymodule]
fn path_jail(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Jail>()?;
    m.add_function(wrap_pyfunction!(join, m)?)?;
    Ok(())
}

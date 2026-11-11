#![allow(clippy::useless_conversion)]

#[cfg(unix)]
use ::path_jail::guard::{Attestation as RustAttestation, FdJail as RustFdJail, OpenOptions};
use ::path_jail::{Jail as RustJail, JailError};
use pyo3::exceptions::{PyNotImplementedError, PyOSError, PyTypeError, PyValueError};
use pyo3::prelude::*;
#[cfg(unix)]
use pyo3::types::PyDict;
use pyo3::types::{PyString, PyTuple};
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::os::fd::IntoRawFd;
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
    if let Ok(s) = obj.cast::<PyString>() {
        return validate_path(&s.to_cow()?);
    }

    // Try os.PathLike via __fspath__
    if let Ok(fspath) = obj.call_method0("__fspath__") {
        if let Ok(s) = fspath.cast::<PyString>() {
            return validate_path(&s.to_cow()?);
        }
        // Could be bytes, but we only support str paths
        if let Ok(s) = fspath.extract::<String>() {
            return validate_path(&s);
        }
    }

    Err(PyTypeError::new_err("expected str or os.PathLike object"))
}

/// Extract path segments as UTF-8 strings for `Jail::join_segments`.
fn extract_segments(parts: &Bound<'_, PyTuple>) -> PyResult<Vec<String>> {
    parts
        .iter()
        .map(|part| {
            let path = extract_path(&part)?;
            path.into_os_string()
                .into_string()
                .map_err(|_| PyValueError::new_err("path segment is not valid Unicode"))
        })
        .collect()
}

/// Convert an OS error without discarding its numeric error code.
fn io_error_to_py(err: std::io::Error) -> PyErr {
    let message = err.to_string();
    match err.raw_os_error() {
        #[cfg(windows)]
        Some(code) => PyOSError::new_err((0, message, Option::<String>::None, code)),
        #[cfg(not(windows))]
        Some(code) => PyOSError::new_err((code, message)),
        None => err.into(),
    }
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
        // Filesystem root or non-directory. (A missing root surfaces as Io.)
        err @ JailError::InvalidRoot { .. } => PyValueError::new_err(err.to_string()),
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        err @ JailError::UnsupportedKernel { .. } => {
            PyNotImplementedError::new_err(err.to_string())
        }
        JailError::Io(err) => io_error_to_py(err),
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
    ///     ValueError: If root is a filesystem root or not a directory
    ///     OSError: If root does not exist or cannot be read
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
    ///     OSError: If an existing path component cannot be inspected
    ///         (e.g. permission denied)
    fn join(&self, path: &Bound<'_, PyAny>) -> PyResult<String> {
        let path = extract_path(path)?;
        self.inner
            .join(&path)
            .map(normalize_path)
            .map(path_to_string)
            .map_err(to_py_err)
    }

    /// Join separately supplied path components beneath the jail root.
    ///
    /// Each non-empty part must be one component. Separators, `..`, and null
    /// bytes are rejected before the path is joined.
    #[pyo3(signature = (*parts))]
    fn join_segments(&self, parts: &Bound<'_, PyTuple>) -> PyResult<String> {
        let parts = extract_segments(parts)?;
        self.inner
            .join_segments(&parts)
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
    ///     OSError: If the path cannot be inspected
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
    ///     OSError: If the path cannot be inspected
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

/// Guarantees and operations provided by the active guarded backend.
#[pyclass(name = "GuardCapabilities", frozen)]
#[derive(Clone)]
struct PyGuardCapabilities {
    #[pyo3(get)]
    toctou_safe: bool,
    #[pyo3(get)]
    directory_operations: bool,
    #[pyo3(get)]
    no_symlinks: bool,
    #[pyo3(get)]
    no_xdev: bool,
}

/// Metadata captured from the exact file handle returned by a guarded open.
#[pyclass(name = "Attestation", frozen)]
#[derive(Clone)]
struct PyAttestation {
    #[pyo3(get)]
    jail_root: String,
    #[pyo3(get)]
    opened_path: String,
    #[pyo3(get)]
    root_inode: u64,
    #[pyo3(get)]
    file_inode: u64,
    #[pyo3(get)]
    device: u64,
    #[pyo3(get)]
    nlink: u64,
    #[pyo3(get)]
    toctou_safe: bool,
    #[pyo3(get)]
    opened_at_ns: u64,
    #[pyo3(get)]
    signature: Option<Vec<u8>>,
}

#[cfg(unix)]
impl From<&RustAttestation> for PyAttestation {
    fn from(value: &RustAttestation) -> Self {
        let opened_at_ns = value
            .opened_at
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        Self {
            jail_root: path_to_string(normalize_path(value.jail_root.clone())),
            opened_path: path_to_string(value.opened_path.clone()),
            root_inode: value.root_inode,
            file_inode: value.file_inode,
            device: value.device,
            nlink: value.nlink,
            toctou_safe: value.toctou_safe,
            opened_at_ns,
            signature: value.signature.map(|signature| signature.to_vec()),
        }
    }
}

#[cfg(unix)]
#[derive(Clone, Copy)]
struct ParsedMode {
    base: char,
    binary: bool,
    update: bool,
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
}

#[cfg(unix)]
fn parse_mode(mode: &str) -> PyResult<ParsedMode> {
    let base_modes = mode
        .chars()
        .filter(|character| matches!(character, 'r' | 'w' | 'a' | 'x'))
        .collect::<Vec<_>>();
    let plus_count = mode.chars().filter(|character| *character == '+').count();
    let binary_count = mode.chars().filter(|character| *character == 'b').count();
    let text_count = mode.chars().filter(|character| *character == 't').count();
    let valid_characters = mode
        .chars()
        .all(|character| matches!(character, 'r' | 'w' | 'a' | 'x' | 'b' | 't' | '+'));

    if !valid_characters
        || base_modes.len() != 1
        || plus_count > 1
        || binary_count > 1
        || text_count > 1
        || (binary_count == 1 && text_count == 1)
    {
        return Err(PyValueError::new_err(format!(
            "invalid file mode: '{mode}'"
        )));
    }

    let update = plus_count == 1;
    let binary = binary_count == 1;
    Ok(match base_modes[0] {
        'r' => ParsedMode {
            base: 'r',
            binary,
            update,
            read: true,
            write: update,
            append: false,
            truncate: false,
            create: false,
            create_new: false,
        },
        'w' => ParsedMode {
            base: 'w',
            binary,
            update,
            read: update,
            write: true,
            append: false,
            truncate: true,
            create: true,
            create_new: false,
        },
        'a' => ParsedMode {
            base: 'a',
            binary,
            update,
            read: update,
            write: false,
            append: true,
            truncate: false,
            create: true,
            create_new: false,
        },
        'x' => ParsedMode {
            base: 'x',
            binary,
            update,
            read: update,
            write: true,
            append: false,
            truncate: false,
            create: false,
            create_new: true,
        },
        _ => unreachable!(),
    })
}

#[cfg(unix)]
fn file_to_python(
    py: Python<'_>,
    file: File,
    mode: ParsedMode,
    requested_mode: &str,
) -> PyResult<Py<PyAny>> {
    let io = py.import("io")?;
    let file_io = io.getattr("FileIO")?;
    let buffered_type = if mode.update {
        io.getattr("BufferedRandom")?
    } else if mode.read {
        io.getattr("BufferedReader")?
    } else {
        io.getattr("BufferedWriter")?
    };
    let text_io_wrapper = if mode.binary {
        None
    } else {
        Some(io.getattr("TextIOWrapper")?)
    };
    let kwargs = PyDict::new(py);
    kwargs.set_item("closefd", true)?;

    let raw_mode = format!("{}b{}", mode.base, if mode.update { "+" } else { "" });
    let raw_fd = file.into_raw_fd();
    // FileIO is the single ownership handoff. If a buffered or text wrapper
    // fails, dropping `raw` closes the descriptor exactly once.
    let raw = file_io.call((raw_fd, raw_mode), Some(&kwargs))?;
    let buffered = buffered_type.call1((raw,))?;
    match text_io_wrapper {
        Some(wrapper) => {
            let text = wrapper.call1((buffered,))?;
            text.setattr("mode", requested_mode)?;
            Ok(text.unbind())
        }
        None => Ok(buffered.unbind()),
    }
}

#[cfg(unix)]
#[pyclass(name = "FdJail")]
struct PyFdJail {
    inner: RustFdJail,
}

#[cfg(unix)]
impl PyFdJail {
    #[allow(clippy::too_many_arguments)]
    fn options(
        &self,
        mode: &str,
        require_regular_file: bool,
        reject_hard_links: bool,
        no_symlinks: bool,
        no_xdev: bool,
    ) -> PyResult<(ParsedMode, OpenOptions)> {
        let parsed = parse_mode(mode)?;
        let capabilities = self.inner.capabilities();
        if no_symlinks && !capabilities.no_symlinks {
            return Err(PyNotImplementedError::new_err(
                "no_symlinks is not supported by the active guarded backend",
            ));
        }
        if no_xdev && !capabilities.no_xdev {
            return Err(PyNotImplementedError::new_err(
                "no_xdev is not supported by the active guarded backend",
            ));
        }
        let options = OpenOptions::new()
            .read(parsed.read)
            .write(parsed.write)
            .append(parsed.append)
            .truncate(parsed.truncate)
            .create(parsed.create)
            .create_new(parsed.create_new)
            .require_regular_file(require_regular_file)
            .reject_hard_links(reject_hard_links)
            .no_symlinks(no_symlinks)
            .no_xdev(no_xdev);
        Ok((parsed, options))
    }

    fn open_guarded(
        &self,
        path: PathBuf,
        options: OpenOptions,
    ) -> Result<(File, PyAttestation), JailError> {
        let guarded = self.inner.open(path, options)?;
        let attestation = PyAttestation::from(guarded.attestation());
        Ok((guarded.into_file(), attestation))
    }

    fn require_directory_operations(&self) -> PyResult<()> {
        if self.inner.capabilities().directory_operations {
            Ok(())
        } else {
            Err(PyNotImplementedError::new_err(
                "guarded directory mutations require Linux x86_64/aarch64",
            ))
        }
    }
}

#[cfg(unix)]
#[pymethods]
impl PyFdJail {
    #[new]
    fn new(root: &Bound<'_, PyAny>) -> PyResult<Self> {
        let root = extract_path(root)?;
        let inner = RustFdJail::new(root).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    #[getter]
    fn root(&self) -> String {
        path_to_string(normalize_path(self.inner.root().to_owned()))
    }

    fn capabilities(&self) -> PyGuardCapabilities {
        let capabilities = self.inner.capabilities();
        PyGuardCapabilities {
            toctou_safe: capabilities.toctou_safe,
            directory_operations: capabilities.directory_operations,
            no_symlinks: capabilities.no_symlinks,
            no_xdev: capabilities.no_xdev,
        }
    }

    #[pyo3(signature = (path, mode = "r", *, require_regular_file = false, reject_hard_links = false, no_symlinks = false, no_xdev = false))]
    #[allow(clippy::too_many_arguments)]
    fn open(
        &self,
        py: Python<'_>,
        path: &Bound<'_, PyAny>,
        mode: &str,
        require_regular_file: bool,
        reject_hard_links: bool,
        no_symlinks: bool,
        no_xdev: bool,
    ) -> PyResult<Py<PyAny>> {
        let path = extract_path(path)?;
        let (parsed, options) = self.options(
            mode,
            require_regular_file,
            reject_hard_links,
            no_symlinks,
            no_xdev,
        )?;
        let (file, _) = py
            .detach(|| self.open_guarded(path, options))
            .map_err(to_py_err)?;
        file_to_python(py, file, parsed, mode)
    }

    #[pyo3(signature = (path, mode = "r", *, require_regular_file = false, reject_hard_links = false, no_symlinks = false, no_xdev = false))]
    #[allow(clippy::too_many_arguments)]
    fn open_with_attestation(
        &self,
        py: Python<'_>,
        path: &Bound<'_, PyAny>,
        mode: &str,
        require_regular_file: bool,
        reject_hard_links: bool,
        no_symlinks: bool,
        no_xdev: bool,
    ) -> PyResult<(Py<PyAny>, PyAttestation)> {
        let path = extract_path(path)?;
        let (parsed, options) = self.options(
            mode,
            require_regular_file,
            reject_hard_links,
            no_symlinks,
            no_xdev,
        )?;
        let (file, attestation) = py
            .detach(|| self.open_guarded(path, options))
            .map_err(to_py_err)?;
        Ok((file_to_python(py, file, parsed, mode)?, attestation))
    }

    #[pyo3(signature = (path, *, require_regular_file = false, reject_hard_links = false, no_symlinks = false, no_xdev = false))]
    fn create(
        &self,
        py: Python<'_>,
        path: &Bound<'_, PyAny>,
        require_regular_file: bool,
        reject_hard_links: bool,
        no_symlinks: bool,
        no_xdev: bool,
    ) -> PyResult<Py<PyAny>> {
        self.open(
            py,
            path,
            "xb",
            require_regular_file,
            reject_hard_links,
            no_symlinks,
            no_xdev,
        )
    }

    fn create_dir(&self, path: &Bound<'_, PyAny>) -> PyResult<()> {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            self.require_directory_operations()?;
            let path = extract_path(path)?;
            self.inner.create_dir(path).map_err(to_py_err)
        }
        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        {
            let _ = path;
            self.require_directory_operations()
        }
    }

    fn remove_file(&self, path: &Bound<'_, PyAny>) -> PyResult<()> {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            self.require_directory_operations()?;
            let path = extract_path(path)?;
            self.inner.remove_file(path).map_err(to_py_err)
        }
        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        {
            let _ = path;
            self.require_directory_operations()
        }
    }

    fn remove_dir(&self, path: &Bound<'_, PyAny>) -> PyResult<()> {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            self.require_directory_operations()?;
            let path = extract_path(path)?;
            self.inner.remove_dir(path).map_err(to_py_err)
        }
        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        {
            let _ = path;
            self.require_directory_operations()
        }
    }

    fn rename(&self, source: &Bound<'_, PyAny>, destination: &Bound<'_, PyAny>) -> PyResult<()> {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            self.require_directory_operations()?;
            let source = extract_path(source)?;
            let destination = extract_path(destination)?;
            self.inner.rename(source, destination).map_err(to_py_err)
        }
        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        {
            let _ = (source, destination);
            self.require_directory_operations()
        }
    }

    fn __repr__(&self) -> String {
        format!("FdJail('{}')", self.inner.root().display())
    }
}

#[cfg(windows)]
#[pyclass(name = "FdJail")]
struct PyFdJail;

#[cfg(windows)]
#[pymethods]
impl PyFdJail {
    #[new]
    fn new(root: &Bound<'_, PyAny>) -> PyResult<Self> {
        let _ = root;
        Err(PyNotImplementedError::new_err(
            "FdJail is available on Unix platforms only",
        ))
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
///     ValueError: If path would escape the jail, or root is not a directory
///     OSError: If root does not exist, or a path component cannot be inspected
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
    m.add_class::<PyFdJail>()?;
    m.add_class::<PyGuardCapabilities>()?;
    m.add_class::<PyAttestation>()?;
    m.add_function(wrap_pyfunction!(join, m)?)?;
    Ok(())
}

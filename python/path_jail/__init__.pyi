"""Type stubs for path_jail."""

from os import PathLike
from typing import IO, Any, BinaryIO

__version__: str

_PathLike = str | PathLike[str]

class Jail:
    """A filesystem sandbox that restricts paths to a root directory.

    All returned paths are canonicalized (symlinks resolved, '..' eliminated).

    Note:
        On Windows, returns standard paths (e.g. ``C:\\...``) when possible.
        For paths exceeding Windows limits (>250 chars), the ``\\\\?\\`` prefix
        is preserved to ensure OS compatibility. Avoid regex patterns like
        ``^C:\\\\`` that assume a specific format.
    """

    def __init__(self, root: _PathLike) -> None:
        """Create a jail rooted at the given directory.

        Args:
            root: Path to the jail root directory (must exist)

        Raises:
            ValueError: If root is a filesystem root or not a directory
            OSError: If root does not exist or cannot be read
        """
        ...

    @property
    def root(self) -> str:
        """Returns the canonicalized root path.

        Note:
            On Windows, may include ``\\\\?\\`` prefix for long paths.
        """
        ...

    def join(self, path: _PathLike) -> str:
        """Safely join a relative path to the jail root.

        Args:
            path: Relative path to join

        Returns:
            Absolute path inside the jail. On Windows, may include ``\\\\?\\``
            prefix for paths exceeding 250 characters.

        Raises:
            ValueError: If path would escape the jail or is absolute
            OSError: If an existing path component cannot be inspected
                (e.g. permission denied)
        """
        ...

    def join_segments(self, *parts: _PathLike) -> str:
        """Join separately validated path components beneath the jail root.

        Empty parts are skipped. Separators, ``..``, and null bytes are rejected.
        """
        ...

    def contains(self, path: _PathLike) -> str:
        """Verify an absolute path is inside the jail.

        Args:
            path: Absolute path to verify (must exist)

        Returns:
            Canonicalized path if inside the jail. On Windows, may include
            ``\\\\?\\`` prefix for paths exceeding 250 characters.

        Raises:
            ValueError: If path is outside the jail or not absolute
            OSError: If the path cannot be inspected
        """
        ...

    def relative(self, path: _PathLike) -> str:
        """Get the relative path from an absolute path inside the jail.

        Args:
            path: Absolute path inside the jail (must exist)

        Returns:
            Relative path from the jail root

        Raises:
            ValueError: If path is outside the jail
            OSError: If the path cannot be inspected
        """
        ...

    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

class GuardCapabilities:
    """Guarantees and operations provided by the active guarded backend."""

    @property
    def toctou_safe(self) -> bool: ...
    @property
    def directory_operations(self) -> bool: ...
    @property
    def no_symlinks(self) -> bool: ...
    @property
    def no_xdev(self) -> bool: ...

class Attestation:
    """Metadata captured from the exact handle returned by a guarded open."""

    @property
    def jail_root(self) -> str: ...
    @property
    def opened_path(self) -> str: ...
    @property
    def root_inode(self) -> int: ...
    @property
    def file_inode(self) -> int: ...
    @property
    def device(self) -> int: ...
    @property
    def nlink(self) -> int: ...
    @property
    def toctou_safe(self) -> bool: ...
    @property
    def opened_at_ns(self) -> int: ...
    @property
    def signature(self) -> bytes | None: ...

class FdJail:
    """Descriptor-based jail for guarded file operations on Unix."""

    def __init__(self, root: _PathLike) -> None: ...
    @property
    def root(self) -> str: ...
    def capabilities(self) -> GuardCapabilities: ...
    def open(
        self,
        path: _PathLike,
        mode: str = "r",
        *,
        require_regular_file: bool = False,
        reject_hard_links: bool = False,
        no_symlinks: bool = False,
        no_xdev: bool = False,
    ) -> IO[Any]: ...
    def open_with_attestation(
        self,
        path: _PathLike,
        mode: str = "r",
        *,
        require_regular_file: bool = False,
        reject_hard_links: bool = False,
        no_symlinks: bool = False,
        no_xdev: bool = False,
    ) -> tuple[IO[Any], Attestation]: ...
    def create(
        self,
        path: _PathLike,
        *,
        require_regular_file: bool = False,
        reject_hard_links: bool = False,
        no_symlinks: bool = False,
        no_xdev: bool = False,
    ) -> BinaryIO: ...
    def create_dir(self, path: _PathLike) -> None: ...
    def remove_file(self, path: _PathLike) -> None: ...
    def remove_dir(self, path: _PathLike) -> None: ...
    def rename(self, source: _PathLike, destination: _PathLike) -> None: ...
    def __repr__(self) -> str: ...

def join(root: _PathLike, path: _PathLike) -> str:
    """One-shot path validation.

    This is a convenience function for validating a single path.
    For multiple paths, create a Jail and reuse it.

    Args:
        root: Path to the jail root directory (must exist)
        path: Relative path to validate and join

    Returns:
        Absolute path inside the jail. On Windows, may include ``\\\\?\\``
        prefix for paths exceeding 250 characters.

    Raises:
        ValueError: If path would escape the jail, or root is not a directory
        OSError: If root does not exist, or a path component cannot be inspected

    Note:
        On Windows, returns standard paths (e.g. ``C:\\...``) when possible.
        For paths exceeding Windows limits (>250 chars), the ``\\\\?\\`` prefix
        is preserved to ensure OS compatibility.
    """
    ...

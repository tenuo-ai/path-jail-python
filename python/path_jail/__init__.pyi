"""Type stubs for path_jail."""

from os import PathLike

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
            OSError: If root does not exist or is not a directory
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
        """
        ...

    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

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
        ValueError: If path would escape the jail
        OSError: If root does not exist

    Note:
        On Windows, returns standard paths (e.g. ``C:\\...``) when possible.
        For paths exceeding Windows limits (>250 chars), the ``\\\\?\\`` prefix
        is preserved to ensure OS compatibility.
    """
    ...

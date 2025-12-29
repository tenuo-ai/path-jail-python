from os import PathLike
from typing import Union

StrOrPath = Union[str, PathLike[str]]

class Jail:
    """A filesystem sandbox that restricts paths to a root directory.
    
    All returned paths are canonicalized (symlinks resolved). On macOS,
    this means /var paths become /private/var.
    """

    def __init__(self, root: StrOrPath) -> None:
        """Create a jail rooted at the given directory.

        Args:
            root: Path to the jail root directory (must exist).
                  Will be canonicalized.

        Raises:
            IOError: If root does not exist or is not a directory
        """
        ...

    @property
    def root(self) -> str:
        """Returns the canonicalized root path."""
        ...

    def join(self, path: StrOrPath) -> str:
        """Safely join a relative path to the jail root.

        Args:
            path: Relative path to join

        Returns:
            Canonicalized absolute path inside the jail

        Raises:
            ValueError: If path would escape the jail or is absolute
        """
        ...

    def contains(self, path: StrOrPath) -> str:
        """Verify an absolute path is inside the jail.

        Args:
            path: Absolute path to verify (must exist)

        Returns:
            Canonicalized path if inside the jail

        Raises:
            ValueError: If path is outside the jail or not absolute
        """
        ...

    def relative(self, path: StrOrPath) -> str:
        """Get the relative path from an absolute path inside the jail.

        Args:
            path: Absolute path inside the jail (must exist)

        Returns:
            Relative path from the jail root

        Raises:
            ValueError: If path is outside the jail
        """
        ...

def join(root: StrOrPath, path: StrOrPath) -> str:
    """One-shot path validation.

    This is a convenience function for validating a single path.
    For multiple paths, create a Jail and reuse it.

    Args:
        root: Path to the jail root directory (must exist)
        path: Relative path to validate and join

    Returns:
        Canonicalized absolute path inside the jail

    Raises:
        ValueError: If path would escape the jail
        IOError: If root does not exist
    """
    ...


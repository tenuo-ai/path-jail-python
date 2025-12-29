import os
import tempfile
from pathlib import Path

import pytest
from path_jail import Jail, join


@pytest.fixture
def jail_dir():
    """Create a temporary directory for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


class TestJail:
    def test_create_jail(self, jail_dir):
        jail = Jail(jail_dir)
        assert jail.root == os.path.realpath(jail_dir)

    def test_create_jail_pathlike(self, jail_dir):
        jail = Jail(Path(jail_dir))
        assert jail.root == os.path.realpath(jail_dir)

    def test_create_jail_nonexistent(self):
        with pytest.raises(IOError):
            Jail("/nonexistent/path")

    def test_join_simple(self, jail_dir):
        jail = Jail(jail_dir)
        result = jail.join("file.txt")
        assert result == os.path.join(jail.root, "file.txt")

    def test_join_nested(self, jail_dir):
        jail = Jail(jail_dir)
        result = jail.join("subdir/file.txt")
        assert result == os.path.join(jail.root, "subdir", "file.txt")

    def test_join_pathlike(self, jail_dir):
        jail = Jail(jail_dir)
        result = jail.join(Path("subdir") / "file.txt")
        assert result == os.path.join(jail.root, "subdir", "file.txt")

    def test_join_blocks_traversal(self, jail_dir):
        jail = Jail(jail_dir)
        with pytest.raises(ValueError, match="escapes"):
            jail.join("../etc/passwd")

    def test_join_blocks_deep_traversal(self, jail_dir):
        jail = Jail(jail_dir)
        with pytest.raises(ValueError, match="escapes"):
            jail.join("foo/../../etc/passwd")

    def test_join_blocks_absolute(self, jail_dir):
        jail = Jail(jail_dir)
        with pytest.raises(ValueError):
            jail.join("/etc/passwd")

    def test_contains_valid(self, jail_dir):
        jail = Jail(jail_dir)
        # Create a file inside the jail
        test_file = os.path.join(jail_dir, "test.txt")
        Path(test_file).touch()

        result = jail.contains(test_file)
        # Compare canonicalized paths (handles /var -> /private/var on macOS)
        assert result == os.path.realpath(test_file)

    def test_contains_outside(self, jail_dir):
        jail = Jail(jail_dir)
        with pytest.raises(ValueError, match="escapes"):
            jail.contains("/etc/passwd")

    def test_relative(self, jail_dir):
        jail = Jail(jail_dir)
        test_file = os.path.join(jail_dir, "subdir", "file.txt")
        os.makedirs(os.path.dirname(test_file), exist_ok=True)
        Path(test_file).touch()

        result = jail.relative(test_file)
        assert result == os.path.join("subdir", "file.txt")

    def test_repr(self, jail_dir):
        jail = Jail(jail_dir)
        assert "Jail(" in repr(jail)
        assert jail_dir in repr(jail) or os.path.realpath(jail_dir) in repr(jail)

    def test_str(self, jail_dir):
        jail = Jail(jail_dir)
        assert str(jail) == jail.root


class TestJoinFunction:
    def test_join_simple(self, jail_dir):
        result = join(jail_dir, "file.txt")
        expected = os.path.join(os.path.realpath(jail_dir), "file.txt")
        assert result == expected

    def test_join_blocks_traversal(self, jail_dir):
        with pytest.raises(ValueError, match="escapes"):
            join(jail_dir, "../etc/passwd")

    def test_join_pathlike(self, jail_dir):
        result = join(Path(jail_dir), Path("file.txt"))
        expected = os.path.join(os.path.realpath(jail_dir), "file.txt")
        assert result == expected


class TestSymlinks:
    """Test symlink security handling."""

    def test_symlink_escape_blocked(self, jail_dir):
        """Symlink pointing outside jail should be blocked."""
        jail = Jail(jail_dir)
        link_path = os.path.join(jail_dir, "escape_link")
        os.symlink("/etc", link_path)

        with pytest.raises(ValueError, match="escapes"):
            jail.contains(os.path.join(link_path, "passwd"))

    def test_symlink_chain_escape_blocked(self, jail_dir):
        """Chain of symlinks escaping jail should be blocked."""
        jail = Jail(jail_dir)
        # Create a -> b -> /etc
        link_a = os.path.join(jail_dir, "link_a")
        link_b = os.path.join(jail_dir, "link_b")
        os.symlink("/etc", link_b)
        os.symlink(link_b, link_a)

        with pytest.raises(ValueError, match="escapes"):
            jail.contains(os.path.join(link_a, "passwd"))

    def test_broken_symlink_blocked(self, jail_dir):
        """Broken symlink should be blocked (can't verify target)."""
        jail = Jail(jail_dir)
        link_path = os.path.join(jail_dir, "broken_link")
        os.symlink("/nonexistent/target", link_path)

        # Broken symlinks raise OSError (file not found) or ValueError
        with pytest.raises((OSError, ValueError)):
            jail.contains(link_path)

    def test_internal_symlink_allowed(self, jail_dir):
        """Symlink pointing inside jail should work."""
        jail = Jail(jail_dir)
        # Create a real file and a symlink to it
        real_file = os.path.join(jail_dir, "real.txt")
        Path(real_file).touch()
        link_path = os.path.join(jail_dir, "link.txt")
        os.symlink(real_file, link_path)

        result = jail.contains(link_path)
        assert result == os.path.realpath(real_file)

    def test_internal_dir_symlink_allowed(self, jail_dir):
        """Symlink to directory inside jail should work."""
        jail = Jail(jail_dir)
        # Create subdir with file
        subdir = os.path.join(jail_dir, "subdir")
        os.makedirs(subdir)
        Path(os.path.join(subdir, "file.txt")).touch()
        # Create symlink to subdir
        link_path = os.path.join(jail_dir, "link_dir")
        os.symlink(subdir, link_path)

        result = jail.contains(os.path.join(link_path, "file.txt"))
        assert "file.txt" in result


class TestEdgeCases:
    """Test edge cases and special paths."""

    def test_dot_path(self, jail_dir):
        """Single dot should resolve to jail root."""
        jail = Jail(jail_dir)
        result = jail.join(".")
        assert result == jail.root

    def test_dot_in_path(self, jail_dir):
        """Dot in path should be normalized."""
        jail = Jail(jail_dir)
        result = jail.join("./subdir/./file.txt")
        assert result == os.path.join(jail.root, "subdir", "file.txt")

    def test_internal_parent_traversal(self, jail_dir):
        """foo/../bar should resolve to bar (stays in jail)."""
        jail = Jail(jail_dir)
        result = jail.join("foo/../bar.txt")
        assert result == os.path.join(jail.root, "bar.txt")

    def test_deep_internal_traversal(self, jail_dir):
        """a/b/c/../../d should resolve correctly."""
        jail = Jail(jail_dir)
        result = jail.join("a/b/c/../../d.txt")
        assert result == os.path.join(jail.root, "a", "d.txt")

    def test_empty_path(self, jail_dir):
        """Empty path should resolve to jail root or error."""
        jail = Jail(jail_dir)
        # Behavior depends on implementation - either root or error
        try:
            result = jail.join("")
            assert result == jail.root
        except ValueError:
            pass  # Also acceptable

    def test_whitespace_path(self, jail_dir):
        """Path with spaces should work."""
        jail = Jail(jail_dir)
        result = jail.join("file with spaces.txt")
        assert "file with spaces.txt" in result


class TestTypeErrors:
    """Test type error handling."""

    def test_invalid_type_int(self, jail_dir):
        """Integer path should raise TypeError."""
        jail = Jail(jail_dir)
        with pytest.raises(TypeError, match="PathLike"):
            jail.join(123)

    def test_invalid_type_none(self, jail_dir):
        """None path should raise TypeError."""
        jail = Jail(jail_dir)
        with pytest.raises(TypeError):
            jail.join(None)

    def test_invalid_type_list(self, jail_dir):
        """List path should raise TypeError."""
        jail = Jail(jail_dir)
        with pytest.raises(TypeError):
            jail.join(["subdir", "file.txt"])

    def test_invalid_root_type(self):
        """Invalid root type should raise TypeError."""
        with pytest.raises(TypeError):
            Jail(123)

    def test_bytes_path_rejected(self, jail_dir):
        """Bytes path should raise TypeError (we only support str)."""
        jail = Jail(jail_dir)
        with pytest.raises(TypeError):
            jail.join(b"file.txt")

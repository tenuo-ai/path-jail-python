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


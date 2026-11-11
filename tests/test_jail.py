import gc
import os
import subprocess
import sys
import tempfile
from io import IOBase, UnsupportedOperation
from pathlib import Path

import pytest
from path_jail import FdJail, Jail, join

# Windows extended-length path prefix
WIN_PREFIX = "\\\\?\\"


def normalize_path(path: str) -> str:
    """Normalize path for comparison (strips Windows \\?\\ prefix)."""
    if path.startswith(WIN_PREFIX):
        return path[len(WIN_PREFIX) :]
    return path


def paths_equal(a: str, b: str) -> bool:
    """Compare paths, handling Windows extended-length paths."""
    return normalize_path(a) == normalize_path(b)


# Skip symlink tests on Windows (requires admin/Developer Mode)
skip_symlinks_on_windows = pytest.mark.skipif(
    sys.platform == "win32",
    reason="Symlinks require admin privileges on Windows",
)


@pytest.fixture
def jail_dir():
    """Create a temporary directory for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


class TestJail:
    def test_create_jail(self, jail_dir):
        jail = Jail(jail_dir)
        assert paths_equal(jail.root, os.path.realpath(jail_dir))

    def test_create_jail_pathlike(self, jail_dir):
        jail = Jail(Path(jail_dir))
        assert paths_equal(jail.root, os.path.realpath(jail_dir))

    def test_create_jail_nonexistent(self):
        with pytest.raises(FileNotFoundError) as exc_info:
            Jail("/nonexistent/path")
        assert exc_info.value.errno is not None

    def test_join_simple(self, jail_dir):
        jail = Jail(jail_dir)
        result = jail.join("file.txt")
        assert paths_equal(result, os.path.join(normalize_path(jail.root), "file.txt"))

    def test_join_nested(self, jail_dir):
        jail = Jail(jail_dir)
        result = jail.join("subdir/file.txt")
        assert paths_equal(result, os.path.join(normalize_path(jail.root), "subdir", "file.txt"))

    def test_join_pathlike(self, jail_dir):
        jail = Jail(jail_dir)
        result = jail.join(Path("subdir") / "file.txt")
        assert paths_equal(result, os.path.join(normalize_path(jail.root), "subdir", "file.txt"))

    def test_join_segments(self, jail_dir):
        jail = Jail(jail_dir)
        result = jail.join_segments("users", "alice", "report.pdf")
        expected = os.path.join(normalize_path(jail.root), "users", "alice", "report.pdf")
        assert paths_equal(result, expected)

    def test_join_segments_accepts_pathlike_and_skips_empty(self, jail_dir):
        jail = Jail(jail_dir)
        assert paths_equal(
            jail.join_segments(Path("users"), "", "report.pdf"),
            jail.join_segments("users", "report.pdf"),
        )

    @pytest.mark.parametrize("part", ["..", "users/alice", "users\\alice", "bad\x00name"])
    def test_join_segments_rejects_invalid_component(self, jail_dir, part):
        jail = Jail(jail_dir)
        with pytest.raises(ValueError):
            jail.join_segments("safe", part)

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
        # Compare canonicalized paths (handles /var -> /private/var on macOS, \\?\ on Windows)
        assert paths_equal(result, os.path.realpath(test_file))

    def test_contains_outside(self, jail_dir):
        jail = Jail(jail_dir)
        # Use a path that's absolute on the current platform but outside the jail
        if sys.platform == "win32":
            outside_path = "C:\\Windows\\System32\\cmd.exe"
        else:
            outside_path = "/etc/passwd"
        with pytest.raises(ValueError, match="escapes"):
            jail.contains(outside_path)

    def test_contains_missing_path_is_os_error(self, jail_dir):
        jail = Jail(jail_dir)
        missing = os.path.join(jail_dir, "missing.txt")
        with pytest.raises(FileNotFoundError):
            jail.contains(missing)

    def test_relative(self, jail_dir):
        jail = Jail(jail_dir)
        test_file = os.path.join(jail_dir, "subdir", "file.txt")
        os.makedirs(os.path.dirname(test_file), exist_ok=True)
        Path(test_file).touch()

        result = jail.relative(test_file)
        # On Windows, path separator might differ
        assert normalize_path(result) == os.path.join("subdir", "file.txt")

    def test_relative_missing_path_is_os_error(self, jail_dir):
        jail = Jail(jail_dir)
        missing = os.path.join(jail_dir, "missing.txt")
        with pytest.raises(FileNotFoundError):
            jail.relative(missing)

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
        assert paths_equal(result, expected)

    def test_join_blocks_traversal(self, jail_dir):
        with pytest.raises(ValueError, match="escapes"):
            join(jail_dir, "../etc/passwd")

    def test_join_pathlike(self, jail_dir):
        result = join(Path(jail_dir), Path("file.txt"))
        expected = os.path.join(os.path.realpath(jail_dir), "file.txt")
        assert paths_equal(result, expected)


@pytest.mark.skipif(sys.platform == "win32", reason="Symlinks require admin on Windows")
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
        assert paths_equal(result, os.path.realpath(real_file))

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
        assert paths_equal(result, jail.root)

    def test_dot_in_path(self, jail_dir):
        """Dot in path should be normalized."""
        jail = Jail(jail_dir)
        result = jail.join("./subdir/./file.txt")
        assert paths_equal(result, os.path.join(normalize_path(jail.root), "subdir", "file.txt"))

    def test_internal_parent_traversal(self, jail_dir):
        """foo/../bar should resolve to bar (stays in jail)."""
        jail = Jail(jail_dir)
        result = jail.join("foo/../bar.txt")
        assert paths_equal(result, os.path.join(normalize_path(jail.root), "bar.txt"))

    def test_deep_internal_traversal(self, jail_dir):
        """a/b/c/../../d should resolve correctly."""
        jail = Jail(jail_dir)
        result = jail.join("a/b/c/../../d.txt")
        assert paths_equal(result, os.path.join(normalize_path(jail.root), "a", "d.txt"))

    def test_empty_path(self, jail_dir):
        """Empty path should resolve to jail root or error."""
        jail = Jail(jail_dir)
        # Behavior depends on implementation - either root or error
        try:
            result = jail.join("")
            assert paths_equal(result, jail.root)
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


class TestSecurityEdgeCases:
    """Test security-sensitive edge cases."""

    def test_unicode_path(self, jail_dir):
        """Unicode characters in paths should work."""
        jail = Jail(jail_dir)
        result = jail.join("文件/données/αρχείο.txt")
        assert "αρχείο.txt" in result

    def test_emoji_path(self, jail_dir):
        """Emoji in paths should work."""
        jail = Jail(jail_dir)
        result = jail.join("📁/📄.txt")
        assert "📄.txt" in result

    def test_null_byte_in_path(self, jail_dir):
        """Null bytes in paths should be handled safely (stay in jail)."""
        jail = Jail(jail_dir)
        # Null bytes can be used to truncate paths in C-based systems
        # The result should either raise an error OR stay inside the jail
        try:
            result = jail.join("file\x00.txt")
            assert normalize_path(result).startswith(normalize_path(jail.root))
        except (ValueError, OSError):
            pass  # Also acceptable to reject

    def test_null_byte_traversal_attack(self, jail_dir):
        """Null byte + traversal attack should be blocked."""
        jail = Jail(jail_dir)
        # Attack: null byte to truncate, then traverse
        # Should either reject or resolve safely inside jail
        try:
            result = jail.join("subdir\x00/../etc/passwd")
            # If it doesn't raise, verify it's inside the jail
            assert normalize_path(result).startswith(normalize_path(jail.root))
            # Should NOT contain /etc/passwd outside jail
            assert "/etc/passwd" not in result or result.startswith(normalize_path(jail.root))
        except (ValueError, OSError):
            pass  # Also acceptable to reject

    def test_special_chars(self, jail_dir):
        """Special characters should be handled safely."""
        jail = Jail(jail_dir)
        # These should either work or raise ValueError, never escape
        for special in ["file'name.txt", 'file"name.txt', "file`name.txt"]:
            try:
                result = jail.join(special)
                # If it works, verify it's inside the jail
                assert normalize_path(result).startswith(normalize_path(jail.root))
            except (ValueError, OSError):
                pass  # Also acceptable to reject

    def test_backslash_on_unix(self, jail_dir):
        """Backslash should be treated as filename char on Unix, separator on Windows."""
        jail = Jail(jail_dir)
        result = jail.join("file\\name.txt")
        # Should not escape regardless of interpretation
        assert normalize_path(result).startswith(normalize_path(jail.root))

    def test_colon_in_path(self, jail_dir):
        """Colon in path (Windows drive letter attack)."""
        jail = Jail(jail_dir)
        # On Windows, this could be interpreted as drive letter
        # Should either work as filename or raise error
        try:
            result = jail.join("C:file.txt")
            assert normalize_path(result).startswith(normalize_path(jail.root))
        except (ValueError, OSError):
            pass  # Acceptable to reject

    def test_long_path(self, jail_dir):
        """Very long paths should be handled."""
        jail = Jail(jail_dir)
        # Create a path near the 260 char limit
        long_component = "a" * 50
        long_path = "/".join([long_component] * 5)  # ~255 chars
        result = jail.join(long_path)
        assert long_component in result

    def test_very_long_path(self, jail_dir):
        """Paths exceeding 260 chars should work (with prefix on Windows)."""
        jail = Jail(jail_dir)
        # Create a path exceeding 260 chars
        long_component = "a" * 50
        long_path = "/".join([long_component] * 10)  # ~509 chars
        result = jail.join(long_path)
        assert long_component in result

    def test_dot_dot_in_filename(self, jail_dir):
        """Literal .. in filename (not as traversal)."""
        jail = Jail(jail_dir)
        # This should be treated as a filename, not traversal
        # Behavior may vary - either works or raises
        try:
            result = jail.join("file..txt")
            assert "file..txt" in result
        except ValueError:
            pass

    def test_multiple_slashes(self, jail_dir):
        """Multiple consecutive slashes should be normalized."""
        jail = Jail(jail_dir)
        result = jail.join("subdir///file.txt")
        # Should normalize to single slashes
        assert "file.txt" in result

    def test_trailing_slash(self, jail_dir):
        """Trailing slash should be handled."""
        jail = Jail(jail_dir)
        result = jail.join("subdir/")
        assert normalize_path(result).startswith(normalize_path(jail.root))


class TestCoreBehavior:
    """Behavior that comes from the path_jail 0.6 core."""

    def test_non_directory_root_is_value_error(self, jail_dir):
        file_root = os.path.join(jail_dir, "file.txt")
        with open(file_root, "w"):
            pass
        with pytest.raises(ValueError, match="not a directory"):
            Jail(file_root)

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
    @pytest.mark.skipif(
        hasattr(os, "geteuid") and os.geteuid() == 0, reason="root bypasses permissions"
    )
    def test_unreadable_component_fails_closed(self, jail_dir):
        locked = os.path.join(jail_dir, "locked")
        os.mkdir(locked)
        os.chmod(locked, 0)
        try:
            jail = Jail(jail_dir)
            # 0.2 treated the unreadable component as nonexistent and returned
            # a path; 0.5 reports the I/O error instead.
            with pytest.raises(PermissionError):
                jail.join("locked/file.txt")
        finally:
            os.chmod(locked, 0o700)

    def test_version_matches_metadata(self):
        from importlib.metadata import version

        import path_jail

        assert path_jail.__version__ == version("path-jail")


class TestFdJail:
    def test_windows_reports_unsupported(self, jail_dir):
        if sys.platform != "win32":
            pytest.skip("Windows-only behavior")
        with pytest.raises(NotImplementedError, match="Unix"):
            FdJail(root=jail_dir)

    @pytest.mark.skipif(sys.platform == "win32", reason="FdJail is Unix-only")
    def test_open_returns_normal_python_file(self, jail_dir):
        Path(jail_dir, "message.txt").write_text("hello", encoding="utf-8")
        jail = FdJail(jail_dir)

        with jail.open("message.txt") as file:
            assert isinstance(file, IOBase)
            assert file.read() == "hello"

    @pytest.mark.skipif(sys.platform == "win32", reason="FdJail is Unix-only")
    def test_binary_create_and_open(self, jail_dir):
        jail = FdJail(jail_dir)
        with jail.create("created.bin") as file:
            file.write(b"created")
        with jail.open("created.bin", "rb", require_regular_file=True) as file:
            assert file.read() == b"created"
        with pytest.raises(FileExistsError):
            jail.create("created.bin")

    @pytest.mark.skipif(sys.platform == "win32", reason="FdJail is Unix-only")
    def test_write_append_and_update_modes(self, jail_dir):
        jail = FdJail(jail_dir)
        with jail.open("value.txt", "w") as file:
            assert file.mode == "w"
            file.write("one")
        with jail.open("value.txt", "a") as file:
            file.write(" two")
        with jail.open("value.txt", "r+") as file:
            assert file.read() == "one two"
            file.seek(0)
            file.write("ONE")
        assert Path(jail_dir, "value.txt").read_text(encoding="utf-8") == "ONE two"

    @pytest.mark.skipif(sys.platform == "win32", reason="FdJail is Unix-only")
    @pytest.mark.parametrize("mode", ["", "rr", "rw", "rbb", "rbt", "q"])
    def test_invalid_mode_is_rejected(self, jail_dir, mode):
        jail = FdJail(jail_dir)
        with pytest.raises(ValueError, match="invalid file mode"):
            jail.open("value.txt", mode)

    @pytest.mark.skipif(sys.platform == "win32", reason="FdJail is Unix-only")
    def test_non_seekable_wrapper_failure_closes_descriptor_once(self, jail_dir):
        os.mkfifo(Path(jail_dir, "pipe"))
        jail = FdJail(jail_dir)
        before = len(os.listdir("/dev/fd"))

        for _ in range(20):
            with pytest.raises(UnsupportedOperation):
                jail.open("pipe", "r+")

        gc.collect()
        assert len(os.listdir("/dev/fd")) <= before

    @pytest.mark.skipif(sys.platform == "win32", reason="FdJail is Unix-only")
    def test_blocking_open_releases_gil(self, jail_dir):
        script = """
import os
import sys
import threading
import time
from path_jail import FdJail

root = sys.argv[1]
fifo = os.path.join(root, "blocking-pipe")
os.mkfifo(fifo)
jail = FdJail(root)

def write_later():
    time.sleep(0.1)
    fd = os.open(fifo, os.O_WRONLY)
    try:
        os.write(fd, b"ready")
    finally:
        os.close(fd)

writer = threading.Thread(target=write_later)
writer.start()
with jail.open("blocking-pipe", "rb") as file:
    assert file.read() == b"ready"
writer.join()
"""
        subprocess.run(
            [sys.executable, "-c", script, jail_dir],
            check=True,
            timeout=5,
        )

    @pytest.mark.skipif(sys.platform == "win32", reason="FdJail is Unix-only")
    def test_open_with_attestation(self, jail_dir):
        Path(jail_dir, "report.txt").write_text("report", encoding="utf-8")
        jail = FdJail(jail_dir)

        file, attestation = jail.open_with_attestation(
            "report.txt", "rb", require_regular_file=True
        )
        with file:
            assert file.read() == b"report"
        assert attestation.opened_path == "report.txt"
        assert attestation.file_inode > 0
        assert attestation.root_inode > 0
        assert attestation.nlink >= 1
        assert attestation.signature is None
        assert attestation.toctou_safe == jail.capabilities().toctou_safe

    @pytest.mark.skipif(sys.platform == "win32", reason="FdJail is Unix-only")
    def test_require_regular_file_rejects_directory(self, jail_dir):
        Path(jail_dir, "directory").mkdir()
        jail = FdJail(jail_dir)
        with pytest.raises(ValueError, match="regular"):
            jail.open("directory", "rb", require_regular_file=True)

    @pytest.mark.skipif(sys.platform == "win32", reason="FdJail is Unix-only")
    def test_reject_hard_links(self, jail_dir):
        original = Path(jail_dir, "original.txt")
        original.write_text("linked", encoding="utf-8")
        os.link(original, Path(jail_dir, "linked.txt"))
        jail = FdJail(jail_dir)

        with pytest.raises(ValueError, match="hard link"):
            jail.open("linked.txt", "rb", reject_hard_links=True)

    @pytest.mark.skipif(sys.platform == "win32", reason="FdJail is Unix-only")
    def test_symlink_escape_is_rejected(self, jail_dir):
        outside = tempfile.NamedTemporaryFile(delete=False)
        try:
            outside.write(b"secret")
            outside.close()
            os.symlink(outside.name, Path(jail_dir, "escape"))
            jail = FdJail(jail_dir)
            with pytest.raises(ValueError):
                jail.open("escape", "rb")
        finally:
            outside.close()
            os.unlink(outside.name)

    @pytest.mark.skipif(sys.platform != "linux", reason="no_symlinks requires Linux")
    def test_no_symlinks_rejects_internal_symlink(self, jail_dir):
        Path(jail_dir, "target.txt").write_text("inside", encoding="utf-8")
        os.symlink("target.txt", Path(jail_dir, "link.txt"))
        jail = FdJail(jail_dir)
        assert jail.capabilities().no_symlinks

        with jail.open("link.txt") as file:
            assert file.read() == "inside"
        with pytest.raises(ValueError):
            jail.open("link.txt", no_symlinks=True)

    @pytest.mark.skipif(sys.platform == "win32", reason="FdJail is Unix-only")
    def test_capabilities_and_directory_mutations(self, jail_dir):
        jail = FdJail(jail_dir)
        capabilities = jail.capabilities()
        assert capabilities.toctou_safe == capabilities.directory_operations
        assert capabilities.no_symlinks == capabilities.toctou_safe
        assert capabilities.no_xdev == capabilities.toctou_safe

        if not capabilities.directory_operations:
            with pytest.raises(NotImplementedError, match="no_symlinks"):
                jail.open("missing", no_symlinks=True)
            with pytest.raises(NotImplementedError, match="no_xdev"):
                jail.open("missing", no_xdev=True)
            with pytest.raises(NotImplementedError):
                jail.create_dir("work")
            return

        jail.create_dir("work")
        with jail.create("work/source.txt") as file:
            file.write(b"data")
        jail.rename("work/source.txt", "work/destination.txt")
        jail.remove_file("work/destination.txt")
        jail.remove_dir("work")
        assert not Path(jail_dir, "work").exists()

# path-jail

Python bindings for [path_jail](https://github.com/aimable100/path_jail); a secure filesystem sandbox that restricts paths to a root directory, preventing traversal attacks.

## Installation

```bash
pip install path-jail
```

### From Source

Requires [Rust](https://rustup.rs/) and [maturin](https://github.com/PyO3/maturin):

```bash
git clone https://github.com/aimable100/path-jail-python.git
cd path-jail-python
pip install maturin
maturin develop --release
```

## Usage

```python
from path_jail import Jail, join  # Note: underscore in import

# One-shot validation
safe_path = join("/var/uploads", "user/file.txt")

# Reusable jail
jail = Jail("/var/uploads")
path = jail.join("report.pdf")

# Escape attempts raise ValueError
jail.join("../../etc/passwd")  # ValueError: path escapes jail root
```

### PathLike Support

Works with `pathlib.Path` and any `os.PathLike`:

```python
from pathlib import Path

jail = Jail(Path("/var/uploads"))
safe = jail.join(Path("subdir") / "file.txt")
```

### API

```python
jail = Jail(root)           # Create jail (root must exist)
jail.root                   # Canonicalized root path
jail.join(path)             # Safely join relative path
jail.contains(path)         # Verify absolute path is inside jail
jail.relative(path)         # Get relative path from absolute

join(root, path)            # One-shot validation
```

### Path Canonicalization

All returned paths are canonicalized (symlinks resolved, `..` eliminated). This is essential for security but may surprise you on macOS where `/var` is a symlink:

```python
jail = Jail("/var/uploads")
print(jail.root)  # "/private/var/uploads" on macOS
```

When comparing paths, always canonicalize your expected values:

```python
import os
result = jail.contains("/var/uploads/file.txt")
assert result == os.path.realpath("/var/uploads/file.txt")
```

## Development

```bash
pip install maturin pytest
maturin develop
pytest
```

## Security

See the [main library](https://github.com/aimable100/path_jail#security) for security details. This library defends against:

- Path traversal (`../../etc/passwd`)
- Symlink escapes
- Absolute path injection

## License

MIT OR Apache-2.0


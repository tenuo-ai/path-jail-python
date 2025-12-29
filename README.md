# path-jail

Python bindings for [path_jail](https://github.com/aimable100/path_jail) — a secure filesystem sandbox that restricts paths to a root directory, preventing traversal attacks.

## Installation

```bash
pip install path-jail
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

## Security

See the [main library](https://github.com/aimable100/path_jail#security) for security details. This library defends against:

- Path traversal (`../../etc/passwd`)
- Symlink escapes
- Absolute path injection

## License

MIT OR Apache-2.0


# path-jail

[![CI](https://github.com/aimable100/path-jail-python/actions/workflows/ci.yml/badge.svg)](https://github.com/aimable100/path-jail-python/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/path-jail.svg)](https://pypi.org/project/path-jail/)
[![Python](https://img.shields.io/pypi/pyversions/path-jail.svg)](https://pypi.org/project/path-jail/)
[![License](https://img.shields.io/pypi/l/path-jail.svg)](https://github.com/aimable100/path-jail-python#license)

A secure filesystem sandbox for Python. Restricts paths to a root directory, preventing traversal attacks while supporting files that don't exist yet.

Built with Rust via [PyO3](https://pyo3.rs/) for native performance.

## Installation

```bash
pip install path-jail
```

## Quick Start

```python
from path_jail import Jail, join

# One-shot validation
safe_path = join("/var/uploads", "user/report.pdf")

# Reusable jail (better for multiple paths)
jail = Jail("/var/uploads")
path1 = jail.join("2025/report.pdf")
path2 = jail.join("data.csv")

# These raise ValueError:
jail.join("../../etc/passwd")      # Path traversal
jail.join("/etc/passwd")           # Absolute path
```

## Why path-jail?

Python's standard library is treacherous for path sandboxing:

| Function | Problem |
|----------|---------|
| `os.path.abspath()` | Lexical only. Does not touch disk. `../../etc/passwd` becomes `/etc/passwd`. |
| `os.path.realpath()` | Resolves symlinks but does not jail. You must manually check `startswith()`. |
| `pathlib.Path.resolve()` | Same as `realpath()`. No sandboxing. |

**path-jail** handles the edge cases:

- Resolves `..` safely (no escape)
- Follows symlinks and verifies they stay inside the jail
- Rejects broken symlinks (cannot verify target)
- Works with non-existent paths (for creating new files)

## API

### `join(root, path) -> str`

One-shot validation. Creates a jail and joins a path in one call.

```python
from path_jail import join

safe = join("/var/uploads", "user/file.txt")
# Returns: "/var/uploads/user/file.txt"
```

### `Jail(root)`

Create a reusable jail rooted at `root` (must exist).

```python
from path_jail import Jail

jail = Jail("/var/uploads")
print(jail.root)  # Canonicalized root path
```

### `Jail.join(path) -> str`

Join a relative path to the jail root. Returns the absolute path.

```python
safe = jail.join("subdir/file.txt")
```

### `Jail.contains(path) -> str`

Verify an existing absolute path is inside the jail.

```python
canonical = jail.contains("/var/uploads/file.txt")
```

### `Jail.relative(path) -> str`

Get the relative path from an absolute path inside the jail.

```python
rel = jail.relative("/var/uploads/2025/report.pdf")
# Returns: "2025/report.pdf"
```

## pathlib Support

All methods accept `str` or `os.PathLike` (including `pathlib.Path`):

```python
from pathlib import Path
from path_jail import Jail

jail = Jail(Path("/var/uploads"))
safe = jail.join(Path("user") / "file.txt")
```

## Error Handling

```python
from path_jail import Jail

jail = Jail("/var/uploads")

try:
    safe_path = jail.join(user_input)
except ValueError as e:
    # Path escapes jail, broken symlink, or invalid path
    print(f"Rejected: {e}")
except TypeError as e:
    # Invalid type (not str or PathLike)
    print(f"Bad input: {e}")
```

Creating a jail can also fail:

```python
try:
    jail = Jail("/nonexistent")
except OSError as e:
    # Root doesn't exist or isn't a directory
    print(f"Invalid root: {e}")
```

## Example: File Uploads

```python
from pathlib import Path
from path_jail import Jail

UPLOAD_DIR = "/var/uploads"
jail = Jail(UPLOAD_DIR)

def save_upload(user_id: str, filename: str, data: bytes) -> str:
    """Safely save an uploaded file."""
    # Validate and build path
    safe_path = jail.join(f"{user_id}/{filename}")
    
    # Create parent directories
    Path(safe_path).parent.mkdir(parents=True, exist_ok=True)
    
    # Write file
    Path(safe_path).write_bytes(data)
    
    # Return relative path for database storage
    return jail.relative(safe_path)
```

## Framework Integration

### FastAPI

```python
from fastapi import FastAPI, UploadFile, HTTPException
from path_jail import Jail

app = FastAPI()
uploads = Jail("/var/uploads")

@app.post("/upload/{filename:path}")
async def upload(filename: str, file: UploadFile):
    try:
        safe_path = uploads.join(filename)
    except ValueError:
        raise HTTPException(400, "Invalid filename")
    
    Path(safe_path).parent.mkdir(parents=True, exist_ok=True)
    Path(safe_path).write_bytes(await file.read())
    return {"path": filename}
```

### Flask

```python
from flask import Flask, request, abort
from path_jail import Jail

app = Flask(__name__)
uploads = Jail("/var/uploads")

@app.route("/upload/<path:filename>", methods=["POST"])
def upload(filename):
    try:
        safe_path = uploads.join(filename)
    except ValueError:
        abort(400, "Invalid filename")
    
    Path(safe_path).parent.mkdir(parents=True, exist_ok=True)
    request.files["file"].save(safe_path)
    return {"path": filename}
```

## Performance

path-jail crosses the Python/Rust boundary once per call. The tight syscall loop runs at native speed, making it significantly faster than equivalent pure-Python implementations for deep paths.

## Development

```bash
git clone https://github.com/aimable100/path-jail-python.git
cd path-jail-python
pip install maturin pytest ruff mypy
maturin develop
pytest
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

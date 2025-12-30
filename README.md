# path-jail

[![CI](https://github.com/tenuo-ai/path-jail-python/actions/workflows/ci.yml/badge.svg)](https://github.com/tenuo-ai/path-jail-python/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/path-jail.svg)](https://pypi.org/project/path-jail/)
[![Python](https://img.shields.io/pypi/pyversions/path-jail.svg)](https://pypi.org/project/path-jail/)
[![License](https://img.shields.io/pypi/l/path-jail.svg)](https://github.com/tenuo-ai/path-jail-python#license)

A secure filesystem sandbox for Python. Restricts paths to a root directory, preventing traversal attacks while supporting files that don't exist yet.

Built with Rust via [PyO3](https://pyo3.rs/) for native performance. Python bindings for [`path_jail`](https://crates.io/crates/path_jail).

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

## Type Hints

path-jail is fully typed. Your IDE will provide autocompletion and type checking:

```python
# mypy and pyright will catch this:
jail.join(123)  # error: Argument 1 has incompatible type "int"
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
from pathlib import Path
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

### Django

```python
from pathlib import Path
from django.conf import settings
from django.http import JsonResponse, HttpResponseBadRequest
from path_jail import Jail

uploads = Jail(settings.MEDIA_ROOT)

def upload(request, filename):
    try:
        safe_path = uploads.join(filename)
    except ValueError:
        return HttpResponseBadRequest("Invalid filename")
    
    Path(safe_path).parent.mkdir(parents=True, exist_ok=True)
    with open(safe_path, "wb") as f:
        for chunk in request.FILES["file"].chunks():
            f.write(chunk)
    return JsonResponse({"path": filename})
```

## Security Considerations

path-jail provides strong protection against path traversal attacks, but there are edge cases to be aware of:

### What path-jail Protects Against

- **Path traversal** (`../`, `..\\`) - Blocked
- **Symlink escapes** - Symlinks pointing outside the jail are rejected
- **Broken symlinks** - Rejected (cannot verify target)
- **Absolute paths** - Rejected in `join()`
- **Null bytes** - Rejected (prevents C-library truncation attacks)

### Known Limitations

#### Hard Links

Hard links cannot be detected by path inspection. If an attacker has shell access and creates a hard link to a sensitive file inside your jail directory, path-jail will allow access to it.

```bash
# Attacker with shell access:
ln /etc/passwd /var/uploads/innocent.txt
```

**Mitigations:**
- Use a separate partition for the jail (hard links cannot cross partitions)
- Don't give untrusted users shell access
- Use container isolation

#### TOCTOU Race Conditions

path-jail validates paths at call time. A symlink could be created between validation and use.

```python
safe_path = jail.join("file.txt")  # Validated
# Attacker creates symlink here
open(safe_path)                     # Escapes!
```

**Mitigations:**
- Use `O_NOFOLLOW` when opening files
- Use container/chroot isolation for strong guarantees

#### Windows Reserved Device Names

On Windows, filenames like `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9` are special device names. For paths under 250 characters, we strip the `\\?\` prefix for usability, which re-enables this legacy behavior.

```python
# If an attacker uploads "CON.txt":
safe_path = jail.join("CON.txt")   # Returns "C:\uploads\CON.txt"
open(safe_path)                     # Opens console device, not file!
```

**Impact:** Denial of Service (thread hangs or data vanishes). Not a filesystem escape.

**Mitigations:**
- Validate filenames against a blocklist before calling path-jail
- Use UUIDs for stored filenames instead of user-provided names

#### Unicode Normalization (macOS)

macOS automatically converts filenames to NFD (decomposed) form. A file saved as `cafe.txt` (with composed e) may be stored as `cafe.txt` (with decomposed e + combining accent).

**Impact:** Not a security issue, but may cause "file not found" errors if comparing filenames byte-for-byte. Python's `os.path` handles this transparently for most cases.

#### Case Sensitivity (Windows/macOS)

Windows and macOS (by default) have case-insensitive filesystems:

```python
jail = Jail("/var/uploads")
jail.join("FILE.txt")  # Points to same file as "file.txt"

# Attacker could bypass naive blocklists:
blocklist = ["secret.txt"]
jail.join("SECRET.TXT")  # Not in blocklist, but same file!
```

**Mitigation:** Normalize case (e.g., `filename.lower()`) before blocklist checks.

#### Trailing Dots and Spaces (Windows)

Windows silently strips trailing dots and spaces from filenames:

```python
jail.join("file.txt.")   # Becomes "file.txt"
jail.join("file.txt ")   # Becomes "file.txt"

# Could bypass extension checks:
if not filename.endswith(".exe"):
    jail.join("malware.exe.")  # Passes check, becomes .exe!
```

**Mitigation:** Strip trailing dots/spaces before validation.

#### Alternate Data Streams (Windows NTFS)

NTFS supports alternate data streams that hide data from directory listings:

```python
jail.join("file.txt:hidden")  # Creates alternate stream
```

**Impact:** Not an escape, but can hide data. Consider rejecting filenames containing `:`.

#### Special Filesystems (Linux)

Avoid using path-jail with special filesystem roots:

- `/proc` - `/proc/self/root` is a symlink to filesystem root
- `/dev` - `/dev/fd/N` are symlinks to open file descriptors

These are unlikely scenarios but worth noting for completeness.

#### Path Encoding

Returned paths are converted to Python strings using lossy UTF-8 conversion. On rare filesystems with non-UTF8 filenames, invalid bytes are replaced with `�` (U+FFFD). This affects only the returned string; the security check uses the original bytes.

### Path Canonicalization

All returned paths are canonicalized (symlinks resolved, `..` eliminated). This is essential for security but may surprise you:

```python
# macOS: /var is a symlink to /private/var
jail = Jail("/var/uploads")
print(jail.root)  # "/private/var/uploads"

# Windows: Long paths (>250 chars) keep the \\?\ prefix
jail = Jail("C:\\data")
print(jail.join("a" * 300))  # "\\?\C:\data\aaa..."
```

When comparing paths, always canonicalize your expected values:

```python
import os
assert result == os.path.realpath("/var/uploads/file.txt")
```

## Performance

path-jail crosses the Python/Rust boundary once per call. The tight syscall loop runs at native speed, making it significantly faster than equivalent pure-Python implementations for deep paths.

## Thread Safety

`Jail` instances are thread-safe and can be shared across threads without locks.

## Development

```bash
git clone https://github.com/tenuo-ai/path-jail-python.git
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

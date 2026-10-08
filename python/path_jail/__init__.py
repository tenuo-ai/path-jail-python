# Re-export from native module
from .path_jail import Jail, join

__all__ = ["Jail", "join"]
from importlib.metadata import version as _version

__version__ = _version("path-jail")

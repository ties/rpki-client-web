import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, TextIO

from yaml import Loader, load

__all__ = ["load_yaml", "json_dumps"]


def load_yaml(config_file: TextIO) -> Dict:
    """load a yaml file."""
    return load(config_file, Loader=Loader)


class CustomJSONEncoder(json.JSONEncoder):
    """JSON encoder for configuration objects."""

    def default(self, o: Any) -> Any:
        """Encode object"""
        # Encode paths as their full name
        if is_dataclass(o):
            return asdict(o)
        if isinstance(o, Path):
            return str(o)
        if isinstance(o, datetime):
            return o.isoformat()
        # Let the base class default method raise the TypeError if otherwise
        # unknown)
        return json.JSONEncoder.default(self, o)


def json_dumps(obj: Any, indent: Optional[int] = 2) -> str:
    """Dump configuration object to JSON string."""
    return json.dumps(obj, indent=indent, cls=CustomJSONEncoder)

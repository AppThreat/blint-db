# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

from enum import Enum
import json
import shlex
from pathlib import Path
from typing import Any


def load_json_file(file_name: str | Path) -> Any:
    with open(file_name, "r", encoding="utf-8") as handle:
        return json.load(handle)


def dump_json_file(file_name: str | Path, data: Any) -> None:
    with open(file_name, "w", encoding="utf-8") as handle:
        json.dump(make_json_safe(data), handle, indent=2, sort_keys=True)


def make_json_safe(data: Any) -> Any:
    if data is None or isinstance(data, (bool, int, float, str)):
        return data
    if isinstance(data, Enum):
        return str(data)
    if isinstance(data, Path):
        return str(data)
    if isinstance(data, dict):
        return {str(key): make_json_safe(value) for key, value in data.items()}
    if isinstance(data, (list, tuple, set)):
        return [make_json_safe(value) for value in data]
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data).hex()
    return str(data)


def canonical_json_dumps(data: Any) -> str:
    return json.dumps(
        make_json_safe(data),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def coerce_json_object(data: Any) -> dict[str, Any]:
    return data if isinstance(data, dict) else {}


def optional_json_object(data: Any) -> dict[str, Any] | None:
    normalized = make_json_safe(coerce_json_object(data))
    return normalized or None


def split_shell_args(raw_value: str | None) -> tuple[str, ...]:
    if not raw_value:
        return ()
    return tuple(shlex.split(raw_value))


def get_nested_json_value(data: Any, *keys, default=None):
    current = data
    for key in keys:
        if isinstance(current, dict):
            if key not in current:
                return default
            current = current[key]
        elif isinstance(current, list) and isinstance(key, int):
            if key < 0 or key >= len(current):
                return default
            current = current[key]
        else:
            return default
    return current

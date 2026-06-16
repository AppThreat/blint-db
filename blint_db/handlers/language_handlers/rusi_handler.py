from __future__ import annotations

# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

"""Invoke the rusi source analyzer to produce a source callgraph.

rusi is an external Rust source analysis tool. Its location and invocation vary
between environments, so the base command is supplied by the caller, either as a
CLI argument or through the ``BLINT_DB_RUSI_CMD`` (or ``RUSI_CMD``) environment
variable. Examples of a base command are ``cargo run -p rusi-cli --`` when
running from a rusi checkout, or the path to a prebuilt ``rusi-cli`` binary.
"""

import json
import shlex
import subprocess
from pathlib import Path

from blint_db import RUSI_COMMAND, RUSI_HTTP_TIMEOUT, logger


def resolve_rusi_command(explicit_command: str | None = None) -> list[str]:
    """Return the rusi base command as an argument list, or an empty list.

    The explicit command, when provided, takes precedence over the environment.
    The returned list is suitable for use as the prefix of a subprocess
    invocation. An empty list means no rusi command is configured.
    """
    raw = explicit_command if explicit_command else RUSI_COMMAND
    if not raw:
        return []
    return shlex.split(raw)


def run_rusi_callgraph(
    source_dir: str | Path,
    *,
    rusi_command: str | None = None,
    work_dir: str | Path | None = None,
    timeout: int = RUSI_HTTP_TIMEOUT,
) -> dict | None:
    """Run rusi over a source tree and return the parsed callgraph as a dict.

    Args:
        source_dir: Path to the crate or workspace source to analyze.
        rusi_command: Base rusi command. Falls back to the environment when not
            given.
        work_dir: Directory used for the temporary callgraph output file.
            Defaults to ``source_dir``.
        timeout: Maximum seconds to allow the analysis to run.

    Returns:
        The parsed callgraph JSON as a dict, or ``None`` when rusi is not
        configured, fails, or produces no output. Failures are logged rather
        than raised so a corpus build can continue past a single bad crate.
    """
    base_command = resolve_rusi_command(rusi_command)
    if not base_command:
        logger.debug("rusi command is not configured; skipping source callgraph")
        return None

    source_path = Path(source_dir)
    if not source_path.exists():
        logger.warning("rusi source directory does not exist: %s", source_path)
        return None

    out_dir = Path(work_dir) if work_dir else source_path
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "rusi-callgraph.json"

    command = [
        *base_command,
        "analyze",
        "--dir",
        str(source_path),
        "--callgraph",
        "static",
        "--out",
        str(out_path),
    ]
    logger.debug("Running rusi: %s", " ".join(command))
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            encoding="utf-8",
            timeout=timeout,
        )
    except (FileNotFoundError, OSError) as exc:
        logger.warning("rusi could not be executed (%s): %s", base_command[0], exc)
        return None
    except subprocess.TimeoutExpired:
        logger.warning("rusi timed out after %ss on %s", timeout, source_path)
        return None

    if result.returncode != 0:
        logger.warning(
            "rusi exited with status %s on %s", result.returncode, source_path
        )
        return None
    if not out_path.exists():
        logger.warning("rusi produced no callgraph output for %s", source_path)
        return None
    try:
        return json.loads(out_path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        logger.warning("Could not read rusi callgraph for %s: %s", source_path, exc)
        return None

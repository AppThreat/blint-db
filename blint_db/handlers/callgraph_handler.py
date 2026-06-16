# -*- coding: utf-8 -*-
"""
Extract callgraph node and edge rows for the blint-db corpus.

Both the binary callgraph emitted by blint and the source callgraph emitted by a
source analyzer are reduced to canonical-name-keyed nodes by blint's callgraph
loaders. This module turns those graphs into flat row dictionaries suitable for
:func:`blint_db.handlers.sqlite_handler.replace_callgraph_nodes` and
:func:`replace_callgraph_edges`, keeping all Rust name normalization in blint so
the database stores an already-canonical join key.
"""

from __future__ import annotations

from typing import Any

from blint.lib.callgraph.model import (
    load_binary_callgraph,
    load_source_callgraph,
)


def extract_binary_callgraph(metadata: dict[str, Any]) -> dict[str, Any]:
    """Return node and edge rows for a binary callgraph.

    Args:
        metadata: Parsed blint ``*-metadata.json`` contents.

    Returns:
        A dict with ``nodes``, ``edges``, ``node_count`` and ``edge_count``.
        Edges are taken directly from the binary callgraph payload so the call
        kind and confidence recorded by the disassembler are preserved.
    """
    graph = load_binary_callgraph(metadata)
    nodes = [
        {
            "node_ref": node.id,
            "canon_name": node.canon.value,
            "raw_name": node.canon.raw,
            "address": node.address,
            "kind": node.canon.kind.value,
            "is_local": node.local,
            "features": node.features or None,
        }
        for node in graph.nodes.values()
    ]
    edges = [
        {
            "src_ref": str(edge.get("src")),
            "dst_ref": str(edge.get("dst")),
            "edge_type": edge.get("kind"),
            "confidence": edge.get("confidence"),
        }
        for edge in (metadata.get("callgraph") or {}).get("edges") or []
        if edge.get("src") is not None and edge.get("dst") is not None
    ]
    return {
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
    }


def extract_source_callgraph(source_payload: dict[str, Any]) -> dict[str, Any]:
    """Return node and edge rows for a source callgraph.

    Args:
        source_payload: Parsed source-analysis callgraph JSON contents.

    Returns:
        A dict with ``nodes``, ``edges``, ``node_count`` and ``edge_count``.
        Nodes are keyed by canonical name; edges connect canonical names.
    """
    graph = load_source_callgraph(source_payload)
    nodes = [
        {
            "node_ref": node.id,
            "canon_name": node.canon.value,
            "raw_name": node.canon.raw,
            "address": None,
            "kind": node.canon.kind.value,
            "is_local": node.local,
            "features": None,
        }
        for node in graph.nodes.values()
    ]
    edges = [
        {
            "src_ref": src,
            "dst_ref": dst,
            "edge_type": "static",
            "confidence": "high",
        }
        for src in graph.nodes
        for dst in graph.successors(src)
    ]
    return {
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
    }

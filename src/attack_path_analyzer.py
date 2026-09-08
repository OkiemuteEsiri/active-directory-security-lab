"""Analyze synthetic identity relationships for paths to privileged assets.

Designed for controlled labs and defensive identity-security validation.
"""
from __future__ import annotations

import csv
from collections import defaultdict, deque
from pathlib import Path


def load_edges(path: str | Path) -> dict[str, list[tuple[str, str]]]:
    graph: dict[str, list[tuple[str, str]]] = defaultdict(list)
    with Path(path).open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            graph[row["source"]].append((row["target"], row["relationship"]))
    return graph


def shortest_path(graph: dict[str, list[tuple[str, str]]], start: str, target: str):
    """Return the shortest relationship path between two synthetic identities/assets."""
    queue = deque([(start, [])])
    visited = {start}
    while queue:
        node, path = queue.popleft()
        if node == target:
            return path
        for neighbor, relationship in graph.get(node, []):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, path + [(node, relationship, neighbor)]))
    return None


def format_path(path) -> str:
    if path is None:
        return "No path found"
    return "\n".join(f"{source} --{relationship}--> {target}" for source, relationship, target in path)


if __name__ == "__main__":
    graph = load_edges("data/synthetic_identity_edges.csv")
    print(format_path(shortest_path(graph, "alex", "DC-LAB")))

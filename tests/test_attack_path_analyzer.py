import tempfile
import unittest
from pathlib import Path

from src.attack_path_analyzer import load_edges, shortest_path


class AttackPathAnalyzerTests(unittest.TestCase):
    def test_shortest_path(self):
        content = "source,target,relationship\na,b,MemberOf\nb,c,AdminTo\na,d,MemberOf\n"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "edges.csv"
            path.write_text(content, encoding="utf-8")
            graph = load_edges(path)
            result = shortest_path(graph, "a", "c")
        self.assertEqual(result, [("a", "MemberOf", "b"), ("b", "AdminTo", "c")])

    def test_unreachable_target(self):
        graph = {"a": [("b", "MemberOf")]}
        self.assertIsNone(shortest_path(graph, "a", "z"))


if __name__ == "__main__":
    unittest.main()

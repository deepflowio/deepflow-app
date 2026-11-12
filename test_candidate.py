import ast
import asyncio
from pathlib import Path
import types
import unittest

path = Path(__file__).parent / 'app/app/common/disjoint_set.py'
tree = ast.parse(path.read_text(encoding='utf-8'))
ns = {'asyncio': asyncio, 'const': types.SimpleNamespace(SUCCESS='SUCCESS', PARTIAL_RESULT='PARTIAL_RESULT')}
nodes = [n for n in tree.body if isinstance(n, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))]
exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), ns)

class NodeTest(unittest.TestCase):
    def test_deep_chain(self):
        cls = ns['DisjointSet']
        tree = cls()
        for i in range(1500):
            tree.put(i, i - 1)
        self.assertEqual(tree.get(1499), 0)
        self.assertEqual(tree.disjoint_set[1499], 0)

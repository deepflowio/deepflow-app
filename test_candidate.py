import ast
import asyncio
from pathlib import Path
import types
import unittest

path = Path(__file__).parent / 'app/app/data/querier_client.py'
tree = ast.parse(path.read_text(encoding='utf-8'))
ns = {'asyncio': asyncio, 'const': types.SimpleNamespace(SUCCESS='SUCCESS', PARTIAL_RESULT='PARTIAL_RESULT')}
nodes = [n for n in tree.body if isinstance(n, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))]
exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), ns)

class NodeTest(unittest.TestCase):
    def test_empty_and_filtered_queries(self):
        obj = ns['Querier']()
        self.assertEqual(asyncio.run(obj.exec_query({}, 'db', 'sql')), [])
        self.assertEqual(asyncio.run(obj.exec_query({'a':'host'}, 'db', 'sql', region_name='b')), [])

import ast
import asyncio
from pathlib import Path
import types
import unittest

path = Path(__file__).parent / 'app/app/common/utils.py'
tree = ast.parse(path.read_text(encoding='utf-8'))
ns = {'asyncio': asyncio, 'const': types.SimpleNamespace(SUCCESS='SUCCESS', PARTIAL_RESULT='PARTIAL_RESULT')}
nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'format_response']
exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), ns)

class NodeTest(unittest.TestCase):
    def test_optional_failed_regions(self):
        status = types.SimpleNamespace(get_status=lambda:206, description='')
        result, code = ns['format_response']('test', status, [])
        self.assertEqual(code, 206)
        self.assertIn('查询数据区域失败', result['description'])

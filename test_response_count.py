import ast
from pathlib import Path
import types
import unittest


class ResponseCountTest(unittest.TestCase):
    def test_zero_total_is_preserved(self):
        path = Path(__file__).parent / 'app/app/common/utils.py'
        tree = ast.parse(path.read_text(encoding='utf-8'))
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                        and node.name == 'format_response')
        namespace = {'const': types.SimpleNamespace(SUCCESS='SUCCESS')}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), 'exec'), namespace)
        status = types.SimpleNamespace(get_status=lambda: 200)
        result, code = namespace['format_response']('test', status, [], total=0)
        self.assertEqual(code, 200)
        self.assertEqual(result['count'], 0)
        result, _ = namespace['format_response']('test', status, [])
        self.assertNotIn('count', result)

import importlib.util
from pathlib import Path
import unittest


class StatusDebugTest(unittest.TestCase):
    def test_repeated_debug_does_not_duplicate_queries(self):
        path = Path(__file__).parent / 'app/app/data/status.py'
        spec = importlib.util.spec_from_file_location('query_status', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        status = module.Status()
        status.append('query', {'status': 200, 'query_uuids': {'region': 'id'}})
        status.to_querier_debug()
        result = status.to_querier_debug()
        self.assertEqual(len(result['_QUERY_IDS']), 1)
        self.assertEqual(len(result['_TSDB_INFO']['QUERIES']), 1)

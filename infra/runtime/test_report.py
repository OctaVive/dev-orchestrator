import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('m09_report', Path(__file__).with_name('report.py'))
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)


class AcceptanceGateTests(unittest.TestCase):
    def test_missing_failed_skipped_changed_and_duplicate_evidence_refuse_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'source.go').write_text('fixture source')
            (root / 'runtime.json').write_text(json.dumps({'fixture': 'not real acceptance'}))
            sha = lambda name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            manifest = {'source': {'source.go': sha('source.go')}, 'evidence': {'runtime.json': sha('runtime.json')}, 'isolated_runtime_acceptance': True}
            ledger = {'milestone': 'P1-M09', 'cases': [{'id': f'R{i:02}', 'status': 'PASS', 'evidence': ['runtime.json']} for i in range(1, 11)]}
            # This is a reporter unit fixture, never milestone evidence.
            self.assertEqual(report.evaluate(root, ledger, manifest)['status'], 'PASS')
            for status in ('FAIL', 'SKIP', 'NOT_RUN', 'INCOMPLETE'):
                bad = copy.deepcopy(ledger)
                bad['cases'][0]['status'] = status
                self.assertEqual(report.evaluate(root, bad, manifest)['status'], 'INCOMPLETE')
            bad = copy.deepcopy(ledger)
            bad['cases'].pop()
            self.assertEqual(report.evaluate(root, bad, manifest)['status'], 'INCOMPLETE')
            bad = copy.deepcopy(ledger)
            bad['cases'][1]['id'] = 'R01'
            self.assertEqual(report.evaluate(root, bad, manifest)['status'], 'INCOMPLETE')
            bad = copy.deepcopy(ledger)
            bad['cases'][0]['evidence'] = []
            self.assertEqual(report.evaluate(root, bad, manifest)['status'], 'INCOMPLETE')
            (root / 'source.go').write_text('changed source')
            self.assertEqual(report.evaluate(root, ledger, manifest)['status'], 'INCOMPLETE')


if __name__ == '__main__':
    unittest.main()

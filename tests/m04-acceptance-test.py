"""Unprivileged helper refusal/diagnostic regressions; never launches a guest."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'infra/builder/m04-acceptance.sh'


@unittest.skipIf(os.geteuid() == 0, 'helper requires a normal user')
class AcceptanceDiagnostics(unittest.TestCase):
    def run_helper(self, evidence, stub=None, action='preflight'):
        env = dict(os.environ, EVIDENCE=str(evidence),
                   M04_DISPOSABLE_HOST='YES-I-AUTHORIZE-REAL-KVM')
        if stub:
            name, body = stub
            binary = evidence / 'tools'
            binary.mkdir()
            command = binary / name
            command.write_text('#!/bin/bash\n' + body + '\n')
            command.chmod(0o700)
            env['PATH'] = str(binary) + os.pathsep + env['PATH']
        return subprocess.run(['bash', str(SCRIPT), action], env=env,
                              capture_output=True, text=True)

    def test_checkout_evidence_explains_refusal(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            result = self.run_helper(Path(directory))
            self.assertEqual(result.returncode, 1)
            self.assertIn('Evidence directory must be outside the checkout.', result.stderr)

    def test_wrong_architecture_explains_blocker_and_records_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            result = self.run_helper(evidence, ('uname', 'echo aarch64'))
            self.assertEqual(result.returncode, 1)
            run, = evidence.glob('preflight.*')
            self.assertIn('BLOCKED: requires x86-64.', (run / 'output.txt').read_text())
            self.assertEqual((run / 'exit-code.txt').read_text(), '1\n')

    def test_failed_inventory_reports_line_and_preserves_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            result = self.run_helper(evidence, ('lscpu', 'exit 42'))
            self.assertEqual(result.returncode, 42)
            run, = evidence.glob('preflight.*')
            self.assertIn('FAILED: acceptance helper line ', (run / 'output.txt').read_text())
            self.assertEqual((run / 'exit-code.txt').read_text(), '42\n')

    def test_host_tests_refuses_unavailable_sudo_before_host_actions(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            result = self.run_helper(
                evidence, ('sudo', '[[ "$*" == "-n true" ]] || exit 99\nexit 1'),
                action='host-tests')
            self.assertEqual(result.returncode, 1)
            run, = evidence.glob('host-tests.*')
            self.assertIn('BLOCKED: sudo -n true failed.',
                          (run / 'output.txt').read_text())
            self.assertEqual((run / 'exit-code.txt').read_text(), '1\n')


if __name__ == '__main__':
    unittest.main()

"""Run integration checks in a fresh process with isolated storage."""
from pathlib import Path
import subprocess
import sys
import unittest


class IntegrationTests(unittest.TestCase):
    def test_isolated_workflows(self):
        result = subprocess.run([sys.executable, str(Path(__file__).with_name("integration_check.py"))],
                                capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

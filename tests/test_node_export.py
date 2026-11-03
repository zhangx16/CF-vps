"""Run pure production JavaScript export tests through the existing CI entrypoint."""
from pathlib import Path
import shutil
import subprocess
import unittest


class NodeExportTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for browser export logic tests')
    def test_regional_templates_and_exact_endpoint_export(self):
        root = Path(__file__).resolve().parent.parent
        result = subprocess.run(['node', str(root/'tests/test_node_export.cjs')], cwd=root,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

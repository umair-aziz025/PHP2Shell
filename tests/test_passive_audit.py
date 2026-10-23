"""Offline regression checks for PHP2Shell's defensive reporting.

Run: python -m unittest discover -s tests -v
These tests do not open sockets or send exploit traffic.
"""
import io
import json
import unittest
from contextlib import redirect_stdout
from unittest import mock

import requests

import php2shell as tool


class FakeSession:
    def __init__(self, headers=None):
        self.headers = {}
        self.verify = True
        self._response_headers = headers or {}

    def get(self, *_args, **_kwargs):
        response = requests.Response()
        response.status_code = 200
        response.headers.update(self._response_headers)
        response._content = b"ok"
        return response


class PassiveAuditTests(unittest.TestCase):
    def scan(self, version, extra_headers=None):
        headers = {"X-Powered-By": f"PHP/{version}"}
        headers.update(extra_headers or {})
        engine = tool.UnifiedPHP2Shell(session=FakeSession(headers))
        return engine.run_passive("http://127.0.0.1:8899/index.php")

    def test_affected_upstream_version(self):
        version, _ = self.scan("8.4.26")
        self.assertEqual(version.status, tool.VulnerabilityStatus.VULNERABLE)
        self.assertIn("vendor backports", version.detail)

    def test_first_fixed_upstream_version(self):
        version, _ = self.scan("8.4.27")
        self.assertEqual(version.status, tool.VulnerabilityStatus.PATCHED)

    def test_future_branch_is_not_automatically_patched(self):
        version, _ = self.scan("8.6.0")
        self.assertEqual(version.status, tool.VulnerabilityStatus.UNKNOWN)

    def test_outside_documented_affected_range_is_not_automatically_vulnerable(self):
        version, _ = self.scan("5.3.29")
        self.assertEqual(version.status, tool.VulnerabilityStatus.UNKNOWN)

    def test_synthetic_lab_does_not_claim_real_exposure(self):
        version, _ = self.scan("8.4.26", {"X-PHP2Shell-Lab": "standalone-fixture"})
        self.assertEqual(version.status, tool.VulnerabilityStatus.UNKNOWN)
        self.assertEqual(version.applicable_cves, [])

    def test_apache_header_does_not_prove_mod_php(self):
        _, header_info = self.scan("8.4.27", {"Server": "Apache/2.4.69"})
        self.assertEqual(header_info.runtime_mode, tool.PHPRuntime.UNKNOWN)

    def test_default_tls_verification(self):
        self.assertTrue(tool.UnifiedPHP2Shell(session=FakeSession()).session.verify)

    def test_oversize_command_is_rejected_not_substituted(self):
        engine = tool.UnifiedPHP2Shell(session=FakeSession())
        result = engine.run_exploit("http://127.0.0.1:8899/index.php",
                                    method="binary",
                                    cmd="echo this command cannot fit")
        self.assertEqual(result.status, tool.ExploitStatus.ERROR)
        self.assertIn("No command was substituted", result.details)

    def test_unrepresentable_command_is_rejected(self):
        engine = tool.UnifiedPHP2Shell(session=FakeSession())
        result = engine.run_exploit("http://127.0.0.1:8899/index.php",
                                    method="binary",
                                    cmd="echo 🔎")
        self.assertEqual(result.status, tool.ExploitStatus.ERROR)

    def test_all_does_not_implicitly_invoke_exploitation(self):
        with (mock.patch.object(tool, "load_custom_wordlist", return_value=[]),
              mock.patch.object(tool.UnifiedPHP2Shell, "run_recon",
                                return_value=tool.ReconResult()),
              mock.patch.object(tool.UnifiedPHP2Shell, "run_passive",
                                return_value=(tool.VersionResult(), tool.HeaderAnalysis())),
              mock.patch.object(tool.UnifiedPHP2Shell, "run_active_probes",
                                return_value=tool.ProbeResult()),
              mock.patch.object(tool.UnifiedPHP2Shell, "run_waf_analysis",
                                return_value=tool.WAFAnalysis()),
              mock.patch.object(tool.UnifiedPHP2Shell, "run_exploit") as exploit,
              mock.patch("sys.argv", ["php2shell", "http://127.0.0.1:8899/", "--all"]),
              redirect_stdout(io.StringIO())):
            self.assertEqual(tool.main(), 0)
            exploit.assert_not_called()

    def test_json_stdout_is_valid_json(self):
        output = io.StringIO()
        with (mock.patch.object(tool, "load_custom_wordlist", return_value=[]),
              mock.patch.object(tool.UnifiedPHP2Shell, "run_passive",
                                return_value=(tool.VersionResult(), tool.HeaderAnalysis())),
              mock.patch("sys.argv", ["php2shell", "http://127.0.0.1:8899/", "--json"]),
              redirect_stdout(output)):
            self.assertEqual(tool.main(), 0)
        data = json.loads(output.getvalue())
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["target"], "http://127.0.0.1:8899/")



if __name__ == "__main__":
    unittest.main()

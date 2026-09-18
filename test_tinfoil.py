#!/usr/bin/env python3
"""Unit tests for tinfoil's pure logic. Run: python3 -m unittest -v test_tinfoil"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import tinfoil as t


class TestRedaction(unittest.TestCase):
    def test_keeps_a_prefix_and_hides_the_middle(self):
        out = t.redact("AKIAIOSFODNN7EXAMPLE")
        self.assertTrue(out.startswith("AKIA"))
        self.assertTrue(out.endswith("LE"))
        self.assertNotIn("IOSFODNN7EXAMP", out)

    def test_short_values_are_fully_masked(self):
        self.assertEqual(t.redact("abc"), "***")
        self.assertNotIn("a", t.redact("secret"))

    def test_never_leaks_the_original(self):
        for value in ["ghp_" + "a" * 36, "x" * 200, "sk-ant-" + "b" * 40]:
            self.assertNotIn(value, t.redact(value))


class TestSecretScanning(unittest.TestCase):
    def test_detects_common_token_shapes(self):
        cases = {
            "AKIAIOSFODNN7EXAMPLE": "AWS access key",
            "ghp_" + "A" * 36: "GitHub token",
            "sk-ant-" + "x" * 40: "Anthropic key",
            "glpat-" + "y" * 20: "GitLab token",
            "npm_" + "z" * 36: "npm token",
            "AIza" + "0" * 35: "Google API key",
            "xoxb-123456789012-abcdefghijkl": "Slack token",
        }
        for token, label in cases.items():
            hits = t.scan_secrets("some context %s trailing" % token)
            self.assertTrue(hits, "no hit for %s" % label)
            self.assertEqual(hits[0][0], label)

    def test_output_is_redacted(self):
        token = "ghp_" + "A" * 36
        hits = t.scan_secrets(token)
        self.assertNotIn(token, hits[0][1])

    def test_ignores_placeholders(self):
        for noise in ["export API_KEY=changeme", "export TOKEN=<your-token>",
                      "export SECRET=${VAULT_SECRET}", "export PASSWORD=xxxxxxxx"]:
            self.assertEqual(t.scan_secrets(noise), [], noise)

    def test_ignores_ordinary_text(self):
        self.assertEqual(t.scan_secrets("git commit -m 'fix the login page'"), [])
        self.assertEqual(t.scan_secrets("cd ~/projects && npm run build"), [])

    def test_history_scan_strips_zsh_timestamps(self):
        lines = [": 1699999999:0;aws configure set x AKIAIOSFODNN7EXAMPLE"]
        hits, total = t.scan_history_lines(lines)
        self.assertEqual(total, 1)
        self.assertEqual(hits[0][2], "aws")


class TestSshKeyEncryption(unittest.TestCase):
    def test_pem_with_dek_info_is_encrypted(self):
        blob = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,X\n"
        self.assertTrue(t._key_is_encrypted(blob))

    def test_pkcs8_encrypted_header(self):
        self.assertTrue(t._key_is_encrypted("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n"))

    def test_unknown_format_returns_none(self):
        self.assertIsNone(t._key_is_encrypted("not a key at all"))

    def test_real_openssh_keys_round_trip(self):
        """Generate both an encrypted and a bare key and classify them correctly."""
        if not any(Path(p, "ssh-keygen").exists() for p in os.environ.get("PATH", "").split(":")):
            self.skipTest("ssh-keygen not available")
        with tempfile.TemporaryDirectory() as tmp:
            bare = Path(tmp, "bare")
            rc = subprocess.call(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(bare)])
            self.assertEqual(rc, 0)
            self.assertIs(t._key_is_encrypted(bare.read_text()), False)

            locked = Path(tmp, "locked")
            rc = subprocess.call(["ssh-keygen", "-q", "-t", "ed25519",
                                  "-N", "correct horse", "-f", str(locked)])
            self.assertEqual(rc, 0)
            self.assertIs(t._key_is_encrypted(locked.read_text()), True)


class TestScoring(unittest.TestCase):
    def finding(self, status, weight=10):
        return t.Finding("id", "t", "system", t.HIGH, weight, status, "", [], [])

    def test_all_passing_is_100(self):
        self.assertEqual(t.score_of([self.finding(t.PASS)] * 3)[0], 100)

    def test_all_failing_is_zero(self):
        self.assertEqual(t.score_of([self.finding(t.FAIL)] * 3)[0], 0)

    def test_warnings_are_half_credit(self):
        self.assertEqual(t.score_of([self.finding(t.WARN)] * 4)[0], 50)

    def test_skipped_checks_leave_the_score_alone(self):
        with_skip = [self.finding(t.PASS), self.finding(t.SKIP)]
        self.assertEqual(t.score_of(with_skip)[0], 100)

    def test_weight_matters(self):
        mixed = [self.finding(t.FAIL, weight=90), self.finding(t.PASS, weight=10)]
        self.assertEqual(t.score_of(mixed)[0], 10)

    def test_no_checks_does_not_divide_by_zero(self):
        self.assertEqual(t.score_of([]), (0, 0))

    def test_grades_cover_the_whole_range(self):
        for score in range(0, 101):
            label, color = t.grade_of(score)
            self.assertTrue(label and isinstance(color, int))
        self.assertEqual(t.grade_of(100)[0], "LEAD LINED")
        self.assertEqual(t.grade_of(0)[0], "TRANSPARENT")


class TestAddressClassification(unittest.TestCase):
    def test_loopback_is_not_public(self):
        for addr in ["127.0.0.1", "::1", "[::1]", "127.0.0.53"]:
            self.assertFalse(t._is_public(addr), addr)

    def test_wildcards_and_lan_are_public(self):
        for addr in ["0.0.0.0", "*", "::", "192.168.1.10"]:
            self.assertTrue(t._is_public(addr), addr)


class TestRendering(unittest.TestCase):
    def test_clip_adds_an_ellipsis_and_respects_width(self):
        out = t.clip("a rather long sentence that will not fit", 20)
        self.assertLessEqual(len(out), 20)
        self.assertTrue(out.endswith("…"))

    def test_clip_leaves_short_text_untouched(self):
        self.assertEqual(t.clip("short", 40), "short")

    def test_big_number_is_five_aligned_rows(self):
        rows = t.big_number(100)
        self.assertEqual(len(rows), 5)
        self.assertEqual(len({len(r) for r in rows}), 1)

    def test_gauge_width_is_stable(self):
        for score in (0, 37, 100):
            self.assertEqual(len(t.gauge(score, 20)), 20)

    def test_ink_is_a_no_op_when_disabled(self):
        plain = t.Ink(False)
        self.assertEqual(plain.bold_fg(1, "hi"), "hi")
        self.assertIn("\x1b[", t.Ink(True).bold_fg(1, "hi"))


class TestCheckRegistry(unittest.TestCase):
    def test_ids_are_unique(self):
        ids = [c.id for c in t.CHECKS]
        self.assertEqual(len(ids), len(set(ids)))

    def test_metadata_is_well_formed(self):
        for c in t.CHECKS:
            self.assertIn(c.category, t.CATEGORIES, c.id)
            self.assertIn(c.severity, t.SEV_RANK, c.id)
            self.assertGreater(c.weight, 0, c.id)
            self.assertTrue(c.platforms, c.id)

    def test_every_check_returns_a_result_on_this_machine(self):
        for c in t.CHECKS:
            if t.SYSTEM not in c.platforms or c.deep:
                continue
            finding = t._run_one(c)
            self.assertIn(finding.status, (t.FAIL, t.WARN, t.PASS, t.SKIP), c.id)
            self.assertTrue(finding.summary, "%s produced an empty summary" % c.id)


class TestEndToEnd(unittest.TestCase):
    def _cli(self, *args):
        return subprocess.run([sys.executable, str(Path(t.__file__)), *args],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_demo_json_is_parseable_and_complete(self):
        proc = self._cli("--demo", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        data = json.loads(proc.stdout.decode())
        for key in ("tinfoil", "score", "grade", "counts", "findings"):
            self.assertIn(key, data)
        self.assertTrue(0 <= data["score"] <= 100)

    def test_demo_report_renders_without_ansi_when_asked(self):
        proc = self._cli("--demo", "--color", "never")
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn(b"\x1b[", proc.stdout)
        self.assertIn(b"PARANOIA SCORE", proc.stdout)

    def test_fail_under_controls_the_exit_code(self):
        self.assertEqual(self._cli("--demo", "--json", "--fail-under", "0").returncode, 0)
        self.assertEqual(self._cli("--demo", "--json", "--fail-under", "100").returncode, 1)

    def test_list_names_every_check(self):
        proc = self._cli("--list")
        self.assertEqual(proc.returncode, 0)
        for cid in ("ssh-keys", "dotenv-exposure", "exposed-ports"):
            self.assertIn(cid.encode(), proc.stdout)

    def test_the_tool_makes_no_network_calls(self):
        """The privacy promise is load-bearing: no networking modules imported."""
        source = Path(t.__file__).read_text()
        for banned in ("import urllib", "import http", "import requests",
                       "import ftplib", "import smtplib", "socket.socket"):
            self.assertNotIn(banned, source, "found %r in tinfoil.py" % banned)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestNoBlindPasses(unittest.TestCase):
    """A check that could not look must never report PASS."""

    def setUp(self):
        self._real = dict(t._SOCKET_CACHE)
        t._SOCKET_CACHE.clear()
        t._SOCKET_CACHE["v"] = []          # pretend enumeration failed

    def tearDown(self):
        t._SOCKET_CACHE.clear()
        t._SOCKET_CACHE.update(self._real)

    def test_ssh_server_skips_when_sockets_are_unreadable(self):
        self.assertEqual(t.chk_ssh_server().status, t.SKIP)

    def test_docker_does_not_claim_local_only_when_sockets_are_unreadable(self):
        self.assertNotEqual(t.chk_docker_exposure().status, t.PASS)


class TestUnsupportedPlatform(unittest.TestCase):
    def setUp(self):
        self._saved = (t.SYSTEM, t.IS_MAC, t.IS_LINUX)
        t.SYSTEM, t.IS_MAC, t.IS_LINUX = "Windows", False, False

    def tearDown(self):
        t.SYSTEM, t.IS_MAC, t.IS_LINUX = self._saved

    def test_explains_itself_instead_of_matching_nothing(self):
        import contextlib, io as _io
        err = _io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = t.main(["--color", "never"])
        self.assertEqual(rc, 2)
        self.assertIn("not supported", err.getvalue())
        self.assertIn("WSL", err.getvalue())

    def test_demo_still_works_everywhere(self):
        import contextlib, io as _io
        out = _io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = t.main(["--demo", "--color", "never"])
        self.assertEqual(rc, 0)
        self.assertIn("PARANOIA SCORE", out.getvalue())

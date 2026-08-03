import argparse
import json
import unittest

from analisis_vulnerabilidades import (
    ScanResult,
    WebVulnScanError,
    build_nmap_command,
    collect_targets,
    normalize_target,
    render_json_report,
    resolve_profile,
    validate_ports,
)


class TargetValidationTests(unittest.TestCase):
    def test_normalizes_url_to_hostname(self):
        self.assertEqual(normalize_target("https://example.com/login"), "example.com")

    def test_accepts_cidr(self):
        self.assertEqual(normalize_target("192.168.1.0/24"), "192.168.1.0/24")

    def test_keeps_single_ip_without_cidr_suffix(self):
        self.assertEqual(normalize_target("192.168.1.10"), "192.168.1.10")

    def test_rejects_unsafe_target(self):
        with self.assertRaises(WebVulnScanError):
            normalize_target("example.com;rm -rf /")


class PortValidationTests(unittest.TestCase):
    def test_accepts_port_ranges(self):
        self.assertEqual(validate_ports("80,443,8000-8080"), "80,443,8000-8080")

    def test_rejects_out_of_range_ports(self):
        with self.assertRaises(WebVulnScanError):
            validate_ports("0,443")


class ProfileTests(unittest.TestCase):
    def test_resolves_spanish_alias(self):
        self.assertEqual(resolve_profile("estandar").name, "standard")

    def test_ports_override_profile_ports(self):
        command = build_nmap_command(
            "nmap",
            resolve_profile("standard"),
            ["example.com"],
            ports="443",
        )
        self.assertIn("-p", command)
        self.assertIn("443", command)
        self.assertNotIn("--top-ports", command)


class ArgumentCollectionTests(unittest.TestCase):
    def test_collect_targets_deduplicates_positional_and_option_targets(self):
        args = argparse.Namespace(
            targets=["https://example.com/login"],
            target=["example.com"],
        )
        self.assertEqual(collect_targets(args), ["example.com"])


class ReportTests(unittest.TestCase):
    def test_json_report_is_machine_readable(self):
        result = ScanResult(
            started_at="2026-08-03T00:00:00+00:00",
            duration_seconds=0,
            command=["nmap", "example.com"],
            targets=["example.com"],
            profile="quick",
            exit_code=0,
            stdout="ok",
            stderr="",
        )
        payload = json.loads(render_json_report(result))
        self.assertEqual(payload["profile"], "quick")
        self.assertEqual(payload["targets"], ["example.com"])


if __name__ == "__main__":
    unittest.main()

"""Static regressions for rebuilding SNI/QUIC chains from current YAML."""

import re
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "iptables.sh"
SOURCE = SCRIPT.read_text(encoding="utf-8")


def function_body(name):
    match = re.search(
        rf"^{re.escape(name)}\(\) \{{\n(.*?)^\}}\s*$",
        SOURCE,
        re.MULTILINE | re.DOTALL,
    )
    if not match:
        raise AssertionError(f"Function not found: {name}")
    return match.group(1)


class RuleConvergenceTests(unittest.TestCase):
    def test_shrinking_tcp_uid_or_port_set_flushes_v4_v6_chains(self):
        for family, chain, command in (
            ("4", "AGHMOD_SNI4", "iptables"),
            ("6", "AGHMOD_SNI6", "ip6tables"),
        ):
            with self.subTest(chain=chain):
                body = function_body(f"ensure_sni{family}_rules")
                flush = body.index(f"{command} -w 2 -t filter -F {chain}")
                rebuild = body.index("for sni_port in $sni_ports")
                self.assertLess(flush, rebuild)
                self.assertIn("for sni_uid_segment in $sni_uid_range", body)
                self.assertIn(f"sni_tcp_rule {command} -A {chain}", body)

        maintain = function_body("maintain_sni_rules")
        self.assertIn("if ! ensure_sni4_rules; then", maintain)
        self.assertIn("if ! ensure_sni6_rules; then", maintain)
        self.assertNotIn("sni4_rules_are_valid", maintain)
        self.assertNotIn("sni6_rules_are_valid", maintain)

    def test_shrinking_quic_port_or_uid_set_flushes_v4_v6_chains(self):
        for family, chain, command in (
            ("4", "AGHMOD_QUIC4", "iptables"),
            ("6", "AGHMOD_QUIC6", "ip6tables"),
        ):
            with self.subTest(chain=chain):
                body = function_body(f"ensure_quic{family}_rules")
                flush = body.index(f"{command} -w 2 -t filter -F {chain}")
                rebuild = body.index("for sni_port in $sni_quic_ports")
                self.assertLess(flush, rebuild)
                self.assertIn("for sni_uid_segment in $sni_uid_range", body)
                self.assertIn(f"sni_quic_rule {command} -A {chain}", body)

        maintain = function_body("maintain_quic_rules")
        self.assertIn("if ! ensure_quic4_rules; then", maintain)
        self.assertIn("if ! ensure_quic6_rules; then", maintain)
        self.assertNotIn("quic4_rules_are_valid", maintain)
        self.assertNotIn("quic6_rules_are_valid", maintain)


if __name__ == "__main__":
    unittest.main()

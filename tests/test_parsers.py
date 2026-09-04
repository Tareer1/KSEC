from __future__ import annotations

from ksec.parsers.dns import DigParser
from ksec.parsers.nmap_xml import NmapXmlParser
from tests import KsecTestCase

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames><hostname name="target.example.com" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

DIG_OUTPUT = """; <<>> DiG 9.18 <<>> example.com A
;; ANSWER SECTION:
example.com.		3600	IN	A	93.184.216.34
example.com.		3600	IN	AAAA	2606:2800:220:1:248:1893:25c8:1946
;; Query time: 12 msec
"""


class NmapParserTest(KsecTestCase):
    def test_parses_hosts_and_ports(self):
        result = NmapXmlParser().parse(NMAP_XML)
        self.assertEqual(result.tool, "nmap")
        self.assertEqual(len(result.entities), 1)
        host = result.entities[0]
        self.assertIn("10.0.0.5", host["addresses"])
        self.assertIn("target.example.com", host["hostnames"])
        self.assertEqual(len(host["ports"]), 3)
        self.assertEqual(host["ports"][0]["port"], "22")
        self.assertEqual(host["ports"][0]["service"], "ssh")
        self.assertEqual(host["ports"][1]["state"], "open")

    def test_malformed_output_does_not_crash(self):
        result = NmapXmlParser().parse("<nmaprun><broken>")
        self.assertEqual(result.entities, [])


class DigParserTest(KsecTestCase):
    def test_parses_records(self):
        result = DigParser().parse(DIG_OUTPUT)
        types = [e["record_type"] for e in result.entities]
        self.assertIn("A", types)
        self.assertIn("AAAA", types)
        a_record = next(e for e in result.entities if e["record_type"] == "A")
        self.assertEqual(a_record["value"], "93.184.216.34")
        self.assertEqual(a_record["name"], "example.com")


if __name__ == "__main__":
    import unittest

    unittest.main()
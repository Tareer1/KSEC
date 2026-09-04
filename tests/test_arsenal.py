"""Tests for the real offensive arsenal (wpscan, hydra, enum4linux, smbmap,
dnsrecon, whatweb, theHarvester)."""
from __future__ import annotations

from ksec.adapters.base import CommandRequest
from ksec.adapters.dnsrecon import DnsreconAdapter
from ksec.adapters.enum4linux import Enum4LinuxAdapter
from ksec.adapters.hydra import HydraAdapter
from ksec.adapters.smbmap import SmbMapAdapter
from ksec.adapters.theharvester import TheHarvesterAdapter
from ksec.adapters.whatweb import WhatwebAdapter
from ksec.adapters.wpscan import WpscanAdapter
from ksec.parsers.dnsrecon import DnsreconParser
from ksec.parsers.hydra import HydraParser
from ksec.parsers.smb import Enum4LinuxParser, SmbMapParser
from ksec.parsers.theharvester import TheHarvesterParser
from ksec.parsers.whatweb import WhatwebParser
from ksec.parsers.wpscan import WpscanParser
from tests import KsecTestCase


class AdapterCommandTest(KsecTestCase):
    def test_wpscan_builds_json_command(self):
        cmd = WpscanAdapter().build_command(
            CommandRequest(capability="wpscan", target="example.com", options={"enumerate": "vp"})
        )
        self.assertIn("--format", cmd)
        self.assertIn("json", cmd)
        self.assertIn("http://example.com", cmd)
        self.assertIn("--enumerate", cmd)

    def test_wpscan_keeps_existing_scheme(self):
        cmd = WpscanAdapter().build_command(
            CommandRequest(capability="wpscan", target="https://example.com/wp")
        )
        self.assertIn("https://example.com/wp", cmd)

    def test_hydra_builds_service_url(self):
        cmd = HydraAdapter().build_command(
            CommandRequest(
                capability="auth_test",
                target="10.0.0.5",
                options={"service": "ssh", "user": "admin", "passwords": "/tmp/words.txt", "threads": 4},
            )
        )
        self.assertIn("-l", cmd)
        self.assertIn("admin", cmd)
        self.assertIn("-P", cmd)
        self.assertIn("/tmp/words.txt", cmd)
        self.assertIn("ssh://10.0.0.5", cmd)
        # Never a shell string.
        self.assertNotIn("&&", cmd)
        self.assertNotIn(";", cmd)

    def test_enum4linux_builds_full_scan(self):
        cmd = Enum4LinuxAdapter().build_command(
            CommandRequest(capability="smb_enum", target="192.168.1.20")
        )
        self.assertEqual(cmd[:2], ["enum4linux", "-a"])
        self.assertIn("192.168.1.20", cmd)

    def test_smbmap_builds_guest_command(self):
        cmd = SmbMapAdapter().build_command(
            CommandRequest(capability="smb_map", target="192.168.1.20", options={"guest": True})
        )
        self.assertEqual(cmd[:2], ["smbmap", "-H"])
        self.assertIn("192.168.1.20", cmd)

    def test_dnsrecon_builds(self):
        cmd = DnsreconAdapter().build_command(
            CommandRequest(capability="dns_enum", target="example.com", options={"zone_transfer": True})
        )
        self.assertEqual(cmd[:2], ["dnsrecon", "-d"])
        self.assertIn("example.com", cmd)
        self.assertIn("-z", cmd)


class WpscanParserTest(KsecTestCase):
    def test_parses_plugin_vulns(self):
        sample = """
        {"version": {"number": "6.2.1"}, "interesting_findings": [],
         "plugins": {"akismet": {"slug": "akismet", "version": {"number": "5.3"},
          "vulnerabilities": [{"title": "Akismet <= 5.3 - Missing Authorization (CVE-2023-0001)",
           "fixed_in": "5.3.1", "references": {"cve": ["CVE-2023-0001"]}}]}},
         "main_theme": {"slug": "twentytwentyfour", "version": {"number": "1.0"}}}
        """
        result = WpscanParser().parse(sample)
        self.assertEqual(len(result.entities), 1)
        vuln = result.entities[0]
        self.assertEqual(vuln["type"], "wpscan_vuln")
        self.assertEqual(vuln["slug"], "akismet")
        self.assertEqual(vuln["cve"], "CVE-2023-0001")
        self.assertEqual(vuln["fixed_in"], "5.3.1")

    def test_cve_pulled_from_title_when_missing(self):
        sample = '{"version": {"number": "6.2.1"}, "plugins": {"x": {"version": {"number": "1"}, "vulnerabilities": [{"title": "X - CVE-2024-9999 issue"}]}}}'
        result = WpscanParser().parse(sample)
        self.assertEqual(result.entities[0]["cve"], "CVE-2024-9999")

    def test_garbage_does_not_crash(self):
        result = WpscanParser().parse("not json at all")
        self.assertEqual(result.entities, [])


class HydraParserTest(KsecTestCase):
    def test_parses_success_lines_only(self):
        sample = """
Hydra v9.5 starting at ...
[22][ssh] host: 10.0.0.5   login: admin   password: secret123
[DATA] attacking ssh://10.0.0.5:22/
[22][ssh] host: 10.0.0.5   login: root   password: toor
1 of 1 target successfully completed, 2 valid passwords found
"""
        result = HydraParser().parse(sample)
        self.assertEqual(len(result.entities), 2)
        self.assertEqual(result.entities[0]["type"], "auth_finding")
        self.assertEqual(result.entities[0]["service"], "ssh")
        self.assertEqual(result.entities[1]["password"], "toor")


class SmbParserTest(KsecTestCase):
    def test_enum4linux_parses_shares_and_null_session(self):
        sample = """
[+] Got OS info via ...
[+] Server 10.0.0.5 allows sessions using username '', password ''
\tSharename       Type      Comment
\t---------       ----      -------
\tADMIN$          Disk      Remote Admin
\tshared          Disk
\tIPC$            IPC       Remote IPC
"""
        result = Enum4LinuxParser().parse(sample)
        types = {e["type"] for e in result.entities}
        self.assertIn("smb_share", types)
        self.assertIn("smb_finding", types)
        shares = [e for e in result.entities if e["type"] == "smb_share"]
        self.assertEqual({s["share"] for s in shares}, {"ADMIN$", "shared", "IPC$"})

    def test_smbmap_parses_host_and_permissions(self):
        sample = """
[+] IP: 10.0.0.5:445\tName: FILESRV\tStatus: User \tAdmin: NO
\tDisk                                                    \tPermissions\tComment
\t----                                                 \t-----------\t-------
\tADMIN$                                             \tNO ACCESS\t
\tData                                               \tREAD ONLY\t
"""
        result = SmbMapParser().parse(sample)
        hosts = [e for e in result.entities if e["type"] == "smb_host"]
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["ip"], "10.0.0.5")
        shares = {e["share"]: e["permission"] for e in result.entities if e["type"] == "smb_share"}
        self.assertEqual(shares, {"ADMIN$": "NO ACCESS", "Data": "READ ONLY"})


class DnsreconParserTest(KsecTestCase):
    def test_parses_record_lines(self):
        sample = """
[*] Performing General Enumeration of Domain: example.com
[*] \t A example.com 93.184.216.34
[*] \t AAAA example.com 2606:2800:220:1:248:1893:25c8:1946
[*] \t NS a.iana-servers.net example.com
"""
        result = DnsreconParser().parse(sample)
        records = [e for e in result.entities if e["type"] == "dns_record"]
        self.assertEqual(len(records), 3)
        self.assertEqual(records[0]["record_type"], "A")
        self.assertEqual(records[0]["value"], "93.184.216.34")
        self.assertEqual(records[2]["name"], "a.iana-servers.net")

    def test_plain_type_first_lines(self):
        result = DnsreconParser().parse("A example.com 93.184.216.34\nMX 10 mail.example.com\n")
        types = [e["record_type"] for e in result.entities if e["type"] == "dns_record"]
        self.assertEqual(types, ["A", "MX"])


class WhatwebTest(KsecTestCase):
    def test_builds_command_with_scheme(self):
        cmd = WhatwebAdapter().build_command(
            CommandRequest(capability="web_fingerprint", target="example.com")
        )
        self.assertEqual(cmd[0], "whatweb")
        self.assertIn("http://example.com", cmd)
        self.assertIn("--color=never", cmd)

    def test_keeps_existing_scheme(self):
        cmd = WhatwebAdapter().build_command(
            CommandRequest(capability="web_fingerprint", target="https://example.com/path")
        )
        self.assertIn("https://example.com/path", cmd)

    def test_parses_result_line(self):
        sample = (
            "https://example.com [200 OK] Country[UNITED STATES][US], HTML5, "
            "HTTPServer[cloudflare], IP[104.20.23.154], Title[Example Domain], "
            "WordPress[6.2], jQuery[1.12.4]\n"
        )
        result = WhatwebParser().parse(sample)
        hosts = [e for e in result.entities if e["type"] == "host"]
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["addresses"], ["104.20.23.154"])
        self.assertEqual(hosts[0]["hostnames"], ["example.com"])
        tech = [e for e in result.entities if e["type"] == "web_tech"][0]
        self.assertEqual(tech["status"], 200)
        self.assertEqual(tech["server"], "cloudflare")
        self.assertEqual(tech["title"], "Example Domain")
        found = {(t["name"], t["version"]) for t in tech["technologies"]}
        self.assertIn(("WordPress", "6.2"), found)
        self.assertIn(("jQuery", "1.12.4"), found)

    def test_meta_tokens_not_treated_as_tech(self):
        sample = "http://x.test [301 Moved] HTTPServer[nginx], Allow[GET], Title[x]\n"
        result = WhatwebParser().parse(sample)
        tech = [e for e in result.entities if e["type"] == "web_tech"][0]
        names = [t["name"] for t in tech["technologies"]]
        self.assertNotIn("Allow", names)
        self.assertNotIn("HTTPServer", names)

    def test_garbage_does_not_crash(self):
        result = WhatwebParser().parse("not a whatweb line at all")
        self.assertEqual(result.entities, [])


class TheHarvesterTest(KsecTestCase):
    def test_builds_command(self):
        cmd = TheHarvesterAdapter().build_command(
            CommandRequest(capability="osint_harvest", target="example.com", options={"source": "crtsh", "limit": 50})
        )
        self.assertEqual(cmd[0], "theHarvester")
        self.assertIn("example.com", cmd)
        self.assertIn("crtsh", cmd)
        self.assertIn("50", cmd)

    def test_strips_url_scheme(self):
        cmd = TheHarvesterAdapter().build_command(
            CommandRequest(capability="osint_harvest", target="https://example.com")
        )
        self.assertIn("example.com", cmd)

    def test_parses_hosts_emails_ips(self):
        sample = """
*******************************************************************
*  theHarvester 4.11.1                                             *
*******************************************************************
[*] Target: example.com
[*] Searching crtsh.
[*] No IPs found.
[*] Emails found: 2
---------------------
admin@example.com
webmaster@example.com
[*] Hosts found: 3
---------------------
www.example.com
api.example.com
*.wild.example.com
"""
        result = TheHarvesterParser().parse(sample)
        hosts = [e for e in result.entities if e["type"] == "host"]
        hostnames = {name for h in hosts for name in h.get("hostnames", [])}
        self.assertEqual(hostnames, {"www.example.com", "api.example.com"})
        wild = [e for e in result.entities if e.get("wildcard")]
        self.assertEqual([e["host"] for e in wild], ["*.wild.example.com"])
        emails = [e for e in result.entities if e["type"] == "osint_email"]
        self.assertEqual({e["value"] for e in emails}, {"admin@example.com", "webmaster@example.com"})

    def test_empty_result_does_not_crash(self):
        result = TheHarvesterParser().parse("[*] Hosts found: 0\n---------------------")
        self.assertEqual(result.entities, [])


if __name__ == "__main__":
    import unittest

    unittest.main()

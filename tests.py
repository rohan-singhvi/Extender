"""
tests.py -- Unit tests for wifi-extender.

Run with:
    cd wifi-extender
    python3 -m pytest tests.py -v

Or without pytest:
    python3 tests.py
"""

import unittest
from unittest.mock import patch, MagicMock, mock_open
import subprocess
import os
import tempfile

# Module imports
import util
import capabilities
import ap_manager
import nat_manager
import interface_manager
import dhcp_manager
import monitor
import cleanup



# util.py

class TestUtil(unittest.TestCase):

    @patch("subprocess.run")
    def test_run_success(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["echo", "hi"], returncode=0, stdout="hi\n", stderr=""
        )
        result = util.run(["echo", "hi"])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "hi\n")

    @patch("subprocess.run")
    def test_run_failure_with_check(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["false"], returncode=1, stdout="", stderr="fail"
        )
        with self.assertRaises(RuntimeError) as ctx:
            util.run(["false"], check=True)
        self.assertIn("Command failed", str(ctx.exception))

    @patch("subprocess.run")
    def test_run_failure_without_check(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["false"], returncode=1, stdout="", stderr="fail"
        )
        result = util.run(["false"], check=False)
        self.assertEqual(result.returncode, 1)

    @patch("subprocess.run")
    def test_tool_exists_true(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["which", "ls"], returncode=0, stdout="/usr/bin/ls\n", stderr=""
        )
        self.assertTrue(util.tool_exists("ls"))

    @patch("subprocess.run")
    def test_tool_exists_false(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["which", "nonexistent"], returncode=1, stdout="", stderr=""
        )
        self.assertFalse(util.tool_exists("nonexistent"))

    def test_human_bytes(self):
        self.assertEqual(util.human_bytes(0), "0.0 B")
        self.assertEqual(util.human_bytes(512), "512.0 B")
        self.assertEqual(util.human_bytes(1024), "1.0 KB")
        self.assertEqual(util.human_bytes(1024 * 1024), "1.0 MB")
        self.assertEqual(util.human_bytes(1024 * 1024 * 1024), "1.0 GB")
        self.assertEqual(util.human_bytes(1024 ** 4), "1.0 TB")



# capabilities.py

IW_DEV_OUTPUT = """phy#0
\tInterface wlan0
\t\tifindex 3
\t\twdev 0x1
\t\taddr aa:bb:cc:dd:ee:ff
\t\tssid TestNetwork
\t\ttype managed
\t\tchannel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz
"""

IW_PHY_INFO_WITH_AP = """
\tvalid interface combinations:
\t\t * #{ managed } <= 1, #{ AP } <= 1,
\t\t   total <= 2, #channels <= 1
\tSupported interface modes:
\t\t * managed
\t\t * AP
"""

IW_PHY_INFO_NO_AP = """
\tSupported interface modes:
\t\t * managed
\t\t * monitor
"""


class TestCapabilities(unittest.TestCase):

    @patch("util.run")
    def test_check_required_tools_all_present(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="/usr/bin/x\n", stderr=""
        )
        missing = capabilities.check_required_tools()
        self.assertEqual(missing, [])

    @patch("util.run")
    def test_check_required_tools_some_missing(self, mock_run):
        def side_effect(cmd, **kwargs):
            tool = cmd[1] if len(cmd) > 1 else ""
            found = tool in ("iw", "ip")
            return subprocess.CompletedProcess(
                args=cmd, returncode=0 if found else 1, stdout="", stderr=""
            )
        mock_run.side_effect = side_effect
        missing = capabilities.check_required_tools()
        self.assertIn("hostapd", missing)
        self.assertIn("dnsmasq", missing)
        self.assertIn("iptables", missing)
        self.assertNotIn("iw", missing)

    @patch("capabilities.run")
    def test_parse_iw_dev(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["iw", "dev"], returncode=0, stdout=IW_DEV_OUTPUT, stderr=""
        )
        interfaces = capabilities._parse_iw_dev()
        self.assertEqual(len(interfaces), 1)
        self.assertEqual(interfaces[0].name, "wlan0")
        self.assertEqual(interfaces[0].ssid, "TestNetwork")
        self.assertEqual(interfaces[0].channel, 6)
        self.assertEqual(interfaces[0].mode, "managed")
        self.assertEqual(interfaces[0].phy, "phy0")

    @patch("capabilities.run")
    def test_check_phy_with_ap_support(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=IW_PHY_INFO_WITH_AP, stderr=""
        )
        supports_ap, supports_sta_ap = capabilities._check_phy_capabilities("phy0")
        self.assertTrue(supports_ap)
        self.assertTrue(supports_sta_ap)

    @patch("capabilities.run")
    def test_check_phy_without_ap_support(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=IW_PHY_INFO_NO_AP, stderr=""
        )
        supports_ap, supports_sta_ap = capabilities._check_phy_capabilities("phy0")
        self.assertFalse(supports_ap)
        self.assertFalse(supports_sta_ap)



# ap_manager.py

class TestAPManager(unittest.TestCase):

    def test_validate_ok(self):
        mgr = ap_manager.APManager(
            interface="wlan0_ap", ssid="TestAP",
            passphrase="12345678", channel=6,
        )
        self.assertEqual(mgr.validate(), [])

    def test_validate_bad_passphrase(self):
        mgr = ap_manager.APManager(
            interface="wlan0_ap", ssid="TestAP",
            passphrase="short", channel=6,
        )
        errors = mgr.validate()
        self.assertTrue(any("passphrase" in e.lower() for e in errors))

    def test_validate_bad_ssid(self):
        mgr = ap_manager.APManager(
            interface="wlan0_ap", ssid="x" * 33,
            passphrase="12345678", channel=6,
        )
        errors = mgr.validate()
        self.assertTrue(any("ssid" in e.lower() for e in errors))

    def test_validate_bad_channel_2ghz(self):
        mgr = ap_manager.APManager(
            interface="wlan0_ap", ssid="TestAP",
            passphrase="12345678", channel=99, hw_mode="g",
        )
        errors = mgr.validate()
        self.assertTrue(any("channel" in e.lower() for e in errors))

    def test_validate_bad_channel_5ghz(self):
        mgr = ap_manager.APManager(
            interface="wlan0_ap", ssid="TestAP",
            passphrase="12345678", channel=7, hw_mode="a",
        )
        errors = mgr.validate()
        self.assertTrue(any("channel" in e.lower() for e in errors))

    def test_validate_good_channel_5ghz(self):
        mgr = ap_manager.APManager(
            interface="wlan0_ap", ssid="TestAP",
            passphrase="12345678", channel=36, hw_mode="a",
        )
        self.assertEqual(mgr.validate(), [])

    def test_generate_config_contents(self):
        mgr = ap_manager.APManager(
            interface="wlan0_ap", ssid="MyNet",
            passphrase="secretpass", channel=11,
        )
        path = mgr.generate_config()
        try:
            with open(path) as f:
                content = f.read()
            self.assertIn("interface=wlan0_ap", content)
            self.assertIn("ssid=MyNet", content)
            self.assertIn("channel=11", content)
            self.assertIn("wpa_passphrase=secretpass", content)
            self.assertIn("wpa=2", content)
        finally:
            os.unlink(path)

    def test_generate_config_5ghz_has_ac_extras(self):
        mgr = ap_manager.APManager(
            interface="wlan0_ap", ssid="MyNet",
            passphrase="secretpass", channel=36, hw_mode="a",
        )
        path = mgr.generate_config()
        try:
            with open(path) as f:
                content = f.read()
            self.assertIn("ieee80211ac=1", content)
            self.assertIn("hw_mode=a", content)
        finally:
            os.unlink(path)

    def test_is_running_when_not_started(self):
        mgr = ap_manager.APManager(interface="wlan0_ap")
        self.assertFalse(mgr.is_running)



# nat_manager.py

class TestNATManager(unittest.TestCase):

    @patch("nat_manager.run")
    def test_apply_rules_calls_iptables(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        mgr = nat_manager.NATManager("wlan0", "wlan0_ap", "192.168.4.0/24")
        mgr.apply_rules()

        # Should have called iptables 3 times: MASQUERADE, FORWARD (2x)
        calls = mock_run.call_args_list
        cmds = [c[0][0] for c in calls]
        self.assertEqual(len(cmds), 3)
        self.assertTrue(any("MASQUERADE" in cmd for cmd in cmds))
        self.assertTrue(any("FORWARD" in cmd for cmd in cmds))

    @patch("nat_manager.run")
    def test_apply_rules_sets_flag(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        mgr = nat_manager.NATManager("wlan0", "wlan0_ap")
        self.assertFalse(mgr._rules_applied)
        mgr.apply_rules()
        self.assertTrue(mgr._rules_applied)

    @patch("nat_manager.run")
    def test_remove_rules_uses_delete(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        mgr = nat_manager.NATManager("wlan0", "wlan0_ap")
        mgr._rules_applied = True
        mgr.remove_rules()

        calls = mock_run.call_args_list
        cmds = [c[0][0] for c in calls]
        # All removal calls should use -D, not -A
        for cmd in cmds:
            self.assertNotIn("-A", cmd)
            self.assertIn("-D", cmd)

    @patch("nat_manager.run")
    def test_remove_rules_noop_when_not_applied(self, mock_run):
        mgr = nat_manager.NATManager("wlan0", "wlan0_ap")
        mgr.remove_rules()
        mock_run.assert_not_called()



# interface_manager.py

class TestInterfaceManager(unittest.TestCase):

    def test_gateway_ip_calculation(self):
        mgr = interface_manager.InterfaceManager("wlan0", subnet="192.168.4.0/24")
        self.assertEqual(mgr.gateway_ip, "192.168.4.1")

    def test_gateway_ip_different_subnet(self):
        mgr = interface_manager.InterfaceManager("wlan0", subnet="10.0.0.0/24")
        self.assertEqual(mgr.gateway_ip, "10.0.0.1")

    @patch("interface_manager.run")
    def test_create_virtual_interface(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr=""  # Interface doesn't exist yet
        )
        mgr = interface_manager.InterfaceManager("wlan0", "wlan0_ap")
        mgr.create_virtual_interface()
        self.assertTrue(mgr._created_virtual)

    @patch("interface_manager.run")
    def test_enable_ip_forward(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        mgr = interface_manager.InterfaceManager("wlan0")

        with patch("builtins.open", mock_open(read_data="0\n")):
            mgr.enable_ip_forward()

        self.assertEqual(mgr._original_ip_forward, "0")
        # Should have called sysctl to enable
        sysctl_calls = [c for c in mock_run.call_args_list if "sysctl" in c[0][0]]
        self.assertTrue(len(sysctl_calls) > 0)



# dhcp_manager.py

class TestDHCPManager(unittest.TestCase):

    def test_dhcp_range_calculation(self):
        mgr = dhcp_manager.DHCPManager("wlan0_ap", "192.168.4.1", "192.168.4.0/24")
        self.assertEqual(mgr.range_start, "192.168.4.10")
        self.assertEqual(mgr.range_end, "192.168.4.200")

    def test_dhcp_range_small_subnet(self):
        mgr = dhcp_manager.DHCPManager("wlan0_ap", "10.0.0.1", "10.0.0.0/28")
        # /28 = 14 usable hosts, so range should be limited
        self.assertEqual(mgr.range_start, "10.0.0.10")
        # Should not exceed available hosts

    def test_generate_config_contents(self):
        mgr = dhcp_manager.DHCPManager("wlan0_ap", "192.168.4.1")
        path = mgr.generate_config()
        try:
            with open(path) as f:
                content = f.read()
            self.assertIn("interface=wlan0_ap", content)
            self.assertIn("dhcp-option=3,192.168.4.1", content)
            self.assertIn("192.168.4.10,192.168.4.200", content)
            self.assertIn("server=8.8.8.8", content)
        finally:
            os.unlink(path)
            if mgr._pid_file and os.path.exists(mgr._pid_file):
                os.unlink(mgr._pid_file)



# monitor.py

IW_LINK_OUTPUT = """\
Connected to aa:bb:cc:dd:ee:ff (on wlan0)
\tSSID: HomeNetwork
\tfreq: 2437
\tsignal: -65 dBm
\ttx bitrate: 72.2 MBit/s
"""

IW_STATION_DUMP_OUTPUT = """\
Station 11:22:33:44:55:66 (on wlan0_ap)
\tsignal: -45 dBm
\trx bytes: 1048576
\ttx bytes: 524288
\tconnected time: 3600
Station aa:bb:cc:dd:ee:ff (on wlan0_ap)
\tsignal: -72 dBm
\trx bytes: 2097152
\ttx bytes: 100000
\tconnected time: 120
"""


class TestMonitor(unittest.TestCase):

    @patch("subprocess.run")
    def test_get_upstream_status(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=IW_LINK_OUTPUT, stderr=""
        )
        status = monitor.get_upstream_status("wlan0")
        self.assertEqual(status.ssid, "HomeNetwork")
        self.assertEqual(status.signal_dbm, -65)
        self.assertEqual(status.frequency_mhz, 2437)
        self.assertEqual(status.bitrate_mbps, 72.2)

    @patch("subprocess.run")
    def test_get_connected_clients(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=IW_STATION_DUMP_OUTPUT, stderr=""
        )
        clients = monitor.get_connected_clients("wlan0_ap")
        self.assertEqual(len(clients), 2)

        self.assertEqual(clients[0].mac, "11:22:33:44:55:66")
        self.assertEqual(clients[0].signal_dbm, -45)
        self.assertEqual(clients[0].rx_bytes, 1048576)
        self.assertEqual(clients[0].connected_seconds, 3600)

        self.assertEqual(clients[1].mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(clients[1].signal_dbm, -72)

    def test_enrich_with_dhcp(self):
        clients = [
            monitor.ClientInfo(mac="11:22:33:44:55:66"),
            monitor.ClientInfo(mac="aa:bb:cc:dd:ee:ff"),
        ]
        leases = [
            {"mac": "11:22:33:44:55:66", "ip": "192.168.4.10", "hostname": "phone"},
        ]
        monitor.enrich_with_dhcp(clients, leases)
        self.assertEqual(clients[0].ip, "192.168.4.10")
        self.assertEqual(clients[0].hostname, "phone")
        self.assertIsNone(clients[1].ip)

    def test_signal_bars(self):
        self.assertIn("excellent", monitor.signal_bars(-40))
        self.assertIn("good", monitor.signal_bars(-55))
        self.assertIn("fair", monitor.signal_bars(-65))
        self.assertIn("weak", monitor.signal_bars(-75))
        self.assertIn("very weak", monitor.signal_bars(-85))
        self.assertEqual(monitor.signal_bars(None), "?")



# cleanup.py

class TestCleanupManager(unittest.TestCase):

    def test_registers_and_cleans_up_lifo(self):
        order = []

        class FakeComponent:
            def __init__(self, name):
                self.name = name
            def stop(self):
                order.append(f"stop:{self.name}")
            def teardown(self):
                order.append(f"teardown:{self.name}")

        mgr = cleanup.CleanupManager()
        mgr.register(FakeComponent("first"))
        mgr.register(FakeComponent("second"))
        mgr.cleanup()

        # LIFO order: second torn down before first
        self.assertEqual(order, [
            "stop:second", "teardown:second",
            "stop:first", "teardown:first",
        ])

    def test_cleanup_only_runs_once(self):
        call_count = 0

        class FakeComponent:
            def teardown(self_inner):
                nonlocal call_count
                call_count += 1

        mgr = cleanup.CleanupManager()
        mgr.register(FakeComponent())
        mgr.cleanup()
        mgr.cleanup()  # second call should be a no-op
        self.assertEqual(call_count, 1)

    def test_cleanup_continues_on_error(self):
        results = []

        class BadComponent:
            def teardown(self):
                raise RuntimeError("boom")

        class GoodComponent:
            def teardown(self):
                results.append("ok")

        mgr = cleanup.CleanupManager()
        mgr.register(GoodComponent())
        mgr.register(BadComponent())
        mgr.cleanup()  # should not raise
        self.assertEqual(results, ["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
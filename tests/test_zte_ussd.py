"""Tests for zte_ussd.py against the fake modem (tests/mock_zte.py).

Run from the project folder:
    python3 -m unittest discover -s tests -v
"""

import contextlib
import io
import os
import sys
import tempfile
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mock_zte  # noqa: E402
import zte_ussd  # noqa: E402
from zte_ussd import ZteClient, ZteError, decode_ussd, dcs_alphabet  # noqa: E402

BALANCE = "Your balance is 5.00 €. Valid until 31.12.2026."


class DecodeTests(unittest.TestCase):
    def test_ucs2_non_ascii_and_euro(self):
        text = "Grüße: 5,00 € ÄÖÜß"
        self.assertEqual(decode_ussd(text.encode("utf-16-be").hex().upper(), "72"), text)

    def test_ucs2_even_if_dcs_says_gsm7(self):
        # ZTE firmwares usually convert to UCS2 themselves, the DCS stays the network's
        text = "Balance: 12.34 EUR"
        self.assertEqual(decode_ussd(text.encode("utf-16-be").hex(), "15"), text)

    def test_gsm7_reference_vector(self):
        self.assertEqual(decode_ussd("E8329BFD4697D9EC37", "15"), "hellohello")

    def test_gsm7_extension_table_roundtrip(self):
        for text in ("Balance: 3 € [Bonus {1}]", "1234567", "Abc^~|\\"):
            with self.subTest(text=text):
                self.assertEqual(decode_ussd(mock_zte.gsm7_pack(text), "15"), text)

    def test_plain_text_passthrough(self):
        self.assertEqual(decode_ussd("Your balance: 5 EUR", "15"), "Your balance: 5 EUR")
        self.assertEqual(decode_ussd("", "72"), "")

    def test_dcs_alphabet(self):
        self.assertEqual(dcs_alphabet("15"), "gsm7")
        self.assertEqual(dcs_alphabet("0"), "gsm7")
        self.assertEqual(dcs_alphabet("72"), "ucs2")   # 0x48
        self.assertEqual(dcs_alphabet("17"), "ucs2")   # 0x11
        self.assertEqual(dcs_alphabet("68"), "8bit")   # 0x44
        self.assertEqual(dcs_alphabet("244"), "8bit")  # 0xF4
        self.assertIsNone(dcs_alphabet(""))
        self.assertIsNone(dcs_alphabet("abc"))


class MockCase(unittest.TestCase):
    login_mode, ad_mode = "sha256-ld", "md5"

    def setUp(self):
        self.state = mock_zte.MockState(self.login_mode, self.ad_mode, password="admin", polls_until_ready=2)
        self.server, self.addr = mock_zte.start(self.state)
        self.client = self.make_client()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def make_client(self, ad="auto"):
        c = ZteClient(self.addr, timeout=5)
        c.poll_interval = 0.01
        c.ad_mode = ad
        return c


def _variant(login_mode, ad_mode, ad_option="auto"):
    class Variant(MockCase):
        def setUp(self):
            self.login_mode, self.ad_mode = login_mode, ad_mode
            super().setUp()
            self.client.ad_mode = ad_option

        def test_login_and_balance(self):
            if login_mode != "none":
                self.assertFalse(self.client.is_logged_in())
            self.client.login("admin")
            self.assertTrue(self.client.is_logged_in())
            reply = self.client.ussd_send("*100#")
            self.assertEqual(reply.text, BALANCE)
            self.assertFalse(reply.expects_reply)

        def test_code_reaches_device_unchanged(self):
            self.client.login("admin")
            reply = self.client.ussd_send("*103*12345678901234#")
            self.assertIn("Top up successful", reply.text)
            sent = [f for g, f in self.state.history if g == "USSD_PROCESS"]
            self.assertEqual(sent[-1]["USSD_send_number"], "*103*12345678901234#")
            self.assertEqual(sent[-1]["USSD_operator"], "ussd_send")

        def test_menu_navigation(self):
            self.client.login("admin")
            reply = self.client.ussd_send("*101#")
            self.assertTrue(reply.expects_reply)
            self.assertIn("1 Balance", reply.text)
            reply = self.client.ussd_reply("2")
            self.assertTrue(reply.expects_reply)
            reply = self.client.ussd_reply("1")
            self.assertEqual(reply.text, "Small bundle booked.")
            self.assertFalse(reply.expects_reply)

    Variant.__name__ = Variant.__qualname__ = "Variant_%s_%s" % (login_mode.replace("-", "_"), ad_mode)
    return Variant


# Firmware variants: login method x AD checksum
Variant_base64_none = _variant("base64", "none")
Variant_base64_md5 = _variant("base64", "md5")
Variant_sha256ld_md5 = _variant("sha256-ld", "md5")
Variant_sha256ld_sha256_forced = _variant("sha256-ld", "sha256", ad_option="sha256")
Variant_sha256ld_sha256 = _variant("sha256-ld", "sha256")
Variant_nologin_none = _variant("none", "none")


class BehaviourTests(MockCase):
    def test_wrong_password_reports_remaining_attempts(self):
        with self.assertRaises(ZteError) as cm:
            self.client.login("wrong")
        self.assertIn("Wrong password", str(cm.exception))
        self.assertIn("4", str(cm.exception))

    def test_cancel_open_menu(self):
        self.client.login("admin")
        self.assertTrue(self.client.ussd_send("*101#").expects_reply)
        self.assertTrue(self.client.ussd_cancel())
        self.assertEqual(self.state.history[-1][1]["USSD_operator"], "ussd_cancel")
        self.assertIsNone(self.state.node)

    def test_first_send_cancels_stale_session_like_web_ui(self):
        self.client.login("admin")
        self.client.ussd_send("*100#")
        self.client.ussd_send("*100#")
        ops = [f["USSD_operator"] for g, f in self.state.history if g == "USSD_PROCESS"]
        self.assertEqual(ops, ["ussd_cancel", "ussd_send", "ussd_send"])

    def test_error_flags(self):
        self.client.login("admin")
        # ended by the network: outcome unclear, even when it is fast
        with self.assertRaises(zte_ussd.UnclearResult):
            self.client.ussd_send("*996#")
        # status 4 only after a while: real timeout, outcome unclear
        original = zte_ussd.USSD_INSTANT_REJECT
        zte_ussd.USSD_INSTANT_REJECT = 0
        try:
            with self.assertRaises(zte_ussd.UnclearResult):
                self.client.ussd_send("*999#")
        finally:
            zte_ussd.USSD_INSTANT_REJECT = original
        # no network: certainly nothing executed
        with self.assertRaises(ZteError) as cm:
            self.client.ussd_send("*997#")
        self.assertNotIsInstance(cm.exception, zte_ussd.UnclearResult)
        self.assertIn("No network", str(cm.exception))

    def test_stale_flag_right_after_send_is_not_an_error(self):
        self.client.login("admin")
        self.client._ussd_reset_done = True
        self.state.flag = "4"
        self.state.stale_polls = 3
        self.assertEqual(self.client.ussd_send("*100#").text, BALANCE)

    def test_instant_reject_on_lte_suggests_2g(self):
        # MF79U B03 on LTE: status 4 after 0.5 s, nothing sent, hint to use 2G
        self.client.login("admin")
        with self.assertRaises(ZteError) as cm:
            self.client.ussd_send("*999#")
        self.assertNotIsInstance(cm.exception, zte_ussd.UnclearResult)
        self.assertIn("status '4'", str(cm.exception))
        self.assertIn("dropped the request", str(cm.exception))
        self.assertIn("2G", str(cm.exception))

    def test_timeout_when_network_never_answers(self):
        self.client.login("admin")
        with self.assertRaises(zte_ussd.UnclearResult) as cm:
            self.client.ussd_send("*998#", timeout=1)
        self.assertIn("No answer", str(cm.exception))

    def test_send_sms(self):
        self.client.login("admin")
        self.client.send_sms("1234", "hello")
        self.assertEqual(self.state.sent_sms, [("1234", "hello")])
        sms = [f for g, f in self.state.history if g == "SEND_SMS"][-1]
        self.assertEqual(sms["MessageBody"], "00680065006C006C006F")
        self.assertEqual(sms["encode_type"], "UNICODE")
        self.assertEqual(sms["ID"], "-1")
        self.assertRegex(sms["sms_time"], r"^\d\d;\d\d;\d\d;\d\d;\d\d;\d\d;[+-]?\d+(\.\d+)?$")
        with self.assertRaises(ZteError):
            self.client.send_sms("000", "x")

    def test_gsm7_and_plain_replies(self):
        self.client.login("admin")
        self.assertEqual(self.client.ussd_send("*7#").text, "Balance: 3 EUR [Bonus {1}]")
        self.assertEqual(self.client.ussd_send("*8#").text, "Plain text reply without hex")

    def test_device_rejects_requests_without_referer(self):
        url = "http://%s/goform/goform_get_cmd_process?cmd=loginfo" % self.addr
        with self.assertRaises(urllib.error.HTTPError):
            urllib.request.urlopen(url, timeout=5)

    def test_https_host_is_accepted(self):
        c = ZteClient("https://192.168.0.1/")
        self.assertEqual(c.base, "https://192.168.0.1")
        self.assertEqual(c._headers["Referer"], "https://192.168.0.1/index.html")
        ctx = zte_ussd._device_tls_context()
        self.assertFalse(ctx.check_hostname)

    def test_webui_path_filter(self):
        self.assertIsNone(zte_ussd._webui_path("javascript: void(0)"))
        self.assertIsNone(zte_ussd._webui_path("http://www.zte.com.cn/x.js"))
        self.assertIsNone(zte_ussd._webui_path("../etc/passwd.js"))
        self.assertEqual(zte_ussd._webui_path("./js/main"), "js/main.js")
        self.assertEqual(zte_ussd._webui_path("/js/config/config.js"), "js/config/config.js")
        self.assertIsNone(zte_ussd._webui_path("css/style.css"))

    def test_requests_carry_origin_and_referer(self):
        self.assertEqual(self.client._headers["Origin"], "http://" + self.addr)
        self.assertEqual(self.client._headers["Referer"], "http://%s/index.html" % self.addr)

    def test_wrong_ad_algorithm_is_rejected(self):
        self.client.login("admin")
        self.client.ad_mode = "sha256"  # modem expects md5
        with self.assertRaises(ZteError):
            self.client.ussd_send("*100#")


class CliTests(MockCase):
    def run_cli(self, *argv, stdin_lines=()):
        lines = iter(stdin_lines)
        out, err = io.StringIO(), io.StringIO()
        original_input = zte_ussd.input if hasattr(zte_ussd, "input") else None
        zte_ussd.input = lambda prompt="": next(lines)
        original_init = ZteClient.__init__

        def fast_init(client, *a, **kw):
            original_init(client, *a, **kw)
            client.poll_interval = 0.01

        ZteClient.__init__ = fast_init
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = zte_ussd.main(["--host", self.addr, "--password", "admin"] + list(argv))
        finally:
            ZteClient.__init__ = original_init
            if original_input is None:
                del zte_ussd.input
            else:
                zte_ussd.input = original_input
        return code, out.getvalue(), err.getvalue()

    def test_send(self):
        code, out, err = self.run_cli("send", "*100#")
        self.assertEqual(code, 0, err)
        self.assertIn("5.00 €", out)

    def test_send_menu_then_cancel(self):
        code, out, err = self.run_cli("send", "*101#", stdin_lines=["2", ""])
        self.assertEqual(code, 0, err)
        self.assertIn("2 Large", out)
        self.assertIn("cancelled", out)
        self.assertEqual(self.state.history[-1][1]["USSD_operator"], "ussd_cancel")

    def test_info_needs_no_password(self):
        code, out, err = self.run_cli("info")
        self.assertEqual(code, 0, err)
        self.assertIn("BD_MF79UV1.0.0B07", out)
        self.assertFalse(any(g == "LOGIN" for g, _ in self.state.history))

    def test_error_exit_code(self):
        code, out, err = self.run_cli("send", "*999#")
        self.assertEqual(code, 1)
        self.assertIn("Error", err)

    def test_unclear_result_warns_not_to_resend(self):
        original = mock_zte.topup_node
        mock_zte.topup_node = lambda code: {"flag": "2"}
        try:
            code, out, err = self.run_cli("send", "*103*1234567890123#")
        finally:
            mock_zte.topup_node = original
        self.assertEqual(code, 1)
        self.assertIn("before sending the same code again", err)

    def test_logs_in_even_if_loginfo_already_ok(self):
        self.state.login_mode = "none"  # loginfo says ok, e.g. because of a browser session
        self.assertEqual(self.run_cli("send", "*100#")[0], 0)
        self.assertTrue(any(g == "LOGIN" for g, _ in self.state.history))

    def test_version(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            zte_ussd.main(["--version"])
        self.assertIn(zte_ussd.VERSION, out.getvalue())

    def test_no_login_reuses_browser_session(self):
        self.state.login_mode = "none"  # modem reports loginfo=ok (browser logged in)
        code, out, err = self.run_cli("--no-login", "send", "*100#")
        self.assertEqual(code, 0, err)
        self.assertFalse(any(g == "LOGIN" for g, _ in self.state.history))

    def test_b03_ip_wide_loginfo_needs_own_cookie(self):
        self.state.ip_wide_loginfo = True
        self.make_client().login("admin")  # browser session from the same IP
        code, out, err = self.run_cli("--no-login", "send", "*100#")
        self.assertEqual(code, 1)
        self.assertIn("--cookie", err)
        token = next(iter(self.state.tokens))
        code, out, err = self.run_cli("--cookie", "stok=" + token, "send", "*100#")
        self.assertEqual(code, 0, err)
        self.assertIn("5.00 €", out)

    def test_no_login_without_browser_session_explains(self):
        code, out, err = self.run_cli("--no-login", "send", "*100#")
        self.assertEqual(code, 1)
        self.assertIn("in the browser", err)
        self.assertFalse(any(g == "USSD_PROCESS" for g, _ in self.state.history))

    def test_cookie_from_browser(self):
        self.state.tokens.add("BROWSER123")
        code, out, err = self.run_cli("--cookie", "Cookie: stok=BROWSER123", "send", "*100#")
        self.assertEqual(code, 0, err)
        self.assertIn("5.00 €", out)
        self.assertFalse(any(g == "LOGIN" for g, _ in self.state.history))

    def test_analyze_dumps_webui_and_finds_ussd(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err = self.run_cli("analyze", "--dir", tmp)
            self.assertEqual(code, 0, err)
            for rel in ("index.html", "js/main.js", "js/service.js", "js/lib.js", "tmpl/ussd/ussd.html"):
                self.assertTrue(os.path.exists(os.path.join(tmp, *rel.split("/"))), rel)
        self.assertIn("5 web interface files", out)
        self.assertRegex(out, r"== USSD: [1-9]")
        self.assertIn('goformId:"LOGIN"', out)
        self.assertIn("RD (AD checksum)  yes", out)
        self.assertFalse(any(g == "LOGIN" for g, _ in self.state.history))

    def test_sms_cli(self):
        code, out, err = self.run_cli("sms", "1234", "hello", "world")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.state.sent_sms, [("1234", "hello world")])


if __name__ == "__main__":
    unittest.main()

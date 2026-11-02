#!/usr/bin/env python3
"""Fake ZTE modem (goform API) for testing zte_ussd.py without hardware.

Manual test:
    python3 tests/mock_zte.py --port 8080 --login sha256-ld --ad md5
    python3 zte_ussd.py --host 127.0.0.1:8080 --password admin shell
"""

import argparse
import base64
import hashlib
import json
import secrets
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

GSM7_BASIC = (
    "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?"
    "¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"
)
GSM7_EXT = {"\f": 0x0A, "^": 0x14, "{": 0x28, "}": 0x29, "\\": 0x2F,
            "[": 0x3C, "~": 0x3D, "]": 0x3E, "|": 0x40, "€": 0x65}


def gsm7_pack(text):
    septets = []
    for ch in text:
        if ch in GSM7_EXT:
            septets += [0x1B, GSM7_EXT[ch]]
        else:
            septets.append(GSM7_BASIC.index(ch))
    if len(septets) % 8 == 7:
        septets.append(0x0D)  # USSD padding with CR
    out, acc, bits = bytearray(), 0, 0
    for s in septets:
        acc |= s << bits
        bits += 7
        while bits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            bits -= 8
    if bits:
        out.append(acc & 0xFF)
    return out.hex().upper()


def encode_reply(text, encoding):
    """(ussd_data, ussd_dcs) the way a firmware might deliver them."""
    if encoding == "ucs2":
        return text.encode("utf-16-be").hex().upper(), "72"
    if encoding == "gsm7":
        return gsm7_pack(text), "15"
    return text, "15"  # plain text


# Reply tree: code -> node. action "1" = network expects input, "0" = done.
MENU = {
    "text": "Main menu\n1 Balance\n2 Bundles\n3 Help",
    "action": "1",
    "children": {
        "1": {"text": "Your balance is 5.00 €.", "action": "0"},
        "2": {
            "text": "Bundles:\n1 Small\n2 Large",
            "action": "1",
            "children": {
                "1": {"text": "Small bundle booked.", "action": "0"},
                "2": {"text": "Large bundle booked.", "action": "0"},
            },
        },
        "3": {"text": "Help: 0800 123", "action": "0"},
    },
}

SCENARIOS = {
    "*100#": {"text": "Your balance is 5.00 €. Valid until 31.12.2026.", "action": "0"},
    "*101#": MENU,
    "*102#": {"text": "Your number is 01234567890", "action": "0"},
    "*7#": {"text": "Balance: 3 EUR [Bonus {1}]", "action": "0", "encoding": "gsm7"},
    "*8#": {"text": "Plain text reply without hex", "action": "0", "encoding": "plain"},
    "*999#": {"flag": "4"},   # timeout
    "*998#": {"flag": "15"},  # network never answers
    "*997#": {"flag": "1"},   # no network
    "*996#": {"flag": "2"},   # network ends the session
}


# Minimal web interface for the analyze command
WEBUI = {
    "/index.html": '<html><a href="javascript: void(0)">x</a><a href="http://www.zte.com.cn/">ZTE</a>'
                   '<script src="js/lib.js"></script><script data-main="js/main" src="js/require.js"></script></html>',
    "/js/lib.js": "function hex_md5(s){return s}",
    "/js/main.js": 'require(["service"]); var tmpl = "tmpl/ussd/ussd.html";',
    "/js/service.js": 'function aN(){return{goformId:"LOGIN",password:Base64.encode(p)}}'
                      'function ct(){return{goformId:"USSD_PROCESS",USSD_operator:o}}',
    "/tmpl/ussd/ussd.html": '<div id="ussd_action"></div>',
}


def topup_node(code):
    digits = code[len("*103*"):-1]
    if code.startswith("*103*") and code.endswith("#") and digits.isdigit():
        return {"text": "Top up successful. New balance: 20.00 €.", "action": "0"}
    return None


class MockState:
    def __init__(self, login_mode="sha256-ld", ad_mode="md5", password="admin",
                 encoding="ucs2", polls_until_ready=2):
        self.login_mode = login_mode    # base64 | sha256-ld | none (no login needed)
        self.ad_mode = ad_mode          # none | md5 | sha256
        self.password = password
        self.encoding = encoding
        self.polls_until_ready = polls_until_ready
        self.wa_inner_version = "BD_MF79UV1.0.0B07"
        self.cr_version = "CR_MF79U_V1.0.0B07"
        self.lock = threading.Lock()
        self.tokens = set()
        self.ld = secrets.token_hex(16).upper()
        self.rd = ""
        self.fail_left = 5
        self.flag = ""
        self.polls_left = 0
        self.pending = None
        self.node = None
        self.data_info = {"ussd_action": "", "ussd_dcs": "", "ussd_data": ""}
        self.sms_status = ""
        self.sent_sms = []  # (number, text)
        self.ip_wide_loginfo = False  # MF79U B03: loginfo=ok as soon as anybody is logged in
        self.stale_polls = 0  # polls during which ussd_write_flag still shows the old value
        self.stale_left = 0
        self.stale_flag = ""
        self.history = []  # (goformId, fields) of all POSTs, for tests

    # Helpers

    def _hash(self, text):
        h = hashlib.sha256 if self.ad_mode == "sha256" else hashlib.md5
        return h(text.encode()).hexdigest()

    def expected_ad(self):
        return self._hash(self._hash(self.wa_inner_version + self.cr_version) + self.rd)

    def expected_password(self):
        if self.login_mode == "base64":
            return base64.b64encode(self.password.encode()).decode()
        inner = hashlib.sha256(self.password.encode()).hexdigest().upper()
        return hashlib.sha256((inner + self.ld).encode()).hexdigest().upper()

    def logged_in(self, token):
        return self.login_mode == "none" or token in self.tokens

    # GET

    def get_value(self, key, token):
        if key == "loginfo":
            return "ok" if self.logged_in(token) or (self.ip_wide_loginfo and self.tokens) else ""
        if key == "LD":
            return self.ld if self.login_mode == "sha256-ld" else ""
        if key == "RD":
            if self.ad_mode == "none":
                return ""
            self.rd = secrets.token_hex(16)
            return self.rd
        if key == "wa_inner_version":
            return self.wa_inner_version
        if key == "cr_version":
            return self.cr_version
        if key == "psw_fail_num_str":
            return str(self.fail_left)
        if key == "login_lock_time":
            return "300" if self.fail_left <= 0 else "0"
        if key in ("network_provider", "network_type", "modem_main_state", "signalbar"):
            return {"network_provider": "Example", "network_type": "LTE",
                    "modem_main_state": "modem_init_complete", "signalbar": "4"}[key]
        if not self.logged_in(token):
            return ""
        if key == "ussd_write_flag":
            if self.stale_left > 0:
                self.stale_left -= 1
                return self.stale_flag
            if self.flag == "15" and self.pending is not None:
                self.polls_left -= 1
                if self.polls_left <= 0:
                    self._publish()
            return self.flag
        if key == "ussd_data_info":
            return self.data_info
        if key == "sms_cmd_status_result":
            return self.sms_status
        return ""

    def _publish(self):
        node, self.pending = self.pending, None
        if "flag" in node:
            self.flag = node["flag"]
            if self.flag == "15":
                self.pending = node  # stays stuck
            return
        data, dcs = encode_reply(node["text"], node.get("encoding", self.encoding))
        self.data_info = {"ussd_action": node["action"], "ussd_dcs": dcs, "ussd_data": data}
        self.node = node if node["action"] == "1" else None
        self.flag = "16"

    # POST

    def post(self, form, token):
        goform = form.get("goformId", "")
        self.history.append((goform, dict(form)))
        if goform == "LOGIN":
            return self._login(form)
        if not self.logged_in(token):
            return {"result": "failure"}
        if self.ad_mode != "none":
            if not self.rd or form.get("AD") != self.expected_ad():
                return {"result": "failure"}
            self.rd = ""  # every RD is valid once
        if goform == "USSD_PROCESS":
            return self._ussd(form)
        if goform == "SEND_SMS":
            number = form.get("Number", "")
            text = bytes.fromhex(form.get("MessageBody", "")).decode("utf-16-be")
            self.sent_sms.append((number, text))
            self.sms_status = "2" if number == "000" else "3"
            return {"result": "success"}
        return {"result": "failure"}

    def _login(self, form):
        if self.fail_left <= 0:
            return {"result": "5"}, None
        ok = self.login_mode == "none" or form.get("password") == self.expected_password()
        self.ld = secrets.token_hex(16).upper()
        if not ok:
            self.fail_left -= 1
            return {"result": "3"}, None
        self.fail_left = 5
        token = secrets.token_hex(12)
        self.tokens.add(token)
        return {"result": "0"}, token

    def _ussd(self, form):
        op = form.get("USSD_operator")
        if op == "ussd_send":
            code = form.get("USSD_send_number", "")
            node = SCENARIOS.get(code) or topup_node(code) or {"flag": "4"}
        elif op == "ussd_reply":
            if self.node is None:
                return {"result": "failure"}
            node = self.node["children"].get(form.get("USSD_reply_number", ""),
                                             {"text": "Invalid input.", "action": "0"})
        elif op == "ussd_cancel":
            self.node = None
            node = {"flag": "13"}  # cancel confirmed
        else:
            return {"result": "failure"}
        self.stale_left, self.stale_flag = self.stale_polls, self.flag
        self.pending = node
        self.polls_left = self.polls_until_ready
        self.flag = "15"
        return {"result": "success"}


def make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _token(self):
            for part in self.headers.get("Cookie", "").split(";"):
                name, _, value = part.strip().partition("=")
                if name == "stok":
                    return value.strip('"')
            return None

        def _referer_ok(self):
            return self.headers.get("Referer", "").startswith("http://%s/" % self.headers.get("Host", ""))

        def _send(self, payload, cookie=None, status=200):
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/html")
            if cookie:
                self.send_header("Set-Cookie", 'stok="%s"; path=/; HttpOnly' % cookie)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            url = urllib.parse.urlsplit(self.path)
            if url.path in WEBUI:
                body = WEBUI[url.path].encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                return self.wfile.write(body)
            if url.path != "/goform/goform_get_cmd_process":
                return self._send({}, status=404)
            if not self._referer_ok():
                return self._send({}, status=403)
            q = urllib.parse.parse_qs(url.query)
            cmds = q.get("cmd", [""])[0].split(",")
            if cmds == ["sms_cmd_status_info"] and "sms_cmd" in q:
                cmds = ["sms_cmd_status_result"]  # MF79U B03: status per command
            with state.lock:
                values = {c: state.get_value(c, self._token()) for c in cmds}
            if len(cmds) == 1 and isinstance(values[cmds[0]], dict):
                return self._send(values[cmds[0]])
            self._send(values)

        def do_POST(self):
            if self.path != "/goform/goform_set_cmd_process":
                return self._send({}, status=404)
            if not self._referer_ok():
                return self._send({}, status=403)
            length = int(self.headers.get("Content-Length", "0"))
            form = dict(urllib.parse.parse_qsl(self.rfile.read(length).decode()))
            with state.lock:
                result = state.post(form, self._token())
            if isinstance(result, tuple):
                payload, token = result
                return self._send(payload, cookie=token)
            self._send(result)

    return Handler


def start(state, port=0):
    """Start the server in the background, returns (server, "host:port")."""
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(state))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, "127.0.0.1:%d" % server.server_address[1]


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--login", choices=["base64", "sha256-ld", "none"], default="sha256-ld")
    p.add_argument("--ad", choices=["none", "md5", "sha256"], default="md5")
    p.add_argument("--encoding", choices=["ucs2", "gsm7", "plain"], default="ucs2")
    p.add_argument("--password", default="admin")
    a = p.parse_args()
    srv, addr = start(MockState(a.login, a.ad, a.password, a.encoding), a.port)
    print("Fake modem running at http://%s (login %s, AD %s, password %r). Ctrl+C stops it."
          % (addr, a.login, a.ad, a.password))
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.shutdown()

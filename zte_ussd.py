#!/usr/bin/env python3
"""Send USSD codes through a ZTE MF79U USB modem.

Talks to the same HTTP API as the modem's web interface
(/goform/goform_get_cmd_process and /goform/goform_set_cmd_process).
Needs Python 3.8+ and nothing else. Other ZTE modems with the same kind of
web interface (MF79, MF761, MF833, MF971, MF286, ...) may work too.

Examples:
    python3 zte_ussd.py info              modem and network status, sends nothing
    python3 zte_ussd.py send "*100#"      send a USSD code, answer menus interactively
    python3 zte_ussd.py shell             interactive USSD session
    python3 zte_ussd.py sms 1234 hello    send an SMS
"""

import argparse
import base64
import getpass
import hashlib
import http.cookiejar
import json
import os
import re
import ssl
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import warnings
from collections import Counter

VERSION = "1.0.0"
DEFAULT_HOST = "192.168.0.1"

UNCLEAR_WARNING = ("The modem accepted the request but the result is unknown. "
                   "Check whether it went through before sending the same code again.")


class ZteError(Exception):
    pass


class UnclearResult(ZteError):
    """The modem accepted the request, but its outcome is unknown."""


# Decoding of the USSD reply (ussd_data / ussd_dcs)

# 3GPP TS 23.038 GSM 7 bit default alphabet and extension table (after ESC)
GSM7_BASIC = (
    "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?"
    "¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"
)
GSM7_EXT = {0x0A: "\f", 0x14: "^", 0x28: "{", 0x29: "}", 0x2F: "\\",
            0x3C: "[", 0x3D: "~", 0x3E: "]", 0x40: "|", 0x65: "€"}

_HEX = re.compile(r"[0-9A-Fa-f]+")


def unpack_septets(data):
    """Unpack 7 bit characters (GSM 03.38) from bytes."""
    septets = []
    for i in range(len(data) * 8 // 7):
        byte, shift = divmod(i * 7, 8)
        value = data[byte] >> shift
        if shift > 1 and byte + 1 < len(data):
            value |= data[byte + 1] << (8 - shift)
        septets.append(value & 0x7F)
    # USSD pads a spare 8th septet with CR (or 0)
    if septets and len(septets) % 8 == 0 and septets[-1] in (0x0D, 0x00):
        septets.pop()
    return septets


def gsm7_to_text(septets):
    out, escape = [], False
    for s in septets:
        if escape:
            out.append(GSM7_EXT.get(s, GSM7_BASIC[s]))
            escape = False
        elif s == 0x1B:
            escape = True
        else:
            out.append(GSM7_BASIC[s])
    return "".join(out)


def dcs_alphabet(dcs):
    """Alphabet of a data coding scheme (3GPP TS 23.038, chapter 5).

    Returns "gsm7", "8bit", "ucs2" or None (unknown or not given).
    """
    try:
        d = int(str(dcs).strip(), 0)
    except (TypeError, ValueError):
        return None
    if not 0 <= d <= 0xFF:
        return None
    group = d >> 4
    if group in (0x0, 0x2, 0x3):
        return "gsm7"
    if group == 0x1:
        return "ucs2" if d == 0x11 else "gsm7"
    if group in (0x4, 0x5, 0x6, 0x7, 0x9):
        return ("gsm7", "8bit", "ucs2", None)[(d >> 2) & 0x3]
    if group == 0xF:
        return "8bit" if d & 0x04 else "gsm7"
    return None


def _clean(text):
    """True if the text has no control or replacement characters (line breaks are fine)."""
    for ch in text:
        if ch in "\r\n\t\f":
            continue
        if ch == "�" or unicodedata.category(ch) in ("Cc", "Cs", "Co", "Cn"):
            return False
    return True


def _looks_like_ucs2(raw):
    # UCS2 text in one language uses few distinct high bytes (mostly 0x00,
    # plus 0x20 for €), packed GSM 7 bit uses many.
    highs = raw[0::2]
    covered = sum(n for _, n in Counter(highs).most_common(3))
    return covered >= 0.9 * len(highs)


def decode_ussd(data, dcs=None):
    """Turn ussd_data from the web API into readable text.

    The stock web interface always decodes ussd_data as UCS2 hex (4 hex digits
    per character, decodeMessage() in util.js), whatever the network DCS is.
    Packed GSM 7 bit and plain text are handled as fallbacks.
    """
    s = (data or "").strip()
    if not s:
        return ""
    if not _HEX.fullmatch(s) or len(s) % 2:
        return s  # already plain text
    raw = bytes.fromhex(s)
    alphabet = dcs_alphabet(dcs)

    if len(raw) % 2 == 0 and (alphabet == "ucs2" or _looks_like_ucs2(raw)):
        text = raw.decode("utf-16-be", errors="replace")
        if _clean(text):
            return text
    if alphabet in ("gsm7", None):
        text = gsm7_to_text(unpack_septets(raw))
        if _clean(text):
            return text
    for codec in ("utf-8", "latin-1"):
        text = raw.decode(codec, errors="replace")
        if _clean(text):
            return text
    return s


# HTTP client for the goform API

# ussd_write_flag as interpreted by the stock web interface (com.js / service.js)
USSD_FLAG_DONE = "16"
USSD_FLAG_WAIT = "15"
USSD_FLAG_CANCELLED = "13"
USSD_FLAG_ERRORS = {
    "1": "No network service, USSD is not possible right now.",
    "2": "The network ended the USSD session.",
    "3": "Timeout, no answer from the network.",
    "4": "Timeout, no answer from the network.",
    "unknown": "Timeout, no answer from the network.",
    "10": "The modem is busy, try again in a moment.",
    "41": "Operation not supported.",
    "99": "USSD is not supported by the modem or network.",
}
# Nothing was executed for these values
USSD_FLAG_NOT_EXECUTED = {"1", "41", "99"}
# How long ussd_write_flag may still show the previous value after sending
USSD_START_GRACE = 5.0
# If one of these values comes faster, the modem dropped the request itself
# (MF79U B03 on LTE: status 4 after 0.5 s). The network never answers that fast.
USSD_FLAG_REJECTED = {"3", "4", "unknown"}
USSD_INSTANT_REJECT = 2.0

LOGIN_OK = ("0", "4", "7")


def _sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _md5(text):
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def _sms_time():
    # Format of getCurrentTimeString() in the web interface: "yy;MM;dd;HH;mm;ss;+1"
    t = time.localtime()
    offset = t.tm_gmtoff / 3600
    return time.strftime("%y;%m;%d;%H;%M;%S;", t) + ("+" if offset > 0 else "") + "%g" % offset


def _device_tls_context():
    # For --host https://...: the modem uses a self signed certificate and an
    # old TLS stack without secure renegotiation.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (ssl.SSLError, ValueError, AttributeError):
        pass
    return ctx


class ZteClient:
    def __init__(self, host=DEFAULT_HOST, timeout=10.0, verbose=False):
        self.host = host
        self.base = host.rstrip("/") if "://" in host else "http://" + host
        self.timeout = timeout
        self.verbose = verbose
        self.ad_mode = "auto"      # "auto", "none", "md5", "sha256"
        self.login_mode = "auto"   # "auto", "base64", "sha256", "sha256-ld", "plain"
        self.poll_interval = 1.0   # seconds between status polls (like the web interface)
        self._versions = None
        self._ussd_reset_done = False
        self.own_session = False   # we hold our own session cookie (login or --cookie)
        self._jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._jar),
            urllib.request.HTTPSHandler(context=_device_tls_context()))
        # Without a matching Referer and Origin many ZTE firmwares (MF79U B03 among
        # them) refuse to answer or reject write commands.
        self._headers = {
            "Referer": self.base + "/index.html",
            "Origin": self.base,
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "User-Agent": "Mozilla/5.0 (zte_ussd.py)",
        }

    # Low level

    def _log(self, msg):
        if self.verbose:
            print("  [debug] " + msg, file=sys.stderr)

    def _request(self, path, form=None):
        body = urllib.parse.urlencode(form).encode("ascii") if form is not None else None
        req = urllib.request.Request(self.base + path, data=body, headers=self._headers)
        if body is not None:
            req.add_header("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
        self._log(("POST " if body else "GET ") + path + (" " + _mask(form) if form else ""))
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                text = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            raise ZteError("HTTP error %s for %s" % (e.code, path)) from e
        except (urllib.error.URLError, OSError) as e:
            raise ZteError("Modem not reachable at %s (%s)" % (self.base, getattr(e, "reason", e))) from e
        self._log("-> " + text[:300])
        try:
            return json.loads(text)
        except ValueError:
            raise ZteError("Unexpected answer (not JSON) from %s: %r" % (path, text[:200]))

    def get(self, *cmds, **extra):
        params = {"isTest": "false", "cmd": ",".join(cmds)}
        if len(cmds) > 1:
            params["multi_data"] = "1"
        params.update(extra)
        params["_"] = str(int(time.time() * 1000))
        data = self._request("/goform/goform_get_cmd_process?" + urllib.parse.urlencode(params))
        return data if isinstance(data, dict) else {}

    def post(self, goform_id, **fields):
        form = {"isTest": "false", "goformId": goform_id}
        form.update(fields)
        # MF79U uses MD5 (per its service.js), some newer devices SHA256
        candidates = [self.ad_mode] if self.ad_mode != "auto" else ["md5", "sha256"]
        for algo in candidates:
            ad = self._ad(algo)
            if ad is None:
                form.pop("AD", None)
            else:
                form["AD"] = ad
            data = self._request("/goform/goform_set_cmd_process", form)
            data = data if isinstance(data, dict) else {}
            # With a wrong AD checksum the modem drops the request without
            # executing anything, so a second attempt is safe.
            if ad is None or str(data.get("result", "")).lower() != "failure":
                if self.ad_mode == "auto" and ad is not None:
                    self.ad_mode = algo
                return data
            self._log("AD variant %s rejected" % algo)
        return data

    # AD parameter (CSRF protection of newer firmwares)

    def versions(self):
        if self._versions is None:
            v = self.get("wa_inner_version", "cr_version")
            self._versions = (v.get("wa_inner_version", ""), v.get("cr_version", ""))
        return self._versions

    def _ad(self, algo):
        # AD = H(H(wa_inner_version + cr_version) + RD), RD changes per request
        if algo == "none":
            return None
        rd = self.get("RD").get("RD", "")
        if not rd:
            return None  # firmware without AD check
        h = _sha256 if algo == "sha256" else _md5
        wa, cr = self.versions()
        return h(h(wa + cr) + rd)

    # Login

    def use_cookie(self, cookie):
        """Use a session cookie from the browser, e.g. "stok=ABC123"."""
        cookie = cookie.strip()
        if cookie.lower().startswith("cookie:"):
            cookie = cookie[len("cookie:"):].strip()
        self._headers["Cookie"] = cookie
        self.own_session = True

    def is_logged_in(self):
        return self.get("loginfo").get("loginfo", "").lower() == "ok"

    def login(self, password):
        # Always log in ourselves: some firmwares report loginfo=ok as soon as
        # anybody on this IP is logged in, but commands need our own cookie.
        mode = self.login_mode
        ld = ""
        if mode in ("auto", "sha256-ld"):
            ld = self.get("LD").get("LD", "")
            if mode == "auto":
                mode = "sha256-ld" if ld else "base64"
        if mode == "sha256-ld":
            if not ld:
                raise ZteError("The firmware sends no LD value, login variant sha256-ld does not fit.")
            pw = _sha256(_sha256(password).upper() + ld).upper()
        elif mode == "sha256":
            pw = _sha256(password).upper()
        elif mode == "base64":
            pw = base64.b64encode(password.encode("utf-8")).decode("ascii")
        else:
            pw = password
        self._log("Login variant: " + mode)
        # LOGIN itself is sent without AD, like the web interface does.
        form = {"isTest": "false", "goformId": "LOGIN", "password": pw}
        result = str(self._request("/goform/goform_set_cmd_process", form).get("result", ""))
        self._log("Login result %r, cookies: %s" % (result, ", ".join(c.name for c in self._jar) or "none"))
        if result in LOGIN_OK:
            if self.is_logged_in():
                self.own_session = True
                return
            raise ZteError("Login reported success, but the modem confirms no session (loginfo).")
        if result == "2" and self.is_logged_in():
            self._log("Modem reports an existing session, reusing it")
            return
        raise ZteError(self._login_error(result))

    def fetch(self, path):
        """Fetch a file of the web interface as text, None if it does not exist."""
        req = urllib.request.Request(self.base + "/" + path.lstrip("/"), headers=self._headers)
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except (urllib.error.HTTPError, ValueError):
            return None
        except (urllib.error.URLError, OSError) as e:
            raise ZteError("Modem not reachable at %s (%s)" % (self.base, getattr(e, "reason", e))) from e

    def _login_error(self, result):
        info = self.get("psw_fail_num_str", "login_lock_time")
        left = info.get("psw_fail_num_str", "")
        lock = info.get("login_lock_time", "")
        if result == "3":
            msg = "Wrong password."
        elif result == "8" or (lock and lock not in ("0", "-1")):
            msg = "Login locked after too many failed attempts. Try again in a few minutes."
        elif result == "2":
            msg = "Somebody else is already logged in."
        elif result == "6":
            msg = "The modem wants a new password. Log in once in the web interface."
        else:
            msg = "Login failed (code %r)." % result
        if left not in ("", None):
            msg += " Attempts left according to the modem: %s." % left
        return msg

    # USSD

    def ussd_send(self, code, timeout=60):
        if not self._ussd_reset_done:
            # Like the web interface when it opens its USSD page: end a stale session.
            self._ussd_reset_done = True
            self.ussd_cancel()
        return self._ussd("ussd_send", "USSD_send_number", code, timeout)

    def ussd_reply(self, answer, timeout=60):
        return self._ussd("ussd_reply", "USSD_reply_number", answer, timeout)

    def ussd_cancel(self, timeout=10):
        """End an open USSD session. True if the modem confirms the cancel."""
        res = self.post("USSD_PROCESS", USSD_operator="ussd_cancel")
        if str(res.get("result", "")).lower() != "success":
            return False
        deadline = time.monotonic() + timeout
        while True:
            flag = self._ussd_flag()
            if flag != USSD_FLAG_WAIT or time.monotonic() > deadline:
                return flag == USSD_FLAG_CANCELLED
            time.sleep(self.poll_interval)

    def _session_hint(self):
        if self.own_session:
            return ""
        # MF79U B03: loginfo=ok applies to the whole IP, commands still need our own cookie
        return ("\nReason: without logging in there is no session cookie. Run without "
                "--no-login (enter the password) or pass --cookie 'stok=...' from the browser.")

    def _radio_hint(self):
        # MF79U B03: no circuit switched services on LTE data, USSD needs 2G (GSM).
        net = self.get("network_type", "net_select")
        if "LTE" not in (net.get("network_type", "") + net.get("net_select", "")).upper():
            return ""
        return ("\nThe modem is on LTE (%s, network mode %s). USSD needs 2G here: disconnect "
                "in the web interface, set the network mode to 2G, wait until 'info' no longer "
                "shows LTE, then try again."
                % (net.get("network_type") or "-", net.get("net_select") or "-"))

    def _ussd_flag(self):
        return str(self.get("ussd_write_flag").get("ussd_write_flag", "")).strip()

    def _ussd(self, operator, field, value, timeout):
        before = self._ussd_flag()
        res = self.post("USSD_PROCESS", USSD_operator=operator, notCallback="true", **{field: value})
        if str(res.get("result", "")).lower() != "success":
            raise ZteError("The modem rejected the USSD request, nothing was sent: %s%s"
                           % (json.dumps(res, ensure_ascii=False), self._session_hint()))
        start = time.monotonic()
        waiting_seen = False
        time.sleep(self.poll_interval / 2)
        while True:
            flag = self._ussd_flag()
            elapsed = time.monotonic() - start
            self._log("ussd_write_flag=%r after %.1f s (before %r)" % (flag, elapsed, before))
            if flag == USSD_FLAG_WAIT:
                waiting_seen = True
            elif not waiting_seen and flag == before and elapsed < USSD_START_GRACE:
                pass  # modem has not overwritten the status of the previous request yet
            elif flag == USSD_FLAG_DONE:
                return UssdReply(self.get("ussd_data_info"))
            else:
                msg = "%s (status %r after %.0f s)" % (
                    USSD_FLAG_ERRORS.get(flag, "USSD failed."), flag, elapsed)
                self._log("ussd_data_info: %s" % json.dumps(self.get("ussd_data_info"), ensure_ascii=False))
                if flag in USSD_FLAG_NOT_EXECUTED:
                    raise ZteError(msg)
                if flag in USSD_FLAG_REJECTED and elapsed < USSD_INSTANT_REJECT:
                    # The network cannot answer that fast: the request never reached it
                    raise ZteError(msg.replace(USSD_FLAG_ERRORS["4"],
                                               "The modem dropped the request right away.")
                                   + self._radio_hint())
                raise UnclearResult(msg)
            if elapsed > timeout:
                raise UnclearResult("No answer from the network within %d s." % timeout)
            time.sleep(self.poll_interval)

    # SMS

    def send_sms(self, number, text, timeout=15):
        res = self.post("SEND_SMS", notCallback="true", Number=number, sms_time=_sms_time(),
                        MessageBody=text.encode("utf-16-be").hex().upper(), ID="-1",
                        encode_type="UNICODE")
        if str(res.get("result", "")).lower() != "success":
            raise ZteError("The modem rejected the SMS: %s%s"
                           % (json.dumps(res, ensure_ascii=False), self._session_hint()))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            time.sleep(self.poll_interval / 4)
            # MF79U reports the status per command (sms_cmd 4 = send), older firmwares globally
            info = self.get("sms_cmd_status_info", sms_cmd="4")
            status = str(info.get("sms_cmd_status_result") or info.get("sms_cmd_status_info") or "")
            if status == "3":
                return
            if status == "2":
                raise ZteError("The SMS could not be sent.")
        raise UnclearResult("The modem did not confirm sending. Check the SMS page of the web "
                            "interface before sending again.")


class UssdReply:
    def __init__(self, info):
        self.raw = info
        self.action = str(info.get("ussd_action", "")).strip()
        self.dcs = str(info.get("ussd_dcs", "")).strip()
        self.text = decode_ussd(info.get("ussd_data", ""), self.dcs)

    @property
    def expects_reply(self):
        # ussd_action 1 = network expects input (menu), 0 = done, 2 = ended by network
        return self.action == "1"


def _mask(form):
    shown = dict(form)
    if "password" in shown:
        shown["password"] = "***"
    return urllib.parse.urlencode(shown)


# Command line

INFO_FIELDS = [
    "wa_inner_version", "cr_version", "hardware_version", "web_version",
    "modem_main_state", "network_provider", "network_type", "net_select", "signalbar",
    "ppp_status", "loginfo", "LD", "RD",
]


def connect(args, need_login=True):
    client = ZteClient(args.host, timeout=args.timeout, verbose=args.verbose)
    client._log("zte_ussd.py " + VERSION)
    client.ad_mode = args.ad
    client.login_mode = args.login
    if args.cookie:
        client.use_cookie(args.cookie)
    if need_login and (args.no_login or args.cookie):
        # reuse the login of the browser
        if not client.is_logged_in():
            raise ZteError("The modem reports no active login. Log in at %s in the browser, "
                           "keep the page open and try again." % client.base)
    elif need_login:
        password = args.password or os.environ.get("ZTE_PASSWORD")
        if password is None:
            password = getpass.getpass("Web interface password: ")
        client.login(password)
    return client


def print_reply(reply, raw=False):
    print()
    print(reply.text or "(empty reply)")
    print()
    if raw:
        print("  raw: " + json.dumps(reply.raw, ensure_ascii=False))


def run_session(client, first_code, args):
    """Send a code and keep answering menus until the network ends the session."""
    reply = client.ussd_send(first_code, timeout=args.wait)
    print_reply(reply, args.raw)
    while reply.expects_reply:
        try:
            answer = input("Reply (empty = cancel): ").strip()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if not answer:
            client.ussd_cancel()
            print("Session cancelled.")
            return
        reply = client.ussd_reply(answer, timeout=args.wait)
        print_reply(reply, args.raw)


def cmd_info(args):
    client = connect(args, need_login=False)
    data = client.get(*INFO_FIELDS)
    width = max(len(k) for k in INFO_FIELDS)
    for key in INFO_FIELDS:
        value = data.get(key, "")
        if key in ("LD", "RD") and value:
            value = "(present)"
        print("%s  %s" % (key.ljust(width), value if value != "" else "-"))


# Typical files of ZTE web interfaces (MF761, MF79x, R186x ...); more are
# discovered from index.html and the scripts themselves.
WEBUI_FILES = [
    "index.html", "js/main.js", "js/service.js", "js/com.js", "js/util.js", "js/lib.js",
    "js/set.js", "js/net.js", "js/sim_device.js", "js/login.js", "js/config/config.js",
    "js/config/menu.js", "js/config/ufi/config.js", "js/config/ufi/menu.js", "js/ussd/ussd.js",
]
ANALYZE_PATTERNS = [
    ("USSD", r"USSD_PROCESS|ussd_write_flag|ussd_data_info|#ussd\b|ussd/ussd"),
    ("Login", r'goformId\s*:\s*"LOGIN"'),
    ("AD checksum", r'\bAD\s*[:=]|\.AD\s*=|"AD"|getAD|paswordAlgorithmsCookie'),
    ("RD/LD", r'\bcmd\s*[:=]\s*"(?:RD|LD)"|"RD"|"LD"'),
    ("Hash", r"hex_md5\(|SHA256\(|sha256\("),
    ("USB mode", r"USB_MODE_SWITCH|usb_mode"),
]
_WEBUI_REF = re.compile(r"""(?:src|href|data-main)\s*=\s*["']([^"'#?]+)["']"""
                        r"""|["']((?:\./)?(?:js|subpg|tmpl)/[\w./-]+\.(?:js|html))["']""")


def _webui_path(ref):
    if ".." in ref:
        return None
    path = ref.strip().lstrip("./")
    # real file paths only (no "javascript: void(0)", no other servers)
    if not re.fullmatch(r"[\w][\w./-]*", path):
        return None
    if "." not in path.rsplit("/", 1)[-1]:
        path += ".js"  # data-main="js/main"
    return path if path.endswith((".js", ".html")) else None


def cmd_analyze(args):
    """Download the web interface code and search it for USSD, login and AD."""
    client = connect(args, need_login=False)
    data = client.get(*INFO_FIELDS)
    for key in ("wa_inner_version", "cr_version", "loginfo"):
        print("%-17s %s" % (key, data.get(key, "") or "-"))
    print("%-17s %s" % ("LD (SHA256 login)", "yes" if data.get("LD") else "no"))
    print("%-17s %s" % ("RD (AD checksum)", "yes" if data.get("RD") else "no"))

    queue, seen, texts = list(WEBUI_FILES), set(), {}
    index = None
    while queue and len(seen) < 120:
        path = _webui_path(queue.pop(0))
        if not path or path in seen:
            continue
        seen.add(path)
        text = client.fetch(path)
        if text is None or (path != "index.html" and text == index):
            continue
        if path == "index.html":
            index = text
        texts[path] = text
        dest = os.path.join(args.dir, *path.split("/"))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "w", encoding="utf-8") as f:
            f.write(text)
        queue += [a or b for a, b in _WEBUI_REF.findall(text)]
    print("\n%d web interface files saved to: %s\n" % (len(texts), os.path.abspath(args.dir)))

    for name, pattern in ANALYZE_PATTERNS:
        hits = [(p, m) for p, t in texts.items() for m in re.finditer(pattern, t)]
        print("== %s: %d hits" % (name, len(hits)))
        shown = set()
        for path, m in hits:
            if path in shown or len(shown) >= 3:
                continue
            shown.add(path)
            t = texts[path]
            snippet = re.sub(r"\s+", " ", t[max(0, m.start() - 150):m.end() + 250])
            print("   %s: ...%s..." % (path, snippet))
        print()


def cmd_send(args):
    run_session(connect(args), args.code, args)


def cmd_sms(args):
    if not re.fullmatch(r"\+?[0-9]{2,20}", args.number):
        raise ZteError("Invalid phone number: %s" % args.number)
    text = " ".join(args.text)
    client = connect(args)
    client.send_sms(args.number, text)
    print("SMS sent to %s. Replies arrive as SMS on the SMS page of the web interface." % args.number)


def cmd_shell(args):
    client = connect(args)
    print("Interactive USSD session. Enter a code, empty line to quit.")
    print("Answer menus quickly, the network closes open sessions after about 30 s.")
    while True:
        try:
            code = input("USSD> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not code:
            return
        try:
            run_session(client, code, args)
        except ZteError as e:
            print("Error: %s" % e)


def build_parser():
    p = argparse.ArgumentParser(description="Send USSD codes through the web API of a ZTE MF79U.")
    p.add_argument("--version", action="version", version="zte_ussd.py " + VERSION)
    p.add_argument("--host", default=os.environ.get("ZTE_HOST", DEFAULT_HOST),
                   help="IP or name of the modem, https://IP works too (default: %(default)s)")
    p.add_argument("--password", help="web interface password (else ZTE_PASSWORD or prompt)")
    p.add_argument("--no-login", action="store_true",
                   help="do not log in, reuse the login of the browser")
    p.add_argument("--cookie", help='session cookie from the browser instead of a password, e.g. "stok=ABC123"')
    p.add_argument("--login", choices=["auto", "base64", "sha256", "sha256-ld", "plain"], default="auto",
                   help="force a login variant (default: auto)")
    p.add_argument("--ad", choices=["auto", "none", "md5", "sha256"], default="auto",
                   help="force an AD checksum variant (default: auto)")
    p.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds")
    p.add_argument("--wait", type=int, default=60, help="max seconds to wait for the network")
    p.add_argument("--raw", action="store_true", help="also print the raw reply")
    p.add_argument("-v", "--verbose", action="store_true", help="show the HTTP traffic")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("info", help="modem and network status (sends nothing)").set_defaults(func=cmd_info)
    s = sub.add_parser("send", help="send a USSD code")
    s.add_argument("code", help='e.g. "*100#"')
    s.set_defaults(func=cmd_send)
    sub.add_parser("shell", help="interactive USSD session").set_defaults(func=cmd_shell)
    s = sub.add_parser("sms", help="send an SMS")
    s.add_argument("number", help="recipient")
    s.add_argument("text", nargs="+", help="message text")
    s.set_defaults(func=cmd_sms)
    s = sub.add_parser("analyze", help="save and search the web interface code (sends nothing)")
    s.add_argument("--dir", default="zte_webui", help="target folder (default: %(default)s)")
    s.set_defaults(func=cmd_analyze)
    return p


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except UnclearResult as e:
        print("Error: %s\n%s" % (e, UNCLEAR_WARNING), file=sys.stderr)
        return 1
    except ZteError as e:
        print("Error: %s" % e, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())

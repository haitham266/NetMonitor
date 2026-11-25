# -*- coding: utf-8 -*-
"""
Net Microtik Monitor — نسخة اللابتوب (ويندوز)
نفس منطق تطبيق الأندرويد: مراقبة لحظية مستمرة بالخلفية للميكروتيك عبر API،
HOST / ACTIVE مع استهلاك كل مستخدم، المودمات، الواجهات ومجموع الاستهلاك،
وتنبيهات ويندوز عند انقطاع الإنترنت أو أي مودم.

التشغيل:  python net_monitor.py            (يفتح نافذة البرنامج)
          python net_monitor.py --background (يراقب بالخلفية بدون نافذة)
لا يحتاج أي مكتبات إضافية.
"""
import base64
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

APP_NAME = "Net Microtik Monitor"
PORT = 8766
IS_WIN = os.name == "nt"
CFG_DIR = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "NetMonitor")
CFG_FILE = os.path.join(CFG_DIR, "config.json")
DEFAULTS = {"name": "", "local": "", "cloud": "", "port": "8728", "user": "", "pass": "", "wan": "ether1", "modems": "",
            "notifErr": "1", "notifWarn": "0"}
LOG_MAX = 500

STOP = threading.Event()   # إيقاف البرنامج
FORCE = threading.Event()  # فحص فوري للمودمات

S_LOCK = threading.Lock()
S = {"snap": None, "modems": [], "modemsReady": False, "error": None, "via": "", "events": [], "evId": 0, "gen": 0,
     "logs": [], "logsReady": False, "logError": None, "logUnread": 0, "logVer": 0}

# ======================= الإعدادات =======================
_cfg = None
_cfg_lock = threading.Lock()


def load_cfg():
    global _cfg
    with _cfg_lock:
        if _cfg is None:
            c = dict(DEFAULTS)
            try:
                with open(CFG_FILE, "r", encoding="utf-8") as f:
                    c.update({k: str(v) for k, v in json.load(f).items() if k in DEFAULTS})
            except Exception:
                pass
            _cfg = c
        return dict(_cfg)


def save_cfg(c, persist_pass=True):
    global _cfg
    with _cfg_lock:
        os.makedirs(CFG_DIR, exist_ok=True)
        clean = {k: str(c.get(k, DEFAULTS[k])).strip() for k in DEFAULTS}
        disk = dict(clean)
        if not persist_pass:
            disk["pass"] = ""
        with open(CFG_FILE, "w", encoding="utf-8") as f:
            json.dump(disk, f, ensure_ascii=False, indent=2)
        _cfg = clean


# ======================= الراوترات المحفوظة (مثل نسخة الأندرويد) =======================
ROUTERS_FILE = os.path.join(CFG_DIR, "routers.json")
R_KEYS = ("name", "local", "cloud", "port", "user", "pass", "wan", "modems", "notifErr", "notifWarn")
_rt_lock = threading.RLock()
_rt = None   # {"active": id, "list": [ {id, ...} ]}
DEMO = False


def _new_id():
    return "r%x%03d" % (int(time.time()), int.from_bytes(os.urandom(2), "big") % 1000)


def rt_load():
    global _rt
    with _rt_lock:
        if _rt is None:
            d = {"active": "", "list": []}
            try:
                with open(ROUTERS_FILE, "r", encoding="utf-8") as f:
                    j = json.load(f)
                d["active"] = str(j.get("active", ""))
                for r in j.get("list", []):
                    e = {k: str(r.get(k, DEFAULTS[k])) for k in R_KEYS}
                    e["id"] = str(r.get("id") or _new_id())
                    if not e["local"].strip() and e["cloud"].strip():
                        e["local"], e["cloud"] = e["cloud"].strip(), ""
                    d["list"].append(e)
            except Exception:
                pass
            if not d["list"]:   # الإعدادات القديمة (راوتر واحد) تصير أول راوتر
                c = load_cfg()
                if configured(c):
                    e = {k: c[k] for k in R_KEYS}
                    if not e["local"].strip() and e["cloud"].strip():
                        e["local"], e["cloud"] = e["cloud"].strip(), ""
                    e["id"] = _new_id()
                    d = {"active": e["id"], "list": [e]}
            if d["list"] and not any(r["id"] == d["active"] for r in d["list"]):
                d["active"] = d["list"][0]["id"]
            _rt = d
            if not DEMO:
                rt_save()
        return _rt


def rt_save():
    if DEMO:
        return
    with _rt_lock:
        os.makedirs(CFG_DIR, exist_ok=True)
        with open(ROUTERS_FILE, "w", encoding="utf-8") as f:
            json.dump(_rt, f, ensure_ascii=False, indent=2)


def rt_apply(r, live_pass=None, persist_pass=True):
    """يجعل الراوتر r هو النشط: ينسخ بياناته للإعدادات الحالية ويعيد الاتصال بجلسة واحدة جديدة."""
    c = {k: r.get(k, DEFAULTS[k]) for k in R_KEYS}
    if live_pass is not None:
        c["pass"] = live_pass
    save_cfg(c, persist_pass=persist_pass)
    _rt["active"] = r["id"]
    rt_save()
    with S_LOCK:
        S["gen"] += 1
        S["modemsReady"], S["error"], S["snap"], S["modems"] = False, None, None, []
    Net.reset()
    FORCE.set()


def net_name(c=None):
    return ((c or load_cfg()).get("name") or "").strip() or "شبكتي"


def configured(c):
    return bool(c.get("user") and (c.get("local") or c.get("cloud")))


# ======================= بروتوكول RouterOS API =======================
class Trap(Exception):
    pass


class _Call:
    def __init__(self, on_re=None):
        self.on_re = on_re
        self.rows = []
        self.err = None
        self.fatal = None
        self.ret = None
        self.ev = threading.Event()


class Ros:
    """اتصال API واحد مشترك: كل الأوامر على نفس الجلسة بوسوم .tag (بدون تسجيل دخول متكرر)."""

    def __init__(self, host, port, timeout):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(15)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        try:
            self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        self.dead = False
        self.wlock = threading.Lock()
        self.calls = {}
        self.clock = threading.Lock()
        self.seq = 0

    def close(self):
        self.dead = True
        try:
            self.s.close()
        except Exception:
            pass
        self._fail_all(IOError("انقطع الاتصال بالراوتر"))

    def _fail_all(self, e):
        with self.clock:
            cs = list(self.calls.values())
            self.calls.clear()
        for c in cs:
            c.fatal = e
            c.ev.set()

    @staticmethod
    def enc_len(n):
        if n < 0x80:
            return bytes([n])
        if n < 0x4000:
            return (n | 0x8000).to_bytes(2, "big")
        if n < 0x200000:
            return (n | 0xC00000).to_bytes(3, "big")
        if n < 0x10000000:
            return (n | 0xE0000000).to_bytes(4, "big")
        return b"\xf0" + n.to_bytes(4, "big")

    def _recv(self, n):
        buf = b""
        while len(buf) < n:
            ch = self.s.recv(n - len(buf))
            if not ch:
                raise IOError("انقطع الاتصال بالراوتر")
            buf += ch
        return buf

    def _rlen_from(self, c):
        if c & 0x80 == 0:
            return c
        if c & 0xC0 == 0x80:
            return ((c & 0x3F) << 8) | self._recv(1)[0]
        if c & 0xE0 == 0xC0:
            return ((c & 0x1F) << 16) | int.from_bytes(self._recv(2), "big")
        if c & 0xF0 == 0xE0:
            return ((c & 0x0F) << 24) | int.from_bytes(self._recv(3), "big")
        return int.from_bytes(self._recv(4), "big")

    def _sentence(self):
        words = []
        while True:
            n = self._rlen_from(self._recv(1)[0])
            if n == 0:
                return words
            words.append(self._recv(n).decode("utf-8", "replace"))

    @staticmethod
    def _attrs(sn):
        d = {}
        for w in sn:
            if w.startswith("="):
                i = w.find("=", 1)
                if i > 0:
                    d[w[1:i]] = w[i + 1:]
        return d

    def _send(self, words):
        data = b""
        for w in words:
            b = w.encode("utf-8")
            data += self.enc_len(len(b)) + b
        with self.wlock:
            self.s.sendall(data + b"\x00")

    def login(self, user, pw):
        self._send(["/login", "=name=" + user, "=password=" + pw])
        err = None
        while True:
            sn = self._sentence()
            if not sn:
                continue
            if sn[0] == "!trap":
                err = self._attrs(sn).get("message", "error")
            elif sn[0] == "!fatal":
                raise IOError("fatal")
            elif sn[0] == "!done":
                if err is not None:
                    raise Trap(err)
                break
        self.s.settimeout(None)
        threading.Thread(target=self._read_loop, daemon=True).start()

    def _read_loop(self):
        try:
            while not self.dead:
                sn = self._sentence()
                if not sn:
                    continue
                tag = None
                for w in sn:
                    if w.startswith(".tag="):
                        tag = w[5:]
                        break
                c = self.calls.get(tag) if tag is not None else None
                if c is None:
                    continue
                t = sn[0]
                if t == "!re":
                    a = self._attrs(sn)
                    if c.on_re:
                        c.on_re(a)
                    else:
                        c.rows.append(a)
                elif t == "!trap":
                    c.err = self._attrs(sn).get("message", "error")
                elif t == "!fatal":
                    c.fatal = IOError("fatal")
                    self.calls.pop(tag, None)
                    c.ev.set()
                elif t == "!done":
                    c.ret = self._attrs(sn).get("ret")
                    self.calls.pop(tag, None)
                    c.ev.set()
        except Exception as e:
            self.dead = True
            try:
                self.s.close()
            except Exception:
                pass
            self._fail_all(e if isinstance(e, IOError) else IOError(str(e)))

    def _start(self, words, on_re=None):
        if self.dead:
            raise IOError("انقطع الاتصال بالراوتر")
        with self.clock:
            self.seq += 1
            tag = str(self.seq)
            c = _Call(on_re)
            self.calls[tag] = c
        try:
            self._send(list(words) + [".tag=" + tag])
        except Exception:
            self.calls.pop(tag, None)
            self.close()
            raise
        return tag, c

    def cmd(self, *words):
        tag, c = self._start(words)
        if not c.ev.wait(20):
            self.calls.pop(tag, None)
            self.close()
            raise IOError("انتهت مهلة الراوتر")
        if c.fatal:
            raise c.fatal
        if c.err is not None:
            raise Trap(c.err)
        res = list(c.rows)
        if c.ret is not None and not res:
            res.append({"ret": c.ret})
        return res

    def stream(self, words, stop, on_idle, on_re):
        """بث مستمر (مثل /log/print follow-only) على نفس الاتصال."""
        tag, c = self._start(words, on_re)
        try:
            while True:
                if stop():
                    try:
                        self._send(["/cancel", "=tag=" + tag])
                    except Exception:
                        pass
                    raise IOError("stop")
                if c.ev.wait(3):
                    break
                on_idle()
        finally:
            self.calls.pop(tag, None)
        if c.fatal:
            raise c.fatal
        if c.err is not None and c.err != "interrupted":
            raise Trap(c.err)


def friendly(e):
    m = str(e)
    if isinstance(e, Trap):
        return m
    if isinstance(e, socket.gaierror):
        return "عنوان الراوتر غير صحيح"
    if isinstance(e, ConnectionRefusedError):
        return "الاتصال مرفوض — تأكد أن خدمة API مفعلة والمنفذ صحيح"
    if isinstance(e, (socket.timeout, TimeoutError)) or "timed out" in m:
        return "انتهت مهلة الاتصال — تأكد من العنوان والمنفذ والإنترنت"
    return m or e.__class__.__name__


def ros_connect(c, set_via=True):
    try:
        port = int(c.get("port") or 8728)
    except ValueError:
        port = 8728
    last = IOError("أدخل عنوان الراوتر من الإعدادات")
    for key, timeout in (("local", 2.5), ("cloud", 8)):
        host = (c.get(key) or "").strip()
        if not host:
            continue
        r = None
        try:
            r = Ros(host, port, timeout)
            r.login(c.get("user", ""), c.get("pass", ""))
            if set_via:
                S["via"] = "محلي LAN" if key == "local" else "كلاود Cloud"
            return r
        except Exception as e:
            if r:
                r.close()
            last = e
    raise last


class _Net:
    """جلسة واحدة فقط مع الراوتر يستخدمها الجميع."""

    def __init__(self):
        self.lock = threading.Lock()
        self.cur = None
        self.fail_at = 0.0
        self.fail_err = None

    def get(self, c, set_via=True):
        with self.lock:
            r = self.cur
            if r is not None and not r.dead:
                return r
            if self.fail_err is not None and time.time() - self.fail_at < 2.5:
                raise self.fail_err
            try:
                r = ros_connect(c, set_via=True)
                self.cur, self.fail_err = r, None
                return r
            except Exception as e:
                self.fail_err, self.fail_at = e, time.time()
                raise

    def drop(self, r):
        with self.lock:
            if r is not None:
                r.close()
            if self.cur is r or (self.cur is not None and self.cur.dead):
                self.cur = None

    def reset(self):
        with self.lock:
            if self.cur is not None:
                self.cur.close()
            self.cur, self.fail_err = None, None


Net = _Net()


# ======================= أدوات =======================
def parse_modems(raw):
    out = []
    ip_re = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
    for line in (raw or "").splitlines():
        t = line.strip()
        if not t:
            continue
        m = ip_re.search(t)
        if not m:
            continue
        ip = m.group(0)
        name = t.replace(ip, "").strip().strip(",;،|:=- \t")
        out.append((name or ip, ip))
    return out


def mb(v):
    try:
        return int(v or 0) // 1048576
    except ValueError:
        return 0


def ps_quote(s):
    return "'" + str(s).replace("'", "''") + "'"


def win_toast(title, text):
    """تنبيه ويندوز (يعمل حتى لو كانت نافذة البرنامج مغلقة)."""
    if not IS_WIN:
        return
    ps = (
        "Add-Type -AssemblyName System.Windows.Forms;Add-Type -AssemblyName System.Drawing;"
        "$n=New-Object System.Windows.Forms.NotifyIcon;"
        "$n.Icon=[System.Drawing.SystemIcons]::Information;"
        "$n.BalloonTipTitle=" + ps_quote(title) + ";"
        "$n.BalloonTipText=" + ps_quote(text) + ";"
        "$n.Visible=$true;$n.ShowBalloonTip(10000);Start-Sleep -Seconds 10;$n.Dispose()"
    )
    enc = base64.b64encode(ps.encode("utf-16-le")).decode()
    try:
        subprocess.Popen(
            ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-EncodedCommand", enc],
            creationflags=0x08000000,
        )
    except Exception:
        pass


def alert(title, text, toast=True, who=None):
    with S_LOCK:
        S["evId"] += 1
        S["events"] = (S["events"] + [{"id": S["evId"], "title": title, "text": text, "ts": int(time.time() * 1000)}])[-30:]
    if toast:
        win_toast(title + " — " + (who or net_name()), text)


# ======================= التشغيل مع ويندوز =======================
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def autostart_cmd():
    if getattr(sys, "frozen", False):
        return '"%s" --background' % sys.executable
    exe = sys.executable
    pyw = os.path.join(os.path.dirname(exe), "pythonw.exe")
    if os.path.isfile(pyw):
        exe = pyw
    return '"%s" "%s" --background' % (exe, os.path.abspath(__file__))


def get_autostart():
    if not IS_WIN:
        return False
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            winreg.QueryValueEx(k, "NetMonitor")
            return True
    except Exception:
        return False


def set_autostart(on):
    if not IS_WIN:
        return
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
        if on:
            winreg.SetValueEx(k, "NetMonitor", 0, winreg.REG_SZ, autostart_cmd())
        else:
            try:
                winreg.DeleteValue(k, "NetMonitor")
            except FileNotFoundError:
                pass


# ======================= الحلقة الرئيسية (كل ثانيتين) =======================
# ======================= مراقبة بقية الراوترات بالخلفية (اتصال واحد لكل راوتر) =======================
_watches = {}


def _sig(r):
    return "|".join(r.get(k, "") for k in ("local", "cloud", "port", "user", "pass", "name", "notifErr", "notifWarn"))


def watch_sync():
    while not STOP.is_set():
        try:
            d = rt_load()
            with _rt_lock:
                want = {r["id"]: dict(r) for r in d["list"] if r["id"] != d["active"] and r.get("user") and (r.get("local") or r.get("cloud"))}
            for rid in list(_watches):
                w = _watches[rid]
                if rid not in want or w["sig"] != _sig(want[rid]):
                    w["stop"].set()
                    try:
                        if w["ros"]:
                            w["ros"].close()
                    except Exception:
                        pass
                    del _watches[rid]
            for rid, r in want.items():
                if rid not in _watches:
                    w = {"sig": _sig(r), "stop": threading.Event(), "ros": None}
                    _watches[rid] = w
                    threading.Thread(target=watch_loop, args=(r, w), daemon=True).start()
        except Exception:
            pass
        STOP.wait(3)
    for w in list(_watches.values()):
        w["stop"].set()
        try:
            if w["ros"]:
                w["ros"].close()
        except Exception:
            pass


def watch_loop(r, w):
    name = r.get("name") or r.get("local") or r.get("cloud") or "راوتر"
    cc = {k: r.get(k, DEFAULTS[k]) for k in R_KEYS}
    fails, down, last_id = 0, False, -1
    while not STOP.is_set() and not w["stop"].is_set():
        ros = None
        try:
            ros = ros_connect(cc, set_via=False)
            w["ros"] = ros
            if down:
                alert("✅ عاد الاتصال بالراوتر", name, who=name)
                down = False
            fails = 0
            init = [to_log(m) for m in ros.cmd("/log/print", "=.proplist=.id,time,topics,message")]
            init = [e for e in init if e]
            if init:
                last_id = max(last_id, init[-1]["id"])
            pend, st = [], {"last": 0.0}

            def flush(force=False):
                now = time.time()
                if pend and (force or now - st["last"] > 5):
                    reds = sum(1 for e in pend if e["level"] == 2)
                    title = ("🔴 " if reds else "🟡 ") + name + (": خطأ في السجل" if reds else ": تحذير في السجل")
                    alert(title, "\n".join(e["time"] + "  " + e["msg"] for e in pend[-6:]), who=name)
                    pend.clear()
                    st["last"] = now

            def on_re(m):
                nonlocal last_id
                e = to_log(m)
                if e and e["id"] > last_id:
                    last_id = e["id"]
                    if (e["level"] == 2 and cc["notifErr"] == "1") or (e["level"] == 1 and cc["notifWarn"] == "1"):
                        pend.append(e)
                flush()

            ros.stream(["/log/print", "=follow-only=", "=.proplist=.id,time,topics,message"],
                       lambda: STOP.is_set() or w["stop"].is_set(), lambda: flush(), on_re)
        except Exception:
            try:
                if ros:
                    ros.close()
            except Exception:
                pass
            w["ros"] = None
            fails += 1
            if fails >= 3 and not down and not w["stop"].is_set():
                down = True
                alert("🔌 الراوتر لا يستجيب", name, who=name)
        STOP.wait(10 if fails else 3)


def main_loop():
    ros, gen, prev_if, was_wan = None, S["gen"], {}, None
    while not STOP.is_set():
        if gen != S["gen"]:
            Net.reset()
            ros, gen, was_wan = None, S["gen"], None
            prev_if.clear()
        c = load_cfg()
        if not configured(c):
            S["error"] = None
            STOP.wait(1)
            continue
        try:
            r = Net.get(c)
            ros = r
            res = (r.cmd("/system/resource/print") or [{}])[0]
            hl = {}
            try:
                for row in r.cmd("/system/health/print"):
                    if row.get("name"):
                        hl[row["name"]] = row.get("value", "")
                    else:
                        hl.update(row)
            except Trap:
                pass

            host_ok, active_ok = True, True
            try:
                hosts = r.cmd("/ip/hotspot/host/print",
                              "=.proplist=.id,mac-address,address,to-address,uptime,idle-time,authorized,bypassed,comment,bytes-in,bytes-out")
            except Trap:
                host_ok, hosts = False, []
            try:
                active = r.cmd("/ip/hotspot/active/print",
                               "=.proplist=.id,user,address,uptime,bytes-in,bytes-out,mac-address")
            except Trap:
                active_ok, active = False, []

            wan = c.get("wan") or "ether1"
            try:
                rows = r.cmd("/ip/address/print", "?interface=" + wan)
                ip = rows[0].get("address", "-") if rows else "-"
            except Trap:
                ip = "-"

            now = time.time()
            ifs, wan_up = [], False
            for i in r.cmd("/interface/print", "?type=ether", "=.proplist=name,running,disabled,rx-byte,tx-byte"):
                n = i.get("name")
                if not n:
                    continue
                rx, tx = int(i.get("rx-byte") or 0), int(i.get("tx-byte") or 0)
                run, dis = i.get("running") == "true", i.get("disabled") == "true"
                if n == wan:
                    wan_up = run
                rr = tr = 0
                p = prev_if.get(n)
                if p and now > p[2]:
                    rr = max(0, int((rx - p[0]) * 8 / (now - p[2])))
                    tr = max(0, int((tx - p[1]) * 8 / (now - p[2])))
                prev_if[n] = (rx, tx, now)
                ifs.append({"name": n, "running": run, "disabled": dis, "rxRate": rr, "txRate": tr, "totalRx": rx, "totalTx": tx})

            total_mem = max(1, mb(res.get("total-memory")))
            used_mem = total_mem - mb(res.get("free-memory"))
            total_hdd = max(1, mb(res.get("total-hdd-space")))
            used_hdd = total_hdd - mb(res.get("free-hdd-space"))

            snap = {
                "wan": wan, "wanUp": wan_up, "ip": ip,
                "hostOk": host_ok, "hosts": hosts, "activeOk": active_ok, "active": active,
                "uptime": res.get("uptime", "-"),
                "temp": hl.get("temperature") or hl.get("cpu-temperature") or "-",
                "volt": hl.get("voltage") or "-",
                "cpu": int(res.get("cpu-load") or 0),
                "usedMem": used_mem, "totalMem": total_mem, "ramPct": int(used_mem * 100 / total_mem),
                "usedHdd": used_hdd, "totalHdd": total_hdd, "hddPct": int(used_hdd * 100 / total_hdd),
                "ifs": ifs,
            }
            with S_LOCK:
                S["snap"], S["error"] = snap, None

            if was_wan is not None and was_wan != wan_up:
                alert("🟢 عاد الإنترنت" if wan_up else "🔴 انقطع الإنترنت", "الواجهة: " + wan)
            was_wan = wan_up
        except Exception as e:
            if not isinstance(e, Trap):
                Net.drop(ros)
            ros = None
            S["error"] = friendly(e)
        STOP.wait(2)


# ======================= حلقة المودمات (كل ~3 ثواني، 5 اتصالات متوازية) =======================
def modem_loop():
    gen, last_down, first = S["gen"], set(), True
    down_since = {}
    while not STOP.is_set():
        if gen != S["gen"]:
            gen, first, last_down = S["gen"], True, set()
        FORCE.clear()
        c = load_cfg()
        lst = parse_modems(c.get("modems", ""))
        if not lst or not configured(c):
            S["modems"], S["modemsReady"] = [], True
            FORCE.wait(3)
            continue

        prev = {m["ip"]: m for m in S["modems"]}
        workers = min(len(lst), 5)
        results = [None] * len(lst)

        def work(w):
            i = w
            while i < len(lst):
                name, mip = lst[i]
                cn = None
                try:
                    cn = Net.get(c, set_via=False)
                    rows = cn.cmd("/ping", "=address=" + mip, "=count=2", "=interval=0.5")
                    up = any(r.get("received", "0") != "0" or "time" in r for r in rows)
                except Trap:
                    up = False
                except Exception:
                    Net.drop(cn)
                    up = None
                old = prev.get(mip)
                if up is None:
                    results[i] = {"name": name, "ip": mip, "up": old["up"] if old else False, "since": old["since"] if old else None}
                elif up:
                    down_since.pop(mip, None)
                    results[i] = {"name": name, "ip": mip, "up": True, "since": None}
                else:
                    results[i] = {"name": name, "ip": mip, "up": False,
                                  "since": down_since.setdefault(mip, int(time.time() * 1000))}
                i += workers

        ths = [threading.Thread(target=work, args=(w,), daemon=True) for w in range(workers)]
        for t in ths:
            t.start()
        for t in ths:
            t.join()

        stats = [r for r in results if r]
        S["modems"], S["modemsReady"] = stats, True

        now_down = {m["name"] for m in stats if not m["up"]}
        if not first:
            newly = [n for n in now_down if n not in last_down]
            back = [n for n in last_down if n not in now_down]
            if newly:
                alert("🔴 مودم مقطوع", "، ".join(newly))
            if back:
                alert("🟢 عاد الاتصال", "، ".join(back))
        last_down, first = now_down, False
        FORCE.wait(3)


# ======================= سجل الراوتر: بث لحظي + تنبيه للأحمر =======================
def to_log(m):
    try:
        lid = int(m.get(".id", "").lstrip("*"), 16)
    except ValueError:
        return None
    topics = m.get("topics", "")
    t = topics.split(",")
    lvl = 2 if ("error" in t or "critical" in t) else 1 if "warning" in t else 0
    return {"id": lid, "time": m.get("time", ""), "topics": topics, "msg": m.get("message", ""), "level": lvl}


def add_logs(items, notify, pending):
    c = load_cfg()
    with S_LOCK:
        known = S["logs"]
        max_id = known[-1]["id"] if known else -1
        fresh = [e for e in items if e and e["id"] > max_id]
        if not fresh:
            return
        S["logs"] = (known + fresh)[-LOG_MAX:]
        S["logVer"] += 1
        if not notify:
            return
        for e in fresh:
            if e["level"] == 2:
                S["logUnread"] += 1
            if (e["level"] == 2 and c.get("notifErr") == "1") or (e["level"] == 1 and c.get("notifWarn") == "1"):
                pending.append(e)


def log_notify(lst):
    if not lst:
        return
    reds = sum(1 for e in lst if e["level"] == 2)
    if len(lst) == 1:
        title = "🔴 خطأ في سجل الراوتر" if reds else "🟡 تحذير في سجل الراوتر"
    else:
        title = ("🔴 %d رسائل جديدة في السجل (%d أخطاء)" % (len(lst), reds)) if reds else ("🟡 %d تحذيرات جديدة في السجل" % len(lst))
    text = "\n".join(e["time"] + "  " + e["msg"] for e in lst[-4:])
    alert(title, text)


def log_loop():
    my_gen = -1
    while not STOP.is_set():
        if my_gen != S["gen"]:
            my_gen = S["gen"]
            with S_LOCK:
                S["logs"], S["logsReady"], S["logUnread"], S["logError"] = [], False, 0, None
                S["logVer"] += 1
        c = load_cfg()
        if not configured(c):
            STOP.wait(2)
            continue
        r, pending, wait = None, [], 5
        st = {"last": 0.0, "idle": 0.0}

        def flush(force=False):
            now = time.time()
            if pending and (force or now - st["last"] > 5):
                log_notify(list(pending))
                pending.clear()
                st["last"] = now

        try:
            r = Net.get(c, set_via=False)
            first = not S["logsReady"]
            init = [to_log(m) for m in r.cmd("/log/print", "=.proplist=.id,time,topics,message")]
            init = [e for e in init if e]
            known = S["logs"][-1]["id"] if S["logs"] else -1
            if not first and init and init[-1]["id"] < known:   # الراوتر أعاد التشغيل
                S["logs"] = []
                add_logs(init, False, pending)
            else:
                add_logs(init, not first, pending)
            with S_LOCK:
                S["logsReady"], S["logError"] = True, None
                S["logVer"] += 1
            flush(True)

            gen = my_gen

            def on_idle():
                st["idle"] += 3
                flush()

            def on_re(m):
                st["idle"] = 0
                add_logs([to_log(m)], True, pending)
                flush()

            r.stream(["/log/print", "=follow-only=", "=.proplist=.id,time,topics,message"],
                     lambda: STOP.is_set() or gen != S["gen"], on_idle, on_re)
        except Trap as e:
            with S_LOCK:
                S["logError"] = str(e)
                S["logVer"] += 1
            wait = 15
        except Exception as e:
            if str(e) == "stop":
                wait = 0.2
            else:
                wait = 5
                Net.drop(r)
        finally:
            flush(True)
        STOP.wait(wait)


# ======================= أوامر من الواجهة =======================
def do_action(body):
    t = body.get("type")
    if t == "refresh":
        FORCE.set()
        return {"ok": True}
    if t == "logread":
        S["logUnread"] = 0
        return {"ok": True}
    if t == "quit":
        STOP.set()
        Net.reset()
        threading.Timer(0.6, lambda: os._exit(0)).start()
        return {"ok": True}

    c = load_cfg()
    r = Net.get(c, set_via=False)
    try:
        if t == "kick":
            path = "/ip/hotspot/host/remove" if body.get("mode") == "host" else "/ip/hotspot/active/remove"
            r.cmd(path, "=.id=" + str(body.get("id", "")))
            return {"ok": True, "msg": "تم فصل (%s) بنجاح" % body.get("name", "")}
        if t == "ping":
            rows = r.cmd("/ping", "=address=" + str(body.get("address", "")), "=count=4")
            lines, ok = [], 0
            for i, row in enumerate(rows):
                if row.get("time"):
                    ok += 1
                    lines.append("نبضة %d: ✅ الرد خلال %s" % (i + 1, row["time"]))
                else:
                    lines.append("نبضة %d: ❌ انقطاع (%s)" % (i + 1, row.get("status", "timeout")))
            return {"ok": True, "lines": lines, "okCount": ok, "total": len(rows)}
        if t == "iface":
            name = str(body.get("name", ""))
            rows = r.cmd("/interface/print", "?name=" + name)
            if not rows:
                return {"ok": False, "msg": "المنفذ غير موجود"}
            iid = rows[0].get(".id")
            if body.get("op") == "restart":
                r.cmd("/interface/set", "=.id=" + iid, "=disabled=yes")
                time.sleep(1.5)
                r.cmd("/interface/set", "=.id=" + iid, "=disabled=no")
                return {"ok": True, "msg": "تم إعادة تشغيل المنفذ " + name}
            dis = "yes" if body.get("op") == "disable" else "no"
            r.cmd("/interface/set", "=.id=" + iid, "=disabled=" + dis)
            return {"ok": True, "msg": "تم تحديث حالة " + name}
        if t == "reboot":
            try:
                r.cmd("/system/reboot")
            except Exception:
                pass
            return {"ok": True, "msg": "تم إرسال أمر إعادة التشغيل للراوتر"}
        return {"ok": False, "msg": "أمر غير معروف"}
    finally:
        pass


# ======================= خادم الواجهة المحلي =======================
def routers_op(b):
    op = b.get("op")
    d = rt_load()
    if DEMO:
        return {"ok": True}
    with _rt_lock:
        if op == "save":
            rid = str(b.get("id") or "")
            old = next((r for r in d["list"] if r["id"] == rid), None)
            r = dict(old) if old else {k: DEFAULTS[k] for k in R_KEYS}
            r["id"] = rid or _new_id()
            for k in ("name", "local", "cloud", "port", "user"):
                r[k] = str(b.get(k, r.get(k, ""))).strip()
            r["port"] = r["port"] or "8728"
            if not r["user"] or not (r["local"] or r["cloud"]):
                return {"ok": False, "msg": "أدخل العنوان واسم المستخدم"}
            live = str(b.get("pass", ""))
            keep = bool(b.get("remember", True))
            r["pass"] = live if keep else ""
            if old:
                d["list"][d["list"].index(old)] = r
            else:
                d["list"].append(r)
            rt_save()
            if not old or r["id"] == d["active"]:
                rt_apply(r, live_pass=live, persist_pass=keep)
            return {"ok": True, "id": r["id"], "entered": (not old) or r["id"] == d["active"]}
        if op == "enter":
            r = next((x for x in d["list"] if x["id"] == b.get("id")), None)
            if not r:
                return {"ok": False}
            if r["id"] != d["active"] or not configured(load_cfg()):
                rt_apply(r)
            else:
                FORCE.set()
            return {"ok": True}
        if op == "delete":
            rid = b.get("id")
            was = d["active"] == rid
            d["list"] = [x for x in d["list"] if x["id"] != rid]
            if was:
                if d["list"]:
                    rt_save()
                    rt_apply(d["list"][0])
                else:
                    d["active"] = ""
                    c = load_cfg()
                    for k in ("user", "pass", "local", "cloud"):
                        c[k] = ""
                    save_cfg(c)
                    with S_LOCK:
                        S["gen"] += 1
                        S["snap"], S["modems"], S["modemsReady"], S["error"] = None, [], False, None
                    Net.reset()
            rt_save()
            return {"ok": True}
    return {"ok": False}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # بدون سجلات (البرنامج يعمل بدون نافذة أوامر)
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        p = urlparse(self.path).path
        if p == "/":
            return self._send(200, HTML.encode("utf-8"), "text/html; charset=utf-8")
        if p == "/favicon.ico":
            import base64
            return self._send(200, base64.b64decode(ICON_B64), "image/x-icon")
        if p == "/api/state":
            q = urlparse(self.path).query
            want_v = q[5:] if q.startswith("logv=") else ""
            with S_LOCK:
                st = {k: S[k] for k in ("snap", "modems", "modemsReady", "error", "via", "events",
                                        "logsReady", "logError", "logUnread", "logVer")}
                if str(S["logVer"]) != want_v:
                    st["logs"] = S["logs"]
            c = load_cfg()
            st["configured"] = configured(c)
            st["name"] = net_name(c)
            st["active"] = rt_load()["active"]
            return self._send(200, st)
        if p == "/api/routers":
            d = rt_load()
            with _rt_lock:
                return self._send(200, {"active": d["active"], "list": [dict(r) for r in d["list"]]})
        if p == "/api/settings":
            c = load_cfg()
            c["autostart"] = get_autostart()
            c["isWin"] = IS_WIN
            return self._send(200, c)
        self._send(404, {"ok": False})

    def do_POST(self):
        # حماية: لا يقبل أوامر إلا من واجهة البرنامج نفسها
        if self.headers.get("X-App") != "1":
            return self._send(403, {"ok": False})
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
        except Exception:
            return self._send(400, {"ok": False, "msg": "طلب غير صالح"})
        p = urlparse(self.path).path
        if p == "/api/routers":
            return self._send(200, routers_op(body))
        if p == "/api/settings":
            # إعدادات الراوتر الحالي داخل اللوحة: واجهة الإنترنت + المودمات + التنبيهات (بدون بيانات الدخول)
            c = load_cfg()
            for k in ("wan", "modems", "notifErr", "notifWarn"):
                if k in body:
                    c[k] = str(body[k])
            save_cfg(c)
            d = rt_load()
            with _rt_lock:
                for r in d["list"]:
                    if r["id"] == d["active"]:
                        for k in ("wan", "modems", "notifErr", "notifWarn"):
                            r[k] = c[k]
            rt_save()
            try:
                set_autostart(bool(body.get("autostart")))
            except Exception:
                pass
            with S_LOCK:
                S["gen"] += 1
                S["modemsReady"], S["error"], S["snap"], S["modems"] = False, None, None, []
            FORCE.set()
            return self._send(200, {"ok": True})
        if p == "/api/action":
            try:
                return self._send(200, do_action(body))
            except Exception as e:
                return self._send(200, {"ok": False, "msg": friendly(e)})
        self._send(404, {"ok": False})


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = not IS_WIN  # في ويندوز يجب منع تشغيل نسختين على نفس المنفذ

    def server_bind(self):
        if IS_WIN and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def open_window():
    url = "http://127.0.0.1:%d/" % PORT
    if IS_WIN:
        cands = []
        for env in ("ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"):
            base = os.environ.get(env)
            if base:
                cands.append(os.path.join(base, r"Microsoft\Edge\Application\msedge.exe"))
                cands.append(os.path.join(base, r"Google\Chrome\Application\chrome.exe"))
        for pth in cands:
            if os.path.isfile(pth):
                try:
                    subprocess.Popen([pth, "--app=" + url, "--window-size=1440,920"])
                    return
                except Exception:
                    pass
    webbrowser.open(url)


# ======================= وضع تجريبي (لاختبار الواجهة بدون راوتر) =======================
def start_demo():
    import random
    rnd = random.Random(7)

    def mac():
        return ":".join("%02X" % rnd.randrange(256) for _ in range(6))

    hosts, active = [], []
    for i in range(68):
        auth = i % 7 not in (0, 3)
        dl = rnd.randrange(0, 900) * 1048576 + rnd.randrange(1048576)
        hosts.append({".id": "*%X" % (i + 1), "mac-address": mac(), "address": "172.16.%d.%d" % (i % 4, 10 + i),
                      "uptime": "%dh%dm%ds" % (rnd.randrange(9), rnd.randrange(60), rnd.randrange(60)),
                      "authorized": "true" if auth else "false", "bypassed": "false", "comment": "",
                      "bytes-out": str(dl), "bytes-in": str(dl // 9)})
    for i in range(29):
        dl = rnd.randrange(0, 1500) * 1048576
        active.append({".id": "*A%X" % i, "user": str(rnd.randrange(10 ** 9, 10 ** 10)), "address": "172.16.0.%d" % (200 + i),
                       "mac-address": mac(), "uptime": "%dm%ds" % (rnd.randrange(59), rnd.randrange(60)),
                       "bytes-out": str(dl), "bytes-in": str(dl // 12)})
    base = {"ether1": (412 * 2 ** 30, 38 * 2 ** 30), "ether2": (2 * 2 ** 30, 1 * 2 ** 30), "ether3": (21 * 2 ** 30, 160 * 2 ** 30),
            "ether6": (3 * 2 ** 30, 12 * 2 ** 30), "ether7": (6 * 2 ** 30, 55 * 2 ** 30), "ether10": (44 * 2 ** 30, 2 * 2 ** 30)}

    def tick():
        while True:
            ifs = []
            for n, (rx, tx) in base.items():
                ifs.append({"name": n, "running": True, "disabled": False,
                            "rxRate": rnd.randrange(10_000, 30_000_000), "txRate": rnd.randrange(5_000, 21_000_000),
                            "totalRx": rx, "totalTx": tx})
            ifs.append({"name": "ether4", "running": False, "disabled": False, "rxRate": 0, "txRate": 0, "totalRx": 0, "totalTx": 0})
            S["snap"] = {"wan": "ether1", "wanUp": True, "ip": "192.168.33.254/24", "hostOk": True, "hosts": hosts,
                         "activeOk": True, "active": active, "uptime": "8h59m56s", "temp": "37", "volt": "23.3",
                         "cpu": rnd.randrange(2, 30), "usedMem": 89, "totalMem": 1024, "ramPct": 8,
                         "usedHdd": 87, "totalHdd": 128, "hddPct": 67, "ifs": ifs}
            S["modems"] = [{"name": "شيبان", "ip": "90.90.2.2", "up": True, "since": None},
                           {"name": "اكرم", "ip": "90.90.3.3", "up": True, "since": None},
                           {"name": "الاستقبال", "ip": "90.90.2.4", "up": False, "since": int(time.time() * 1000) - 180000},
                           {"name": "الدور الأول", "ip": "90.90.2.5", "up": True, "since": None}]
            S["modemsReady"], S["via"] = True, "كلاود Cloud"
            if not S["logsReady"]:
                demo = [("system,info", "user admin logged in from 192.168.88.10 via winbox"),
                        ("hotspot,info,debug", "0035654424 (172.16.0.236): logged in"),
                        ("dhcp,info", "dhcp1 assigned 172.16.1.193 to C8:F3:19:66:7C:AD"),
                        ("system,error,critical", "login failure for user admin from 45.141.84.12 via ssh"),
                        ("interface,info", "ether4 link down"),
                        ("dhcp,warning", "dhcp1 offering lease 172.16.3.16 for AE:1B:E3:C8:10:C2 without success"),
                        ("hotspot,info,debug", "0549763692 (172.16.2.248): logged out: keepalive timeout"),
                        ("system,error,critical", "router was rebooted without proper shutdown")]
                S["logs"] = [{"id": i + 1, "time": "19:%02d:%02d" % (i, i * 7 % 60), "topics": t, "msg": m,
                              "level": 2 if ("error" in t) else 1 if "warning" in t else 0} for i, (t, m) in enumerate(demo)]
                S["logsReady"], S["logUnread"] = True, 2
                S["logVer"] += 1
            time.sleep(2)

    threading.Thread(target=tick, daemon=True).start()


def main():
    args = sys.argv[1:]
    background = "--background" in args
    try:
        srv = Server(("127.0.0.1", PORT), Handler)
    except OSError:
        # البرنامج يعمل مسبقاً: افتح نافذته فقط
        if not background:
            open_window()
        return
    if "--demo" in args:
        global configured, net_name, DEMO, _rt
        DEMO = True
        _rt = {"active": "r1", "list": [
            {"id": "r1", "name": "شبكة النور", "local": "192.168.88.1", "cloud": "", "port": "8728", "user": "admin", "pass": "x", "wan": "ether1", "modems": "90.90.2.2 شيبان\n90.90.3.3 اكرم\n90.90.2.4 الاستقبال\n90.90.2.5 الدور الأول", "notifErr": "1", "notifWarn": "0"},
            {"id": "r2", "name": "هيثم كلاود", "local": "", "cloud": "b9070b4497c6.sn.mynetname.net", "port": "1177", "user": "haitham", "pass": "x", "wan": "ether1", "modems": "", "notifErr": "1", "notifWarn": "0"},
            {"id": "r3", "name": "راوتر المكتب", "local": "10.99.99.1", "cloud": "", "port": "8728", "user": "admin", "pass": "x", "wan": "ether1", "modems": "", "notifErr": "1", "notifWarn": "1"}]}
        net_name = lambda c=None: "شبكة النور"  # noqa: E731
        configured = lambda c: True  # noqa: E731
        start_demo()
    else:
        threading.Thread(target=main_loop, daemon=True).start()
        threading.Thread(target=modem_loop, daemon=True).start()
        threading.Thread(target=log_loop, daemon=True).start()
        rt_load()
        threading.Thread(target=watch_sync, daemon=True).start()
    if not background and "--no-window" not in args:
        threading.Timer(0.5, open_window).start()
    srv.serve_forever()


# ======================= الواجهة =======================
ICON_B64 = "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"


HTML = r"""<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Net Microtik Monitor</title>
<link rel="icon" type="image/x-icon" href="/favicon.ico">
<style>
:root{--bg:#0d1117;--card:#161b22;--inner:#0d1117;--chip:#21262d;--line:#30363d;--line2:#21262d;--text:#e6edf3;--sub:#8b949e;--mute:#6e7681;--blue:#58a6ff;--green:#3fb950;--red:#f85149;--yellow:#e3b341;--purple:#a371f7}
*{box-sizing:border-box}
html,body{margin:0;background:var(--bg);color:var(--text);font-family:"Segoe UI",Tahoma,"Noto Sans Arabic",Arial,sans-serif}
.wrap{max-width:1500px;margin:0 auto;padding:18px 22px 40px}
header{display:flex;align-items:center;gap:8px}
header h1{flex:1;margin:0;font-size:24px;color:var(--blue)}
.btn{background:var(--chip);border:1px solid var(--line);color:var(--text);border-radius:8px;padding:8px 14px;font:inherit;font-size:14px;cursor:pointer}
.btn:hover{border-color:var(--sub)}
.btn.red{color:var(--red);border-color:var(--red)}
.btn.primary{background:#238636;border-color:#2ea043;color:#fff}
.btn.sm{padding:4px 10px;font-size:12px}
#banner{margin-top:14px;padding:14px;border-radius:12px;text-align:center;font-weight:700;font-size:16px;border:1px solid var(--line);background:var(--card);color:var(--sub)}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.stat{cursor:pointer;transition:border-color .15s}
.stat:hover{border-color:var(--sub)}
.stat .t{color:var(--sub);font-size:13px}
.stat .v{font-size:30px;font-weight:700;margin:6px 0 2px;font-variant-numeric:tabular-nums}
.stat .s{color:var(--mute);font-size:12px}
.cols{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:12px;margin-top:12px;align-items:start}
.col{display:flex;flex-direction:column;gap:12px}
.ch{display:flex;align-items:center;gap:8px;margin-bottom:10px}
.ch h2{flex:1;margin:0;font-size:14px;color:var(--sub)}
.chip{background:var(--chip);border:1px solid var(--line);border-radius:8px;padding:5px 10px;font-size:13px;white-space:nowrap;font-family:inherit}
.badges{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:4px}
.res{margin-top:12px}.res .top{display:flex;justify-content:space-between;font-size:14px}.res .top b{font-variant-numeric:tabular-nums}
.bar{height:8px;background:var(--chip);border-radius:6px;overflow:hidden;margin-top:6px}
.bar>i{display:block;height:100%;border-radius:6px;transition:width .5s}
.mods{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:8px}
.mod{background:var(--inner);border:1px solid var(--line2);border-radius:10px;padding:10px 12px;cursor:pointer}
.mod.down{border-color:var(--red)}
.mod .n{font-weight:700;font-size:15px}.mod .st{font-size:12.5px;margin-top:4px}
.total{background:var(--inner);border:1px solid var(--blue);border-radius:10px;padding:12px 14px;margin-bottom:10px;display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.total .big{font-size:24px;font-weight:700;color:var(--yellow);direction:ltr}
.total .sm{font-size:13px;color:var(--sub)}
.ifr{background:var(--inner);border:1px solid var(--line2);border-radius:10px;padding:10px 12px;margin-bottom:8px;cursor:pointer}
.ifr:hover,.mod:hover{border-color:var(--sub)}
.ifr .top{display:flex;align-items:center;gap:8px}.ifr .nm{flex:1;font-weight:700}
.ifr.off .nm{color:var(--sub)}
.rates{font-size:13.5px;font-variant-numeric:tabular-nums;direction:ltr}
.use{font-size:12.5px;color:var(--sub);margin-top:4px}
.ltr{direction:ltr;unicode-bidi:isolate;display:inline-block}
.g{color:var(--green)}.b{color:var(--blue)}.y{color:var(--yellow)}.r{color:var(--red)}.p{color:var(--purple)}
.note{color:var(--sub);padding:6px 0}
.ov{position:fixed;inset:0;background:rgba(1,4,9,.72);display:flex;align-items:center;justify-content:center;z-index:50;padding:20px}
.mdl{background:var(--card);border:1px solid var(--line);border-radius:14px;width:min(560px,100%);max-height:90vh;display:flex;flex-direction:column;overflow:hidden}
.mdl.wide{width:min(1280px,100%);height:90vh}
.mh{display:flex;align-items:center;gap:10px;padding:14px 18px;border-bottom:1px solid var(--line)}
.mh h3{flex:1;margin:0;font-size:18px}
.mb{padding:16px 18px;overflow:auto;flex:1}
.mf{display:flex;gap:8px;padding:12px 18px;border-top:1px solid var(--line);flex-wrap:wrap}
input,textarea{width:100%;background:var(--inner);border:1px solid var(--line);color:var(--text);border-radius:8px;padding:9px 12px;font:inherit;font-size:14px}
textarea{direction:ltr;text-align:right;min-height:150px;resize:vertical}
input:focus,textarea:focus{outline:none;border-color:var(--blue)}
label{display:block;font-size:13px;color:var(--sub);margin:12px 0 5px}
.chk{display:flex;align-items:center;gap:8px;color:var(--text);font-size:14px;margin-top:14px}
.chk input{width:auto}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:0 12px}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th{position:sticky;top:0;background:var(--card);color:var(--sub);font-weight:600;text-align:right;padding:10px 8px;border-bottom:1px solid var(--line);cursor:pointer;white-space:nowrap;user-select:none}
th.on{color:var(--blue)}
td{padding:8px;border-bottom:1px solid var(--line2);white-space:nowrap}
tbody tr:hover td{background:#1c2129}
.num{font-variant-numeric:tabular-nums}
.kick{background:transparent;border:1px solid var(--red);color:var(--red);border-radius:6px;padding:3px 10px;cursor:pointer;font:inherit;font-size:12px}
.kick:hover{background:#f8514922}
.sumrow{display:flex;gap:8px;flex-wrap:wrap;padding:12px 0}
.toasts{position:fixed;bottom:18px;left:18px;display:flex;flex-direction:column;gap:8px;z-index:60}
.toast{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 14px;min-width:260px;box-shadow:0 6px 24px rgba(0,0,0,.45)}
.toast b{display:block;margin-bottom:2px}
.logc{margin-top:12px;display:flex;align-items:center;gap:14px;cursor:pointer}
.logc:hover{border-color:var(--sub)}
.logc.hot{border-color:var(--red);background:#2a1215}
.logc .lt{flex:1;min-width:0}.logc .lt .t{color:var(--sub);font-size:13px}
.logc .lt .m{margin-top:4px;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.chipbtn{cursor:pointer}.chipbtn.on{background:var(--blue);color:#0d1117;border-color:var(--blue)}
tr.lv2 td{background:#2a1215}tr.lv2 td.msg{color:var(--red);font-weight:700}
tr.lv1 td.msg{color:var(--yellow)}
td.msg{white-space:normal;unicode-bidi:plaintext;text-align:start;line-height:1.6}
pre{white-space:pre-wrap;font:inherit;margin:0;line-height:1.9}
@media (max-width:1050px){.cols{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,1fr)}}

/* ===== مظهر Net Microtik Monitor: بطاقات ملونة بتدرجات ===== */
html,body{background:#EEF3FB;color:#0f1932}
header h1{color:#0f1932}
.btn{background:linear-gradient(135deg,#fff,#dfe8f8);border:1px solid #cfdaf0;color:#0f1932;border-radius:14px}
.btn:hover{border-color:#1e6eff}
.btn.red{color:#d6362a;border-color:#f3b4ae}
.btn.primary{background:linear-gradient(135deg,#1e6eff,#0a32be);border-color:#1e6eff;color:#fff}
#banner{color:#fff;border:0;border-radius:18px;background:linear-gradient(135deg,#6b7a99,#4a5875)}
.stat{border:0;border-radius:20px;color:#fff}
.stat .t,.stat .s{color:#eef3ff}
.stat .v{color:#fff!important;font-size:32px}
.stats .stat:nth-child(1){background:linear-gradient(135deg,#18be82,#109664)}
.stats .stat:nth-child(2){background:linear-gradient(135deg,#14aac8,#0a6eaa)}
.stats .stat:nth-child(3){background:linear-gradient(135deg,#e65a96,#be326e)}
.stats .stat:nth-child(4){background:linear-gradient(135deg,#ffb020,#f07a0a)}
.stat:hover{filter:brightness(1.06);border:0}
.card{border:0;border-radius:22px;background:linear-gradient(135deg,#1a2c50,#121f3c);color:#e6edf3}
.mod .st span[style]{color:#ffe3e0!important}
.stat.card{border-radius:20px}
.chip{border-radius:12px}
.logc{background:linear-gradient(135deg,#fff,#e8f0ff)!important;color:#0f1932}
.logc .lt .t{color:#64708a}
.logc .lt .m span.g{color:#0f7a50}
.logc.hot{background:linear-gradient(135deg,#fff1ef,#ffd9d4)!important;border:0}
.logc .chip.b{background:linear-gradient(135deg,#1e6eff,#0a32be);color:#fff;border:0}
.logc .chip.r{background:linear-gradient(135deg,#ff6a5c,#d6362a);color:#fff;border:0}
.mod{border:0;border-radius:16px;color:#fff;background:linear-gradient(135deg,#18be82,#109664)}
.mod.down{background:linear-gradient(135deg,#ff6a5c,#c82828)}
.mod .st,.mod .st.g,.mod .st.r{color:#fff}
.total{border:0;border-radius:16px;background:linear-gradient(135deg,#1e6eff,#0a32be);color:#fff}
.total .big{color:#fff}.total .sm,.total .sm .g,.total .sm .b,.total .sm .y{color:#e6eeff}
.ifr{border:0;border-radius:16px;color:#fff;background:linear-gradient(135deg,#18be82,#109664)}
.ifr.off{background:linear-gradient(135deg,#ff6a5c,#c82828)}
.ifr.off .nm{color:#fff}
.ifr .g,.ifr .b,.ifr .y,.ifr .use{color:#fff}.ifr .rates .b{color:#fff3c4}
.ifr .bar{background:rgba(255,255,255,.25)}
.ifr .bar>i{background:#fff!important}
.mod:hover,.ifr:hover{filter:brightness(1.06)}

/* ===== النوافذ والقوائم بنفس مظهر نسخة الأندرويد ===== */
.ov{background:rgba(15,25,50,.45)}
.mdl{background:#EEF3FB;color:#1f2a44;border:0;border-radius:26px;box-shadow:0 20px 60px rgba(15,25,50,.35)}
.mh{border:0;background:linear-gradient(135deg,#1a2c50,#121f3c);margin:10px 10px 0;border-radius:20px;color:#fff}
.mh h3,.mh h3 *{color:#fff!important}
.mh .btn,.mh .btn.sm{background:linear-gradient(135deg,#1e6eff,#0a32be);color:#fff;border:0}
.mf{border:0}
.mdl label{color:#64708a}
.mdl input,.mdl textarea{background:#fff;border:1px solid #9fb3d9;color:#1f2a44;border-radius:14px}
.mdl input:focus,.mdl textarea:focus{border-color:#1e6eff}
.mdl .g{color:#0f7a50}.mdl .b{color:#1e6eff}.mdl .y{color:#b07800}.mdl .r{color:#d6362a}.mdl .p{color:#6b3fd4}
.mdl .note{color:#64708a}
.mdl .chip{background:linear-gradient(135deg,#fff,#e8f0ff);border:0;color:#1f2a44}
.mdl .chipbtn.on{background:linear-gradient(135deg,#1e6eff,#0a32be);color:#fff}
.mdl .chk{color:#1f2a44}
.mdl th{background:#EEF3FB;color:#64708a;border-bottom:1px solid #cfdaf0}
.mdl th.on{color:#1e6eff}
.mdl td{border-bottom:1px solid #dbe6fb;color:#1f2a44}
.mdl tbody tr:hover td{background:#e3ecfb}
.mdl .kick{background:linear-gradient(135deg,#ff6a5c,#d6362a);color:#fff;border:0;border-radius:12px;padding:4px 12px}
.mdl tr.lv2 td{background:#fff1ef}.mdl tr.lv2 td.msg{color:#d6362a;font-weight:700}
.mdl tr.lv1 td{background:#fffaf0}.mdl tr.lv1 td.msg{color:#9a6a00}
.mdl pre{color:#1f2a44}
.toast{background:#fff;color:#1f2a44;border:0;border-radius:16px}
.btn.exit{background:linear-gradient(135deg,#ff6a5c,#d6362a);color:#fff;border:0;font-weight:700}
.fl{position:relative;margin-top:16px}
.fl label{position:absolute;top:-8px;right:14px;background:#EEF3FB;padding:0 5px;font-size:11px;color:#1e6eff;margin:0;z-index:1}
.fl input,.fl textarea{padding:13px 14px;border-radius:14px}
.fl textarea{min-height:130px}
.box{background:linear-gradient(135deg,#fff,#e8f0ff);border-radius:18px;padding:10px 14px;margin-top:16px}
.box .chk{margin-top:8px}
.rs{position:fixed;inset:0;background:#EEF3FB;z-index:40;overflow:auto}
.rsin{max-width:760px;margin:0 auto;padding:22px 18px 110px}
.rhead{display:flex;align-items:center;gap:10px;background:linear-gradient(135deg,#1a2c50,#121f3c);border-radius:26px;padding:16px 20px;color:#fff}
.rhead .tt{flex:1}.rhead .tt b{font-size:22px;display:block}.rhead .tt span{color:#b8c6e6;font-size:13px}
.rc{display:flex;align-items:center;gap:14px;margin-top:14px;padding:16px 16px;border-radius:24px;background:linear-gradient(135deg,#fff,#e8f0ff);cursor:pointer;color:#1f2a44}
.rc.act{background:linear-gradient(135deg,#e9fbf3,#c9f1de)}
.rc:hover{filter:brightness(.98)}
.rc .ic{width:54px;height:54px;border-radius:18px;background:linear-gradient(135deg,#dbe6fb,#c3d6f7);display:flex;align-items:center;justify-content:center;font-size:26px}
.rc .inf{flex:1;min-width:0}.rc .inf b{font-size:18px;display:block}.rc.act .inf b{color:#0f7a50}
.rc .inf span{color:#64708a;font-size:13px;direction:ltr;unicode-bidi:isolate;display:inline-block}
.rc .ib{border:0;background:none;font-size:22px;cursor:pointer;padding:6px 8px;border-radius:12px}
.rc .ib:hover{background:#fff}
.fab{position:fixed;left:26px;bottom:26px;width:68px;height:68px;border-radius:24px;border:0;background:linear-gradient(135deg,#1e6eff,#0a32be);color:#fff;font-size:38px;cursor:pointer;box-shadow:0 10px 26px rgba(30,110,255,.45);z-index:41}
.btn.go{background:linear-gradient(135deg,#18be82,#109664);color:#fff;border:0;font-weight:700;padding:12px 20px}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1 id="title">📡 Net Microtik Monitor</h1>
    <button class="btn" onclick="refreshNow()">🔄 تحديث</button>
    <button class="btn" onclick="showRouters()">🔀 الراوترات</button>
    <button class="btn" onclick="openSettings()">⚙️ الإعدادات</button>
    <button class="btn exit" onclick="quitApp()">✖ خروج</button>
  </header>
  <div id="banner">جارٍ الاتصال بالراوتر...</div>

  <div class="stats">
    <div class="card stat" onclick="pingBox('8.8.8.8','فحص الإنترنت العالمي (Google DNS)')">
      <div class="t">🌐 حالة الإنترنت (WAN)</div><div class="v b" id="wanV">-</div><div class="s" id="wanS">اضغط لفحص البنق</div></div>
    <div class="card stat" onclick="openList('host')">
      <div class="t">👥 HOST</div><div class="v g" id="hostV">-</div><div class="s" id="hostS">اضغط لعرض القائمة</div></div>
    <div class="card stat" onclick="openList('active')">
      <div class="t">🔌 ACTIVE</div><div class="v p" id="actV">-</div><div class="s" id="actS">اضغط لعرض القائمة</div></div>
    <div class="card stat" onclick="refreshNow()">
      <div class="t">📡 المودمات المتصلة</div><div class="v y" id="modV">-</div><div class="s">اضغط لإعادة الفحص</div></div>
  </div>
  <div class="card logc" id="logCard" onclick="openLog()">
    <div class="lt"><div class="t">📜 سجل الراوتر (LOG)</div><div class="m" id="logSub">جارٍ تحميل السجل...</div></div>
    <span class="chip b" id="logBtn">عرض السجل ›</span>
  </div>

  <div class="cols">
    <div class="col">
      <div class="card">
        <div class="ch"><h2>🖥️ موارد الميكروتيك الرئيسي</h2><button class="btn red sm" onclick="rebootRouter()">⚡ إعادة تشغيل</button></div>
        <div class="badges"><span class="chip b" id="via">🔗 -</span><span class="chip" id="upt">⏱ -</span><span class="chip g" id="tmp">🌡 -</span><span class="chip y" id="vlt">⚡ -</span></div>
        <div id="resources"></div>
      </div>
      <div class="card">
        <div class="ch"><h2>🛰️ حالة المودمات والأكسسات (اضغط لفحص البنق)</h2></div>
        <div class="mods" id="mods"><div class="note">جارٍ فحص المودمات...</div></div>
      </div>
    </div>
    <div class="col">
      <div class="card">
        <div class="ch"><h2>⚡ الواجهات والسرعة اللحظية (اضغط للتحكم)</h2><button class="chip b" id="flt" style="cursor:pointer" onclick="toggleFlt()">الكل</button></div>
        <div class="total" id="total">📊 مجموع الاستهلاك: -</div>
        <div id="ifs"></div>
      </div>
    </div>
  </div>
</div>
<div id="rs" class="rs" style="display:none"></div>
<div id="ov"></div>
<div class="toasts" id="toasts"></div>

<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const GiB=1073741824, MiB=1048576;
const gb=b=>b>=GiB?(b/GiB).toFixed(2)+' GB':Math.floor(b/MiB)+' MB';
const gbx=b=>(b/GiB).toFixed(2)+' GB';
const bw=v=>v>=1e6?(v/1e6).toFixed(1)+' Mbps':v>=1e3?Math.floor(v/1e3)+' Kbps':v+' bps';
const num=x=>Number(x||0)||0;
function ago(t){const s=Math.floor((Date.now()-t)/1000);return s<60?s+' ث':s<3600?Math.floor(s/60)+' د':Math.floor(s/3600)+' س'}
function secs(u){let t=0;String(u||'').replace(/(\d+)([wdhms])/g,(_,n,k)=>{t+=n*{w:604800,d:86400,h:3600,m:60,s:1}[k]});return t}
function ipNum(ip){return String(ip||'').split('.').reduce((a,x)=>a*256+(+x||0),0)}

let LOGS=[], logV='', logOpen=false, logFilter=0, logQ='', S=null, lastEv=null, onlyRun=false, listMode=null, listQ='', sortKey='total', sortDir=-1, modsSig='', askedSettings=false, dead=false;

async function api(path,body){
  const r=await fetch(path,body===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json','X-App':'1'},body:JSON.stringify(body)});
  return r.json();
}
async function poll(){
  try{ S=await api('/api/state?logv='+logV); if(S.logs){ LOGS=S.logs; } logV=String(S.logVer); dead=false; render(); }
  catch(e){ if(!dead){dead=true; setBanner('⚠️ البرنامج متوقف — شغّله من جديد','#f85149');} }
  setTimeout(poll,1000);
}

function setBanner(t,col){
  const b=$('banner'); if(b.textContent===t) return;
  b.textContent=t; b.style.color='#fff'; b.style.border='0';
  b.style.background={'#f85149':'linear-gradient(135deg,#ff6a5c,#d6362a)','#e3b341':'linear-gradient(135deg,#ffb020,#f07a0a)','#3fb950':'linear-gradient(135deg,#18be82,#109664)','#58a6ff':'linear-gradient(135deg,#1e6eff,#0a32be)'}[col]||'linear-gradient(135deg,#6b7a99,#4a5875)';
}

function render(){
  const s=S.snap, mods=S.modems||[], dn=mods.filter(m=>!m.up);
  if(!askedSettings){ askedSettings=true; showRouters(true); }
  if(!S.configured){ setBanner('🔀 اختر راوتراً من قائمة الراوترات','#58a6ff'); }
  else if(S.error) setBanner('⚠️ تعذر الاتصال بالراوتر: '+S.error,'#f85149');
  else if(!s) setBanner('جارٍ الاتصال بالراوتر...','#8b949e');
  else if(!s.wanUp) setBanner('🔴 انقطاع الإنترنت (الواجهة '+s.wan+')','#f85149');
  else if(dn.length) setBanner('⚠️ مودمات مقطوعة ('+dn.map(m=>m.name).join('، ')+')','#e3b341');
  else setBanner('🟢 كل الأنظمة والخطوط تعمل بشكل طبيعي','#3fb950');

  $('modV').innerHTML=S.modemsReady?`<span class="ltr">${mods.length-dn.length} / ${mods.length}</span>`:'-';
  $('via').textContent='🔗 '+(S.via||'-');
  renderMods(mods);
  if(s) renderSnap(s);
  if(listMode) renderList();
  if(S.name){ const t='📡 '+S.name; if($('title').textContent!==t){ $('title').textContent=t; document.title=S.name; } }
  renderLogCard();
  if(logOpen && S.logs) renderLog();
  showEvents(S.events||[]);
}

/* ---------- سجل الراوتر ---------- */
function renderLogCard(){
  const c=$('logCard'), sub=$('logSub'), btn=$('logBtn'), un=S.logUnread||0;
  const lastRed=[...LOGS].reverse().find(e=>e.level===2);
  c.classList.toggle('hot', un>0 && !logOpen);
  if(S.logError){ sub.innerHTML=`<span class="y">⚠️ لا يمكن قراءة السجل: ${esc(S.logError)} — أعطِ مستخدم API صلاحية read</span>`; }
  else if(!S.logsReady){ sub.textContent='جارٍ تحميل السجل...'; }
  else if(un>0 && lastRed && !logOpen){ sub.innerHTML=`<span class="r">🔴 ${un} أخطاء جديدة • <span class="ltr">${esc(lastRed.time)}</span> ${esc(lastRed.msg)}</span>`; }
  else sub.innerHTML=`<span class="g">✅ لا توجد أخطاء جديدة</span> <span style="color:var(--sub)">• ${LOGS.length} سطر — اضغط لعرض السجل كاملاً</span>`;
  btn.textContent=(un>0&&!logOpen)?`🔴 ${un} جديد`:'عرض السجل ›'; btn.className='chip '+((un>0&&!logOpen)?'r':'b');
}
function openLog(){
  logOpen=true; logFilter=0; logQ=''; listMode=null;
  api('/api/action',{type:'logread'}); if(S) S.logUnread=0;
  $('ov').innerHTML=`<div class="ov" onclick="if(event.target===this)closeLog()"><div class="mdl wide">
    <div class="mh"><h3 id="logT" class="b">📜 سجل الراوتر</h3>
      <span class="chip chipbtn" data-f="0" onclick="setLogF(0)">الكل</span>
      <span class="chip chipbtn" data-f="2" onclick="setLogF(2)">🔴 أخطاء</span>
      <span class="chip chipbtn" data-f="1" onclick="setLogF(1)">🟡 تحذيرات</span>
      <input id="logQ" style="width:260px" placeholder="🔍 بحث في السجل" oninput="logQ=this.value.trim().toLowerCase();renderLog()">
      <button class="btn" onclick="closeLog()">✖ إغلاق</button></div>
    <div class="mb" style="padding-top:0"><table><thead><tr><th style="cursor:default">الوقت</th><th style="cursor:default">النوع (topics)</th><th style="cursor:default;width:65%">الرسالة</th></tr></thead><tbody id="logB"></tbody></table></div></div></div>`;
  renderLog(); renderLogCard();
}
function closeLog(){ logOpen=false; $('ov').innerHTML=''; renderLogCard(); }
function setLogF(f){ logFilter=f; renderLog(); }
function renderLog(){
  if(!logOpen||!$('logB')) return;
  if(S) S.logUnread=0;
  document.querySelectorAll('.chipbtn').forEach(ch=>ch.classList.toggle('on', +ch.dataset.f===logFilter));
  const reds=LOGS.filter(e=>e.level===2).length, yel=LOGS.filter(e=>e.level===1).length;
  $('logT').innerHTML=`📜 سجل الراوتر (${LOGS.length}) &nbsp;<span class="chip r">🔴 ${reds}</span> <span class="chip y">🟡 ${yel}</span>`;
  if(S&&S.logError){ $('logB').innerHTML=`<tr><td colspan="3" class="note">⚠️ لا يمكن قراءة السجل: ${esc(S.logError)} — أعطِ مستخدم API صلاحية read من System → Users → Groups</td></tr>`; return; }
  if(S&&!S.logsReady){ $('logB').innerHTML='<tr><td colspan="3" class="note">جارٍ تحميل السجل...</td></tr>'; return; }
  const rows=[...LOGS].reverse().filter(e=>(!logFilter||e.level===logFilter)&&(!logQ||e.msg.toLowerCase().includes(logQ)||e.topics.toLowerCase().includes(logQ)));
  if(!rows.length){ $('logB').innerHTML='<tr><td colspan="3" class="note">لا توجد رسائل مطابقة</td></tr>'; return; }
  $('logB').innerHTML=rows.map(e=>`<tr class="lv${e.level}"><td class="num" style="color:var(--sub)"><span class="ltr">${esc(e.time)}</span></td>
    <td style="color:var(--sub)"><span class="ltr">${esc(e.topics)}</span></td><td class="msg">${e.level===2?'🔴 ':e.level===1?'🟡 ':''}${esc(e.msg)}</td></tr>`).join('');
}

function renderSnap(s){
  $('wanV').textContent=s.wanUp?'متصل ✓':'مقطوع ✗'; $('wanV').className='v '+(s.wanUp?'g':'r');
  $('wanS').textContent='IP: '+s.ip;
  const auth=s.hosts.filter(h=>h.authorized==='true').length;
  const sum=l=>l.reduce((a,u)=>a+num(u['bytes-out'])+num(u['bytes-in']),0);
  $('hostV').textContent=s.hostOk?s.hosts.length:'-';
  $('hostS').innerHTML=s.hostOk?`منهم مسجلين: ${auth} • <span class="ltr">${gb(sum(s.hosts))}</span>`:'الهوتسبوت غير مفعل';
  $('actV').textContent=s.activeOk?s.active.length:'-';
  $('actS').innerHTML=s.activeOk?`الاستهلاك: <span class="ltr">${gb(sum(s.active))}</span> • اضغط للقائمة`:'الهوتسبوت غير مفعل';
  $('upt').textContent='⏱ '+s.uptime; $('tmp').textContent='🌡 '+s.temp+'°C'; $('vlt').textContent='⚡ '+s.volt+'V';
  $('resources').innerHTML=
    bar('المعالج (CPU Load)',s.cpu+'%',s.cpu)+
    bar('الذاكرة العشوائية (RAM)',`${s.usedMem} / ${s.totalMem} MB (${s.ramPct}%)`,s.ramPct)+
    bar('مساحة التخزين (Storage)',`${s.usedHdd} / ${s.totalHdd} MB (${s.hddPct}%)`,s.hddPct);
  renderIfs(s.ifs, s.wan);
}
function bar(label,val,pct){
  const p=Math.max(0,Math.min(100,pct)); const col=p>=85?'var(--red)':p>=65?'var(--yellow)':'var(--green)';
  return `<div class="res"><div class="top"><span>${label}</span><b class="ltr">${val}</b></div><div class="bar"><i style="width:${p}%;background:${col}"></i></div></div>`;
}

function renderMods(mods){
  const sig=JSON.stringify([S.modemsReady,mods.map(m=>[m.name,m.ip,m.up,m.up?0:ago(m.since)])]);
  if(sig===modsSig) return; modsSig=sig;
  const el=$('mods');
  if(!mods.length){ el.innerHTML=`<div class="note">${S.modemsReady?'لم يتم إدخال مودمات في الإعدادات.':'جارٍ فحص المودمات...'}</div>`; return; }
  el.innerHTML=mods.map(m=>`<div class="mod ${m.up?'':'down'}" data-act="mod" data-ip="${esc(m.ip)}" data-n="${esc(m.name)}">
    <div class="n">${m.up?'🟢':'🔴'} ${esc(m.name)}</div>
    <div class="st ${m.up?'g':'r'}">${m.up?`متصل <span class="ltr">(${esc(m.ip)})</span>`:`مقطوع منذ ${ago(m.since||Date.now())} <span class="ltr" style="color:var(--mute)">${esc(m.ip)}</span>`}</div></div>`).join('');
}

function toggleFlt(){ onlyRun=!onlyRun; $('flt').textContent=onlyRun?'النشط فقط ✓':'الكل'; if(S&&S.snap) renderIfs(S.snap.ifs,S.snap.wan); }
function renderIfs(list,wan){
  const rx=list.reduce((a,i)=>a+i.totalRx,0), tx=list.reduce((a,i)=>a+i.totalTx,0);
  const w=list.find(i=>i.name===wan);
  $('total').innerHTML=`<span>📊 مجموع الاستهلاك</span><span class="big">${gbx(rx+tx)}</span>
    <span class="sm"><span class="g ltr">⬇ ${gbx(rx)}</span> &nbsp; <span class="b ltr">⬆ ${gbx(tx)}</span>${w?` &nbsp;|&nbsp; 🌐 الإنترنت (${esc(w.name)}): <b class="y ltr">${gbx(w.totalRx+w.totalTx)}</b>`:''}</span>`;
  const f=onlyRun?list.filter(i=>i.running):list;
  if(!f.length){ $('ifs').innerHTML='<div class="note">لا توجد منافذ نشطة مطابقة للفلتر.</div>'; return; }
  const max=Math.max(1e7,...f.map(i=>Math.max(i.rxRate,i.txRate)));
  $('ifs').innerHTML=f.map(i=>{
    const dot=i.disabled?'⚪':i.running?'🟢':'🔴';
    const cur=Math.max(i.rxRate,i.txRate), p=Math.max(4,Math.min(100,Math.round(cur*100/max)));
    return `<div class="ifr ${i.running?'':'off'}" data-act="iface" data-n="${esc(i.name)}">
      <div class="top"><span class="nm">${dot} ${esc(i.name)}</span>
        <span class="rates"><span class="g">↓ ${bw(i.rxRate)}</span> &nbsp; <span class="b">↑ ${bw(i.txRate)}</span></span></div>
      <div class="use">📊 الاستهلاك: <span class="g ltr">⬇ ${gbx(i.totalRx)}</span> &nbsp; <span class="b ltr">⬆ ${gbx(i.totalTx)}</span> &nbsp; <span class="y ltr">Σ ${gbx(i.totalRx+i.totalTx)}</span></div>
      ${i.running&&cur>0?`<div class="bar" style="height:4px"><i style="width:${p}%;background:#238636"></i></div>`:''}</div>`;
  }).join('');
}

/* ---------- قوائم HOST / ACTIVE ---------- */
let returnTo=null;
function openList(mode,keep){
  logOpen=false; listMode=mode; if(!keep){ listQ=''; sortKey='total'; sortDir=-1; }
  const isHost=mode==='host';
  $('ov').innerHTML=`<div class="ov" onclick="if(event.target===this)closeModal()"><div class="mdl wide">
    <div class="mh"><h3 id="lt" class="${isHost?'g':'p'}"></h3>
      <input id="lq" style="width:300px" placeholder="${isHost?'🔍 بحث بالماك أو IP أو التعليق':'🔍 بحث باسم المستخدم أو IP أو الماك'}" oninput="listQ=this.value.trim().toLowerCase();renderList()">
      <button class="btn" onclick="closeModal()">✖ إغلاق</button></div>
    <div class="mb" style="padding-top:0"><div class="sumrow" id="lsum"></div>
      <table><thead id="lh"></thead><tbody id="lb"></tbody></table></div></div></div>`;
  $('lq').value=listQ; renderList(); $('lq').focus();
}
function closeModal(){ $('ov').innerHTML=''; listMode=null; if(returnTo){ const m=returnTo; returnTo=null; openList(m,true); } }
function setSort(k){ if(sortKey===k) sortDir=-sortDir; else { sortKey=k; sortDir=(k==='name'||k==='ip'||k==='st')?1:-1; } renderList(); }
function renderList(){
  if(!listMode||!$('lb')) return;
  const s=S&&S.snap, isHost=listMode==='host';
  const ok=s&&(isHost?s.hostOk:s.activeOk), list=s?(isHost?s.hosts:s.active):[];
  const dl=u=>num(u['bytes-out']), ul=u=>num(u['bytes-in']), tot=u=>dl(u)+ul(u);
  const name=u=>isHost?(u.comment||u['mac-address']||'جهاز'):(u.user||'غير معروف');
  const st=u=>u.authorized==='true'?0:u.bypassed==='true'?1:2;
  const rows=list.filter(u=>!listQ||['user','mac-address','address','comment'].some(k=>String(u[k]||'').toLowerCase().includes(listQ)));
  const key={total:tot,dl,ul,name:u=>name(u).toLowerCase(),ip:u=>ipNum(u.address),up:u=>secs(u.uptime),st}[sortKey]||tot;
  rows.sort((a,b)=>{const x=key(a),y=key(b);return (x>y?1:x<y?-1:0)*sortDir});

  $('lt').textContent=`${isHost?'👥 HOST':'🔌 ACTIVE'} (${ok?list.length:'-'})`;
  const T=list.reduce((a,u)=>a+tot(u),0), D=list.reduce((a,u)=>a+dl(u),0), U=list.reduce((a,u)=>a+ul(u),0);
  $('lsum').innerHTML=`<span class="chip">العدد: <b>${list.length}</b></span>`+
    (isHost?`<span class="chip g">✅ مسجلين: ${list.filter(u=>u.authorized==='true').length}</span><span class="chip">⏳ غير مسجلين: ${list.filter(u=>u.authorized!=='true').length}</span>`:'')+
    `<span class="chip y">Σ المجموع: <span class="ltr">${gb(T)}</span></span><span class="chip g">⬇ <span class="ltr">${gb(D)}</span></span><span class="chip b">⬆ <span class="ltr">${gb(U)}</span></span>`+
    (listQ?`<span class="chip">نتائج البحث: ${rows.length}</span>`:'');

  const cols=isHost
    ?[['#',''],['الجهاز','name'],['IP','ip'],['المدة','up'],['الحالة','st'],['⬇ تنزيل','dl'],['⬆ رفع','ul'],['Σ المجموع','total'],['','']]
    :[['#',''],['المستخدم','name'],['IP','ip'],['MAC',''],['المدة','up'],['⬇ تنزيل','dl'],['⬆ رفع','ul'],['Σ المجموع','total'],['','']];
  $('lh').innerHTML='<tr>'+cols.map(([t,k])=>k?`<th class="${sortKey===k?'on':''}" onclick="setSort('${k}')">${t}${sortKey===k?(sortDir>0?' ▲':' ▼'):''}</th>`:`<th style="cursor:default">${t}</th>`).join('')+'</tr>';

  if(!ok){ $('lb').innerHTML=`<tr><td colspan="9" class="note">الهوتسبوت غير متوفر على الراوتر أو لا توجد صلاحية</td></tr>`; return; }
  if(!rows.length){ $('lb').innerHTML=`<tr><td colspan="9" class="note">${listQ?'لا توجد نتائج':'لا يوجد أحد حالياً'}</td></tr>`; return; }
  $('lb').innerHTML=rows.map((u,i)=>{
    const stt=isHost?(u.authorized==='true'?'<span class="g">✅ مسجل</span>':u.bypassed==='true'?'<span class="b">⏩ متجاوز</span>':'<span style="color:var(--sub)">⏳ غير مسجل</span>'):'';
    return `<tr><td class="num" style="color:var(--mute)">${i+1}</td>
      <td><b>${isHost?'💻':'👤'} <span class="ltr">${esc(name(u))}</span></b></td>
      <td class="num"><span class="ltr">${esc(u.address||'-')}</span></td>
      ${isHost?'':`<td class="num" style="color:var(--sub)"><span class="ltr">${esc(u['mac-address']||'-')}</span></td>`}
      <td class="num"><span class="ltr">${esc(u.uptime||'-')}</span></td>
      ${isHost?`<td>${stt}</td>`:''}
      <td class="num g"><span class="ltr">${gb(dl(u))}</span></td>
      <td class="num b"><span class="ltr">${gb(ul(u))}</span></td>
      <td class="num y"><b class="ltr">${gb(tot(u))}</b></td>
      <td><button class="kick" data-act="kick" data-id="${esc(u['.id'])}" data-n="${esc(name(u))}">${isHost?'حذف ❌':'طرد ❌'}</button></td></tr>`;
  }).join('');
}

/* ---------- نوافذ عامة ---------- */
function modal(title,bodyHtml,footHtml){
  listMode=null; logOpen=false;
  $('ov').innerHTML=`<div class="ov" onclick="if(event.target===this)closeModal()"><div class="mdl">
    <div class="mh"><h3>${title}</h3><button class="btn sm" onclick="closeModal()">✖</button></div>
    <div class="mb" id="mbody">${bodyHtml}</div>${footHtml?`<div class="mf">${footHtml}</div>`:''}</div></div>`;
}
function confirmBox(title,msg,okText,fn){
  modal(title,`<div>${msg}</div>`,`<button class="btn red" id="okb">${okText}</button><button class="btn" onclick="closeModal()">إلغاء</button>`);
  $('okb').onclick=()=>{closeModal();fn();};
}
function toast(title,text,col){
  const t=document.createElement('div'); t.className='toast'; if(col) t.style.borderColor=col;
  t.innerHTML=`<b>${esc(title)}</b>${text?`<span style="color:var(--sub)">${esc(text)}</span>`:''}`;
  $('toasts').appendChild(t); setTimeout(()=>t.remove(),8000);
}
function showEvents(evs){
  const max=evs.length?evs[evs.length-1].id:0;
  if(lastEv===null){ lastEv=max; return; }
  evs.filter(e=>e.id>lastEv).forEach(e=>toast(e.title,e.text,e.title.includes('🔴')?'#f85149':'#3fb950'));
  lastEv=Math.max(lastEv,max);
}
async function run(body,okMsg){
  const r=await api('/api/action',body);
  if(r.ok) toast('✅ '+(r.msg||okMsg||'تم'),'', '#3fb950'); else toast('⚠️ خطأ',r.msg||'', '#f85149');
  return r;
}

/* ---------- أوامر ---------- */
function refreshNow(){ api('/api/action',{type:'refresh'}); toast('🔄 جارٍ التحديث الفوري...',''); }
async function pingBox(addr,title){
  modal(esc(title),`<div class="note">جارٍ إرسال 4 نبضات Ping إلى <span class="ltr">${esc(addr)}</span>...</div>`,'');
  const r=await api('/api/action',{type:'ping',address:addr});
  if(!$('mbody')) return;
  $('mbody').innerHTML=r.ok?`<pre>${r.lines.map(esc).join('\n')}</pre><div style="margin-top:12px;font-weight:700" class="${r.okCount?'g':'r'}">النتيجة النهائية: وصل ${r.okCount} من ${r.total}</div>`
    :`<div class="r">خطأ أثناء الفحص: ${esc(r.msg)}</div>`;
}
function ifaceBox(name){
  const i=S&&S.snap&&S.snap.ifs.find(x=>x.name===name); if(!i) return;
  modal('⚙️ التحكم بالمنفذ '+esc(i.name),
    `<pre>الحالة: ${i.disabled?'معطل (Disabled)':i.running?'متصل ونشط (Running)':'غير متصل (No Link)'}
السرعة الحالية: <span class="ltr">↓ ${bw(i.rxRate)} | ↑ ${bw(i.txRate)}</span>
إجمالي التحميل (RX): <span class="ltr g">${gbx(i.totalRx)}</span>
إجمالي الرفع (TX): <span class="ltr b">${gbx(i.totalTx)}</span>
المجموع: <span class="ltr y">${gbx(i.totalRx+i.totalTx)}</span></pre>`,
    `<button class="btn ${i.disabled?'primary':'red'}" id="b1">${i.disabled?'تفعيل المنفذ (Enable)':'إيقاف المنفذ (Disable)'}</button>
     <button class="btn" id="b2">إعادة تشغيل المنفذ</button><button class="btn" onclick="closeModal()">إغلاق</button>`);
  $('b1').onclick=()=>{closeModal();run({type:'iface',name,op:i.disabled?'enable':'disable'});};
  $('b2').onclick=()=>{closeModal();toast('جارٍ إعادة تشغيل '+name,'');run({type:'iface',name,op:'restart'});};
}
function rebootRouter(){
  confirmBox('⚠️ تأكيد إعادة تشغيل الراوتر','هل أنت متأكد من رغبتك في إعادة تشغيل الميكروتيك الرئيسي الآن؟ سينقطع الاتصال مؤقتاً.','نعم، أعد التشغيل',()=>run({type:'reboot'}));
}
function quitApp(){
  confirmBox('إيقاف البرنامج','سيتوقف البرنامج عن المراقبة والتنبيهات بالخلفية. هل تريد الإيقاف؟','نعم، أوقف',async()=>{
    await api('/api/action',{type:'quit'}).catch(()=>{});
    document.body.innerHTML='<div style="padding:60px;text-align:center;font-size:20px;color:#8b949e">⏻ تم إيقاف البرنامج — يمكنك إغلاق النافذة</div>';
  });
}

/* ---------- الراوترات المحفوظة (الشاشة الأولى) ---------- */
let RT=null;
async function showRouters(first){
  RT=await api('/api/routers');
  const cards=RT.list.map(r=>`<div class="rc ${r.id===RT.active?'act':''}" onclick="enterRouter('${r.id}')">
      <div class="ic">📡</div>
      <div class="inf"><b>${esc(r.name||r.local||r.cloud||'راوتر')}${r.id===RT.active?'  ● مراقَب الآن':''}</b><span>${esc(r.user)}@${esc(r.local||r.cloud)}:${esc(r.port)}</span></div>
      <button class="ib" title="تعديل" onclick="event.stopPropagation();loginPage('${r.id}')">✏️</button>
      <button class="ib" title="حذف" onclick="event.stopPropagation();delRouter('${r.id}')">🗑</button></div>`).join('');
  $('rs').innerHTML=`<div class="rsin"><div class="rhead"><div class="tt"><b>Net Microtik Monitor</b><span>اختر الراوتر للمراقبة</span></div>
    ${RT.list.length&&S&&S.configured?`<button class="btn" onclick="hideRouters()">رجوع</button>`:''}
    <button class="btn exit" onclick="quitApp()">✖ خروج</button></div>
    ${cards||'<div class="note" style="padding:30px;text-align:center">لا توجد راوترات محفوظة. اضغط + لإضافة راوتر.</div>'}</div>
    <button class="fab" title="إضافة راوتر" onclick="loginPage(null)">+</button>`;
  $('rs').style.display='block';
  if(first&&!RT.list.length) loginPage(null);
}
function hideRouters(){ $('rs').style.display='none'; }
async function enterRouter(id){
  await api('/api/routers',{op:'enter',id}); hideRouters(); modsSig=''; LOGS=[]; logV=''; toast('🔗 جارٍ الاتصال بالراوتر...','','#58a6ff');
}
function delRouter(id){
  const r=RT.list.find(x=>x.id===id); if(!r) return;
  confirmBox('حذف الراوتر',`حذف "${esc(r.name||r.local||r.cloud)}" من القائمة المحفوظة؟`,'حذف',async()=>{ await api('/api/routers',{op:'delete',id}); modsSig=''; LOGS=[]; logV=''; showRouters(); });
}
const fl=(id,label,val,type='text',ph='')=>`<div class="fl"><label>${label}</label><input id="${id}" type="${type}" value="${esc(val)}" placeholder="${esc(ph)}"></div>`;
// صفحة تسجيل الدخول: راوتر جديد أو تعديل. بدون مودمات ولا تنبيهات.
function loginPage(id){
  const r=id?RT.list.find(x=>x.id===id):null, v=k=>r?r[k]:'';
  modal(r?'✏️ تعديل الراوتر':'➕ إضافة راوتر',
    `${fl('l_name','🏷️ اسم الراوتر',v('name'),'text','شبكة النور')}
     ${fl('l_local','عنوان الراوتر (IP أو كلاود DNS)',v('local')||v('cloud'),'text','192.168.88.1 أو xxxx.sn.mynetname.net')}
     <div class="grid2">${fl('l_user','اسم المستخدم',v('user'))}${fl('l_port','منفذ API',r?v('port'):'8728','text','8728')}</div>
     ${fl('l_pass','كلمة المرور',v('pass'),'password')}
     <div class="box"><label class="chk" style="margin:0"><input type="checkbox" id="l_rem" ${(!r||v('pass'))?'checked':''} style="width:auto"> 🔐 حفظ بيانات الدخول</label></div>
     <div id="l_err" class="r" style="margin-top:10px"></div>`,
    `<button class="btn go" id="sv">حفظ</button><button class="btn" onclick="closeModal()">إلغاء</button>`);
  $('sv').onclick=async()=>{
    const b={op:'save',id:id||'',remember:$('l_rem').checked};
    [['name','l_name'],['local','l_local'],['user','l_user'],['port','l_port'],['pass','l_pass']].forEach(([k,e])=>b[k]=$(e).value);
    const res=await api('/api/routers',b);
    if(!res.ok){ $('l_err').textContent=res.msg||'تعذر الحفظ'; return; }
    closeModal(); modsSig=''; LOGS=[]; logV='';
    if(res.entered){ hideRouters(); toast('✅ تم الحفظ — جارٍ الاتصال...','','#3fb950'); } else showRouters();
  };
}

/* ---------- إعدادات الراوتر الحالي (داخل اللوحة): المودمات + الواجهة + التنبيهات ---------- */
async function openSettings(){
  const c=await api('/api/settings');
  modal('⚙️ إعدادات '+esc(S&&S.name||'الراوتر'),
    `${fl('f_wan','واجهة الإنترنت (WAN)',c.wan,'text','ether1')}
     <div class="fl"><label>المودمات: سطر لكل مودم (IP ثم الاسم)</label><textarea id="f_modems" placeholder="90.90.2.2 شيبان&#10;90.90.3.3 اكرم">${esc(c.modems)}</textarea></div>
     <div class="box">
     <label class="chk" style="margin-top:0"><input type="checkbox" id="f_nErr" ${c.notifErr==='1'?'checked':''}> 🔴 إشعار فوري عند أي خطأ أحمر في السجل</label>
     <label class="chk"><input type="checkbox" id="f_nWarn" ${c.notifWarn==='1'?'checked':''}> 🟡 إشعار للتحذيرات الصفراء أيضاً</label>
     ${c.isWin?`<label class="chk"><input type="checkbox" id="f_auto" ${c.autostart?'checked':''}> تشغيل البرنامج تلقائياً مع ويندوز (مراقبة وتنبيهات بالخلفية)</label>`:''}</div>`,
    `<button class="btn go" id="sv">حفظ</button><button class="btn" onclick="closeModal()">إلغاء</button>`);
  document.querySelector('.mdl').style.width='min(620px,100%)';
  $('sv').onclick=async()=>{
    const b={wan:$('f_wan').value.trim()||'ether1',modems:$('f_modems').value.trim()};
    b.notifErr=$('f_nErr').checked?'1':'0'; b.notifWarn=$('f_nWarn').checked?'1':'0';
    b.autostart=!!($('f_auto')&&$('f_auto').checked);
    await api('/api/settings',b); closeModal(); modsSig=''; LOGS=[]; logV=''; toast('✅ تم الحفظ','','#3fb950');
  };
}

/* أزرار داخل القوائم المتحدثة كل ثانية: نلتقط الضغط لحظة النزول حتى لا يضيع */
document.addEventListener('pointerdown',e=>{
  if(e.button!==0) return;
  const el=e.target.closest('[data-act]'); if(!el) return;
  const a=el.dataset.act;
  if(a==='kick'){ const mode=listMode, id=el.dataset.id, n=el.dataset.n;
    returnTo=mode;
    confirmBox('فصل المتصل',`هل تريد فصل (<span class="ltr">${esc(n)}</span>) ؟`,'نعم، افصل',()=>run({type:'kick',mode,id,name:n})); }
  else if(a==='iface') ifaceBox(el.dataset.n);
  else if(a==='mod') pingBox(el.dataset.ip,`فحص المودم: ${el.dataset.n} (${el.dataset.ip})`);
});
document.addEventListener('keydown',e=>{ if(e.key==='Escape'){ if(logOpen) closeLog(); else closeModal(); } });
poll();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()

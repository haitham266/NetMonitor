# -*- coding: utf-8 -*-
"""
مراقب الشبكة — نسخة اللابتوب (ويندوز)
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

APP_NAME = "مراقب الشبكة"
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


def save_cfg(c):
    global _cfg
    with _cfg_lock:
        os.makedirs(CFG_DIR, exist_ok=True)
        clean = {k: str(c.get(k, DEFAULTS[k])).strip() for k in DEFAULTS}
        with open(CFG_FILE, "w", encoding="utf-8") as f:
            json.dump(clean, f, ensure_ascii=False, indent=2)
        _cfg = clean


def net_name(c=None):
    return ((c or load_cfg()).get("name") or "").strip() or "شبكتي"


def configured(c):
    return bool(c.get("user") and (c.get("local") or c.get("cloud")))


# ======================= بروتوكول RouterOS API =======================
class Trap(Exception):
    pass


class Ros:
    def __init__(self, host, port, timeout):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(15)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.lock = threading.Lock()

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass

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

    def _rlen(self):
        return self._rlen_from(self._recv(1)[0])

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

    def _sentence(self, idle_ok=False):
        words = []
        first = True
        while True:
            if first:
                first = False
                try:
                    c = self.s.recv(1)
                except (socket.timeout, TimeoutError):
                    if idle_ok:
                        return None
                    raise
                if not c:
                    raise IOError("انقطع الاتصال بالراوتر")
                n = self._rlen_from(c[0])
            else:
                n = self._rlen()
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
        self.s.sendall(data + b"\x00")

    def stream(self, words, stop, on_idle, on_re):
        """بث مستمر (مثل /log/print follow-only)."""
        with self.lock:
            self._send(words)
            err = None
            while True:
                if stop():
                    raise IOError("stop")
                sn = self._sentence(idle_ok=True)
                if sn is None:
                    on_idle()
                    continue
                if not sn:
                    continue
                t = sn[0]
                if t == "!re":
                    on_re(self._attrs(sn))
                elif t == "!trap":
                    err = self._attrs(sn).get("message", "error")
                elif t == "!fatal":
                    raise IOError("fatal")
                elif t == "!done":
                    if err is not None:
                        raise Trap(err)
                    return

    def cmd(self, *words):
        with self.lock:
            self._send(words)
            res, err = [], None
            while True:
                sn = self._sentence()
                if not sn:
                    continue
                t = sn[0]
                if t == "!re":
                    res.append(self._attrs(sn))
                elif t == "!trap":
                    err = self._attrs(sn).get("message", "error")
                elif t == "!fatal":
                    raise IOError("fatal")
                elif t == "!done":
                    if err is not None:
                        raise Trap(err)
                    ret = self._attrs(sn).get("ret")
                    if ret is not None and not res:
                        res.append({"ret": ret})
                    return res


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
            r.cmd("/login", "=name=" + c.get("user", ""), "=password=" + c.get("pass", ""))
            if set_via:
                S["via"] = "محلي LAN" if key == "local" else "كلاود Cloud"
            return r
        except Exception as e:
            if r:
                r.close()
            last = e
    raise last


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


def alert(title, text, toast=True):
    with S_LOCK:
        S["evId"] += 1
        S["events"] = (S["events"] + [{"id": S["evId"], "title": title, "text": text, "ts": int(time.time() * 1000)}])[-30:]
    if toast:
        win_toast(title + " — " + net_name(), text)


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
def main_loop():
    ros, gen, prev_if, was_wan = None, S["gen"], {}, None
    while not STOP.is_set():
        if gen != S["gen"]:
            if ros:
                ros.close()
            ros, gen, was_wan = None, S["gen"], None
            prev_if.clear()
        c = load_cfg()
        if not configured(c):
            S["error"] = None
            STOP.wait(1)
            continue
        try:
            r = ros or ros_connect(c)
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
            if ros:
                ros.close()
            ros = None
            S["error"] = friendly(e)
        STOP.wait(2)
    if ros:
        ros.close()


# ======================= حلقة المودمات (كل ~3 ثواني، 5 اتصالات متوازية) =======================
def modem_loop():
    conns = [None] * 5
    gen, last_down, first = S["gen"], set(), True
    down_since = {}
    while not STOP.is_set():
        if gen != S["gen"]:
            for i, cn in enumerate(conns):
                if cn:
                    cn.close()
                conns[i] = None
            gen, first, last_down = S["gen"], True, set()
        FORCE.clear()
        c = load_cfg()
        lst = parse_modems(c.get("modems", ""))
        if not lst or not configured(c):
            S["modems"], S["modemsReady"] = [], True
            FORCE.wait(3)
            continue

        prev = {m["ip"]: m for m in S["modems"]}
        workers = min(len(lst), len(conns))
        results = [None] * len(lst)

        def work(w):
            i = w
            while i < len(lst):
                name, mip = lst[i]
                try:
                    if conns[w] is None:
                        conns[w] = ros_connect(c, set_via=False)
                    rows = conns[w].cmd("/ping", "=address=" + mip, "=count=2", "=interval=0.5")
                    up = any(r.get("received", "0") != "0" or "time" in r for r in rows)
                except Trap:
                    up = False
                except Exception:
                    if conns[w]:
                        conns[w].close()
                    conns[w] = None
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
    for cn in conns:
        if cn:
            cn.close()


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
            r = ros_connect(c, set_via=False)
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

            r.s.settimeout(3)
            gen = my_gen

            def on_idle():
                st["idle"] += 3
                flush()

            def on_re(m):
                st["idle"] = 0
                add_logs([to_log(m)], True, pending)
                flush()

            r.stream(["/log/print", "=follow-only=", "=.proplist=.id,time,topics,message"],
                     lambda: STOP.is_set() or gen != S["gen"] or st["idle"] > 300, on_idle, on_re)
        except Trap as e:
            with S_LOCK:
                S["logError"] = str(e)
                S["logVer"] += 1
            wait = 15
        except Exception as e:
            wait = 0.2 if str(e) == "stop" else 5
        finally:
            flush(True)
            if r:
                r.close()
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
        threading.Timer(0.6, lambda: os._exit(0)).start()
        return {"ok": True}

    c = load_cfg()
    r = ros_connect(c, set_via=False)
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
        r.close()


# ======================= خادم الواجهة المحلي =======================
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
            return self._send(200, st)
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
        if p == "/api/settings":
            save_cfg(body)
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
        global configured, net_name
        net_name = lambda c=None: "شبكة النور"  # noqa: E731
        configured = lambda c: True  # noqa: E731
        start_demo()
    else:
        threading.Thread(target=main_loop, daemon=True).start()
        threading.Thread(target=modem_loop, daemon=True).start()
        threading.Thread(target=log_loop, daemon=True).start()
    if not background and "--no-window" not in args:
        threading.Timer(0.5, open_window).start()
    srv.serve_forever()


# ======================= الواجهة =======================
HTML = r"""<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>مراقب الشبكة</title>
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
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1 id="title">📡 مراقب الشبكة</h1>
    <button class="btn" onclick="refreshNow()">🔄 تحديث</button>
    <button class="btn" onclick="openSettings()">⚙️ الإعدادات</button>
    <button class="btn red" onclick="quitApp()">⏻ إيقاف</button>
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
  b.textContent=t; b.style.color=col; b.style.borderColor=col; b.style.background=col+'22';
}

function render(){
  const s=S.snap, mods=S.modems||[], dn=mods.filter(m=>!m.up);
  if(!S.configured){ setBanner('⚙️ أدخل بيانات الراوتر من زر الإعدادات','#58a6ff'); if(!askedSettings){askedSettings=true;openSettings();} }
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

/* ---------- الإعدادات ---------- */
async function openSettings(){
  const c=await api('/api/settings');
  const f=(k,label,type='text',ph='')=>`<div><label>${label}</label><input id="f_${k}" type="${type}" value="${esc(c[k])}" placeholder="${esc(ph)}" dir="ltr" style="text-align:right"></div>`;
  modal('⚙️ إعدادات الاتصال والمراقبة',
    `${f('name','🏷️ اسم الشبكة','text','مثال: شبكة النور').replace('dir="ltr" style="text-align:right"','')}
     <div class="grid2">${f('local','عنوان الراوتر المحلي','text','192.168.88.1')}${f('cloud','عنوان الكلاود','text','xxxx.sn.mynetname.net')}
     ${f('user','اسم المستخدم')}${f('pass','كلمة المرور','password')}
     ${f('port','منفذ API','text','8728')}${f('wan','واجهة الإنترنت','text','ether1')}</div>
     <label>المودمات — سطر لكل مودم: الاسم و IP (الاسم حر)</label>
     <textarea id="f_modems" placeholder="90.90.2.2 شيبان&#10;90.90.3.3 اكرم">${esc(c.modems)}</textarea>
     <label style="margin-top:16px;font-weight:700">🔔 تنبيهات سجل الراوتر (LOG)</label>
     <label class="chk" style="margin-top:4px"><input type="checkbox" id="f_nErr" ${c.notifErr==='1'?'checked':''}> 🔴 تنبيه فوري عند أي خطأ أحمر (موصى به)</label>
     <label class="chk" style="margin-top:6px"><input type="checkbox" id="f_nWarn" ${c.notifWarn==='1'?'checked':''}> 🟡 تنبيه للتحذيرات الصفراء أيضاً</label>
     ${c.isWin?`<label class="chk"><input type="checkbox" id="f_auto" ${c.autostart?'checked':''}> تشغيل البرنامج تلقائياً مع ويندوز (مراقبة وتنبيهات بالخلفية)</label>`:''}`,
    `<button class="btn primary" id="sv">حفظ واتصال</button><button class="btn" onclick="closeModal()">إلغاء</button>`);
  document.querySelector('.mdl').style.width='min(720px,100%)';
  $('sv').onclick=async()=>{
    const b={}; ['name','local','cloud','user','pass','port','wan','modems'].forEach(k=>b[k]=$('f_'+k).value.trim());
    b.notifErr=$('f_nErr').checked?'1':'0'; b.notifWarn=$('f_nWarn').checked?'1':'0';
    b.autostart=!!($('f_auto')&&$('f_auto').checked);
    await api('/api/settings',b); closeModal(); modsSig=''; LOGS=[]; logV=''; toast('✅ تم الحفظ — جارٍ الاتصال...','','#3fb950');
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

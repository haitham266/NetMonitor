package net.netmonitor.app

import android.annotation.SuppressLint
import android.app.Activity
import android.app.AlertDialog
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.ServiceInfo
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.ClipDrawable
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.LayerDrawable
import android.net.Uri
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import android.provider.Settings
import android.text.Html
import android.view.Gravity
import android.view.View
import android.widget.*
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap

const val CH_MON = "monitor"
const val CH_ALERT = "alerts"

val DEFAULT_MODEMS: String = ""
const val LOG_MAX = 500
const val NOTIF_LOG = 50

fun netName(p: SharedPreferences): String = p.getString("name", null)?.trim().let { if (it.isNullOrEmpty()) "شبكتي" else it }

class Trap(m: String) : Exception(m)

class Ros(host: String, port: Int, timeout: Int) {
    private val s = Socket()
    private val ins: InputStream
    private val out: OutputStream

    init {
        s.connect(InetSocketAddress(host, port), timeout)
        s.soTimeout = 15000
        s.keepAlive = true
        ins = s.getInputStream()
        out = s.getOutputStream()
    }

    fun close() { try { s.close() } catch (e: Exception) { } }

    private fun wlen(n: Int) {
        when {
            n < 0x80 -> out.write(n)
            n < 0x4000 -> { out.write((n shr 8) or 0x80); out.write(n and 0xFF) }
            else -> { out.write((n shr 16) or 0xC0); out.write((n shr 8) and 0xFF); out.write(n and 0xFF) }
        }
    }

    private fun rb(): Int { val c = ins.read(); if (c < 0) throw IOException("closed"); return c }

    fun setTimeout(ms: Int) { s.soTimeout = ms }

    private fun rlen(): Int = rlenFrom(rb())

    private fun rlenFrom(c: Int): Int {
        return when {
            (c and 0x80) == 0 -> c
            (c and 0xC0) == 0x80 -> ((c and 0x3F) shl 8) or rb()
            (c and 0xE0) == 0xC0 -> { var v = c and 0x1F; repeat(2) { v = (v shl 8) or rb() }; v }
            (c and 0xF0) == 0xE0 -> { var v = c and 0x0F; repeat(3) { v = (v shl 8) or rb() }; v }
            else -> { var v = 0; repeat(4) { v = (v shl 8) or rb() }; v }
        }
    }

    // idleOk: يرجع null إذا لم تصل أي بيانات خلال مهلة القراءة (للبث المستمر)
    private fun readSentence(idleOk: Boolean = false): List<String>? {
        val w = ArrayList<String>()
        var firstWord = true
        while (true) {
            val n = if (firstWord) {
                firstWord = false
                val c = try { ins.read() } catch (e: java.net.SocketTimeoutException) { if (idleOk) return null else throw e }
                if (c < 0) throw IOException("closed")
                rlenFrom(c)
            } else rlen()
            if (n == 0) return w
            val b = ByteArray(n)
            var o = 0
            while (o < n) { val r = ins.read(b, o, n - o); if (r < 0) throw IOException("closed"); o += r }
            w.add(String(b, Charsets.UTF_8))
        }
    }

    private fun attrs(sn: List<String>): Map<String, String> {
        val m = HashMap<String, String>()
        for (w in sn) if (w.startsWith("=")) {
            val i = w.indexOf('=', 1)
            if (i > 0) m[w.substring(1, i)] = w.substring(i + 1)
        }
        return m
    }

    private fun send(words: Array<out String>) {
        for (w in words) { val b = w.toByteArray(Charsets.UTF_8); wlen(b.size); out.write(b) }
        out.write(0)
        out.flush()
    }

    @Synchronized
    fun streamImpl(words: Array<String>, stop: () -> Boolean, onIdle: () -> Unit, onRe: (Map<String, String>) -> Unit) {
        send(words)
        var err: String? = null
        while (true) {
            if (stop()) throw IOException("stop")
            val sn = readSentence(true)
            if (sn == null) { onIdle(); continue }
            if (sn.isEmpty()) continue
            when (sn[0]) {
                "!re" -> onRe(attrs(sn))
                "!trap" -> err = attrs(sn)["message"] ?: "error"
                "!fatal" -> throw IOException("fatal")
                "!done" -> { if (err != null) throw Trap(err); return }
            }
        }
    }

    @Synchronized
    fun cmd(vararg words: String): List<Map<String, String>> {
        send(words)
        val res = ArrayList<Map<String, String>>()
        var err: String? = null
        while (true) {
            val sn = readSentence()!!
            if (sn.isEmpty()) continue
            when (sn[0]) {
                "!re" -> res.add(attrs(sn))
                "!trap" -> err = attrs(sn)["message"] ?: "error"
                "!fatal" -> throw IOException("fatal")
                "!done" -> {
                    if (err != null) throw Trap(err)
                    val ret = attrs(sn)["ret"]
                    if (ret != null && res.isEmpty()) res.add(mapOf("ret" to ret))
                    return res
                }
            }
        }
    }
}

// سطر من سجل الراوتر: level 2 = أحمر (error/critical) ، 1 = أصفر (warning) ، 0 = عادي
class LogEntry(val id: Long, val time: String, val topics: String, val msg: String, val level: Int)

fun toLogEntry(m: Map<String, String>): LogEntry? {
    val id = m[".id"]?.removePrefix("*")?.toLongOrNull(16) ?: return null
    val topics = m["topics"] ?: ""
    val t = topics.split(',')
    val lvl = if ("error" in t || "critical" in t) 2 else if ("warning" in t) 1 else 0
    return LogEntry(id, m["time"] ?: "", topics, m["message"] ?: "", lvl)
}

class IfStat(val name: String, val running: Boolean, val disabled: Boolean, val rxRate: Long, val txRate: Long, val totalRx: Long, val totalTx: Long)
class ModemStat(val name: String, val ip: String, val up: Boolean, val downSince: Long?)

// HOST  = /ip/hotspot/host   (كل الأجهزة المتصلة بالهوتسبوت)
// ACTIVE = /ip/hotspot/active (المستخدمون المسجلون دخول)
class Snapshot(
    val wan: String, val wanUp: Boolean, val ip: String,
    val hostOk: Boolean, val hosts: List<Map<String, String>>,
    val activeOk: Boolean, val active: List<Map<String, String>>,
    val uptime: String, val temp: String, val volt: String,
    val cpu: Int, val usedMem: Long, val totalMem: Long, val ramPct: Int,
    val usedHdd: Long, val totalHdd: Long, val hddPct: Int,
    val ifs: List<IfStat>
)

object Shared {
    @Volatile var snap: Snapshot? = null
    @Volatile var modems: List<ModemStat> = emptyList()
    @Volatile var modemsReady = false
    @Volatile var error: String? = null
    @Volatile var via = ""
    @Volatile var forceModem = false
    @Volatile var cfgGen = 0
    @Volatile var logs: List<LogEntry> = emptyList()   // الأقدم أولاً
    @Volatile var logsReady = false
    @Volatile var logError: String? = null
    @Volatile var logUnread = 0                         // أخطاء حمراء لم تُقرأ
    @Volatile var logVer = 0
}

fun mb(s: String?) = (s?.toLongOrNull() ?: 0L) / 1048576
fun gb(b: Long) = if (b >= 1073741824L) "%.2f GB".format(b / 1073741824.0) else "${b / 1048576L} MB"
fun gbx(b: Long) = "%.2f GB".format(b / 1073741824.0)
fun bw(v: Long) = if (v >= 1000000) "%.1f Mbps".format(v / 1e6) else if (v >= 1000) "${v / 1000} Kbps" else "$v bps"
fun ago(t: Long): String {
    val s = (System.currentTimeMillis() - t) / 1000
    return if (s < 60) "$s ث" else if (s < 3600) "${s / 60} د" else "${s / 3600} س"
}

// يقبل: "الاسم,IP" أو "IP" فقط، وأي فاصل (فاصلة / مسافة / تاب)
fun parseModems(raw: String): List<Pair<String, String>> {
    val out = ArrayList<Pair<String, String>>()
    val ipRe = Regex("""\d{1,3}(\.\d{1,3}){3}""")
    for (line in raw.lines()) {
        val t = line.trim()
        if (t.isEmpty()) continue
        val m = ipRe.find(t) ?: continue
        val ip = m.value
        var name = t.replace(ip, "").trim().trim(',', ';', '،', '|', ':', '=', '-', ' ', '\t')
        if (name.isEmpty()) name = ip
        out.add(name to ip)
    }
    return out
}

fun rosConnect(prefs: SharedPreferences): Ros {
    val port = prefs.getString("port", "8728")?.toIntOrNull() ?: 8728
    var last: Exception = IOException("أدخل عنوان الراوتر من الإعدادات")
    for ((k, t) in listOf("local" to 2500, "cloud" to 8000)) {
        val h = prefs.getString(k, "").orEmpty()
        if (h.isBlank()) continue
        var r: Ros? = null
        try {
            r = Ros(h, port, t)
            r.cmd("/login", "=name=" + prefs.getString("user", ""), "=password=" + prefs.getString("pass", ""))
            Shared.via = if (k == "local") "محلي LAN" else "كلاود Cloud"
            return r
        } catch (e: Exception) { r?.close(); last = e }
    }
    throw last
}

fun startMonitorService(ctx: Context) {
    ctx.getSharedPreferences("cfg", Context.MODE_PRIVATE).edit().putBoolean("enabled", true).apply()
    val i = Intent(ctx, MonitorService::class.java)
    try {
        if (Build.VERSION.SDK_INT >= 26) ctx.startForegroundService(i) else ctx.startService(i)
    } catch (e: Exception) { }
}

// ======================= التشغيل التلقائي بعد إعادة تشغيل الجوال =======================
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent?) {
        val p = ctx.getSharedPreferences("cfg", Context.MODE_PRIVATE)
        if (!p.contains("user") || !p.getBoolean("enabled", true)) return
        startMonitorService(ctx)
    }
}

// ======================= خدمة المراقبة بالخلفية =======================
class MonitorService : Service() {
    private val prefs by lazy { getSharedPreferences("cfg", MODE_PRIVATE) }
    @Volatile private var running = false
    private var wl: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null
    private var lastNotifText = ""
    private val prevIf = HashMap<String, Triple<Long, Long, Long>>()
    private val downSince = ConcurrentHashMap<String, Long>()
    private var alertCnt = 0

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        if (Build.VERSION.SDK_INT >= 26) {
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(NotificationChannel(CH_MON, "المراقبة المستمرة", NotificationManager.IMPORTANCE_LOW))
            nm.createNotificationChannel(NotificationChannel(CH_ALERT, "تنبيهات الشبكة", NotificationManager.IMPORTANCE_HIGH))
        }
    }

    private fun goForeground(text: String) {
        val n = buildNotif(text)
        try {
            if (Build.VERSION.SDK_INT >= 29) startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
            else startForeground(1, n)
        } catch (e: Exception) {
            try { startForeground(1, n) } catch (e2: Exception) { }
        }
    }

    @Suppress("DEPRECATION")
    @SuppressLint("WakelockTimeout")
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP") {
            prefs.edit().putBoolean("enabled", false).apply()
            running = false
            stopForeground(true)
            stopSelf()
            return START_NOT_STICKY
        }
        goForeground(if (lastNotifText.isEmpty()) "جارٍ الاتصال بالراوتر..." else lastNotifText)
        if (!running) {
            running = true
            try {
                val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
                wl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "netmonitor:monitor").apply {
                    setReferenceCounted(false); acquire()
                }
            } catch (e: Exception) { }
            // يمنع الواي فاي من النوم عند إطفاء الشاشة
            try {
                val wm = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
                wifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "netmonitor:wifi").apply {
                    setReferenceCounted(false); acquire()
                }
            } catch (e: Exception) { }
            Thread { mainLoop() }.apply { isDaemon = true; start() }
            Thread { modemLoop() }.apply { isDaemon = true; start() }
            Thread { logLoop() }.apply { isDaemon = true; start() }
        }
        return START_STICKY
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        // عند سحب التطبيق من قائمة التطبيقات الأخيرة: تبقى الخدمة تعمل
        super.onTaskRemoved(rootIntent)
        if (prefs.getBoolean("enabled", true)) startMonitorService(applicationContext)
    }

    override fun onDestroy() {
        running = false
        try { wl?.release() } catch (e: Exception) { }
        try { wifiLock?.release() } catch (e: Exception) { }
        super.onDestroy()
    }

    @Suppress("DEPRECATION")
    private fun builder(ch: String): Notification.Builder =
        if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, ch) else Notification.Builder(this)

    private fun buildNotif(text: String): Notification {
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 1, Intent(this, MonitorService::class.java).setAction("STOP"), PendingIntent.FLAG_IMMUTABLE)
        return builder(CH_MON)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle("📡 ${netName(prefs)} — مراقبة مستمرة")
            .setContentText(text)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(open)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "إيقاف", stop)
            .build()
    }

    private fun updateNotif(text: String) {
        if (text == lastNotifText) return
        lastNotifText = text
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(1, buildNotif(text))
    }

    private fun alert(title: String, text: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val n = builder(CH_ALERT)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(title)
            .setContentText(text)
            .setSubText(netName(prefs))
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        nm.notify(100 + (alertCnt++ % 50), n)
    }

    private fun nap(ms: Long, stopOnForce: Boolean = false) {
        var t = 0L
        while (running && t < ms) {
            if (stopOnForce && Shared.forceModem) return
            try { Thread.sleep(200) } catch (e: InterruptedException) { return }
            t += 200
        }
    }

    // ---------- الحلقة الرئيسية: موارد + واجهات + HOST + ACTIVE (كل ثانيتين) ----------
    private fun mainLoop() {
        var ros: Ros? = null
        var myGen = Shared.cfgGen
        var wasWanUp: Boolean? = null

        while (running) {
            if (myGen != Shared.cfgGen) {
                ros?.close(); ros = null
                myGen = Shared.cfgGen
                prevIf.clear()
            }
            try {
                val r = ros ?: rosConnect(prefs).also { ros = it }
                val res = r.cmd("/system/resource/print").firstOrNull() ?: emptyMap()
                val hl = HashMap<String, String>()
                try {
                    for (row in r.cmd("/system/health/print")) {
                        val n = row["name"]
                        if (n != null) hl[n] = row["value"] ?: "" else hl.putAll(row)
                    }
                } catch (e: Trap) { }

                // HOST: كل الأجهزة الظاهرة في الهوتسبوت
                var hostOk = true
                val hosts = try {
                    r.cmd("/ip/hotspot/host/print", "=.proplist=.id,mac-address,address,to-address,uptime,idle-time,authorized,bypassed,comment,bytes-in,bytes-out")
                } catch (e: Trap) { hostOk = false; emptyList<Map<String, String>>() }

                // ACTIVE: المستخدمون المسجلون دخول بالكروت
                var activeOk = true
                val active = try {
                    r.cmd("/ip/hotspot/active/print", "=.proplist=.id,user,address,uptime,bytes-in,bytes-out,mac-address")
                } catch (e: Trap) { activeOk = false; emptyList<Map<String, String>>() }

                val wan = prefs.getString("wan", "ether1") ?: "ether1"
                val ip = try { r.cmd("/ip/address/print", "?interface=$wan").firstOrNull()?.get("address") ?: "-" } catch (e: Trap) { "-" }
                val now = System.currentTimeMillis()

                val ifList = ArrayList<IfStat>()
                var wanUp = false
                for (i in r.cmd("/interface/print", "?type=ether")) {
                    val n = i["name"] ?: continue
                    val rx = i["rx-byte"]?.toLongOrNull() ?: 0L
                    val tx = i["tx-byte"]?.toLongOrNull() ?: 0L
                    val run = i["running"] == "true"
                    val dis = i["disabled"] == "true"
                    if (n == wan) wanUp = run
                    val p = prevIf[n]
                    var rr = 0L
                    var tr = 0L
                    if (p != null && now > p.third) {
                        val calcR = (rx - p.first) * 8000 / (now - p.third)
                        val calcT = (tx - p.second) * 8000 / (now - p.third)
                        rr = if (calcR > 0L) calcR else 0L
                        tr = if (calcT > 0L) calcT else 0L
                    }
                    prevIf[n] = Triple(rx, tx, now)
                    ifList.add(IfStat(n, run, dis, rr, tr, rx, tx))
                }

                val cpuLoad = res["cpu-load"]?.toIntOrNull() ?: 0
                val freeMem = mb(res["free-memory"])
                val rawTotalMem = mb(res["total-memory"])
                val totalMem = if (rawTotalMem < 1L) 1L else rawTotalMem
                val usedMem = totalMem - freeMem
                val ramPercent = ((usedMem.toDouble() / totalMem.toDouble()) * 100.0).toInt()

                val freeHdd = mb(res["free-hdd-space"])
                val rawTotalHdd = mb(res["total-hdd-space"])
                val totalHdd = if (rawTotalHdd < 1L) 1L else rawTotalHdd
                val usedHdd = totalHdd - freeHdd
                val hddPercent = ((usedHdd.toDouble() / totalHdd.toDouble()) * 100.0).toInt()

                val temp = hl["temperature"] ?: hl["cpu-temperature"] ?: "-"
                val volt = hl["voltage"] ?: "-"
                val uptime = res["uptime"] ?: "-"

                Shared.snap = Snapshot(
                    wan, wanUp, ip, hostOk, hosts, activeOk, active, uptime, temp, volt,
                    cpuLoad, usedMem, totalMem, ramPercent, usedHdd, totalHdd, hddPercent, ifList
                )
                Shared.error = null

                val prevWan = wasWanUp
                if (prevWan != null && prevWan != wanUp) {
                    alert(if (wanUp) "🟢 عاد الإنترنت" else "🔴 انقطع الإنترنت", "الواجهة: $wan")
                }
                wasWanUp = wanUp

                val mods = Shared.modems
                val mUp = mods.count { it.up }
                updateNotif(
                    (if (wanUp) "🌐 متصل" else "🌐 مقطوع") +
                            " • HOST ${if (hostOk) hosts.size.toString() else "-"}" +
                            " • ACTIVE ${if (activeOk) active.size.toString() else "-"}" +
                            " • مودمات $mUp/${mods.size}"
                )
            } catch (e: Exception) {
                ros?.close(); ros = null
                Shared.error = e.message ?: "خطأ غير معروف"
                updateNotif("⚠️ تعذر الاتصال بالراوتر — جارٍ إعادة المحاولة")
            }
            nap(2000)
        }
        ros?.close()
    }

    // ---------- سجل الراوتر: بث لحظي + إشعار للأحمر ----------
    private fun logNotify(list: List<LogEntry>) {
        if (list.isEmpty()) return
        val reds = list.count { it.level == 2 }
        val title = when {
            list.size == 1 && reds == 1 -> "🔴 خطأ في سجل الراوتر"
            list.size == 1 -> "🟡 تحذير في سجل الراوتر"
            reds > 0 -> "🔴 ${list.size} رسائل جديدة في السجل ($reds أخطاء)"
            else -> "🟡 ${list.size} تحذيرات جديدة في السجل"
        }
        val text = list.takeLast(6).joinToString("\n") { "${it.time}  ${it.msg}" }
        val open = PendingIntent.getActivity(
            this, 5, Intent(this, MainActivity::class.java).putExtra("open_log", true),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val n = builder(CH_ALERT)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(title)
            .setContentText(list.last().msg)
            .setSubText(netName(prefs))
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).notify(NOTIF_LOG, n)
    }

    private fun addLogs(items: List<LogEntry>, notify: Boolean, pending: MutableList<LogEntry>) {
        if (items.isEmpty()) return
        val known = Shared.logs
        val maxId = known.lastOrNull()?.id ?: -1L
        val fresh = items.filter { it.id > maxId }
        if (fresh.isEmpty()) return
        val merged = known + fresh
        Shared.logs = if (merged.size > LOG_MAX) merged.subList(merged.size - LOG_MAX, merged.size).toList() else merged
        Shared.logVer++
        if (!notify) return
        val wantErr = prefs.getBoolean("notif_err", true)
        val wantWarn = prefs.getBoolean("notif_warn", false)
        for (e in fresh) {
            if (e.level == 2) Shared.logUnread++
            if ((e.level == 2 && wantErr) || (e.level == 1 && wantWarn)) pending.add(e)
        }
    }

    private fun logLoop() {
        var myGen = -1
        while (running) {
            if (myGen != Shared.cfgGen) {
                myGen = Shared.cfgGen
                Shared.logs = emptyList(); Shared.logsReady = false; Shared.logUnread = 0; Shared.logVer++
            }
            if (!prefs.contains("user")) { nap(2000); continue }
            var r: Ros? = null
            var wait = 5000L
            val pending = ArrayList<LogEntry>()
            var lastFlush = 0L
            fun flush(force: Boolean) {
                val now = System.currentTimeMillis()
                // تجميع: إشعار واحد كل 5 ثواني على الأكثر
                if (pending.isNotEmpty() && (force || now - lastFlush > 5000)) {
                    logNotify(pending.toList()); pending.clear(); lastFlush = now
                }
            }
            try {
                r = rosConnect(prefs)
                // أول مرة: نحمل السجل بدون إشعارات. عند إعادة الاتصال: نُشعر بما فاتنا فقط
                val firstTime = !Shared.logsReady
                val init = r.cmd("/log/print", "=.proplist=.id,time,topics,message").mapNotNull { toLogEntry(it) }
                val known = Shared.logs.lastOrNull()?.id ?: -1L
                if (!firstTime && init.isNotEmpty() && init.last().id < known) {
                    // الراوتر أعاد التشغيل: نبدأ السجل من جديد
                    Shared.logs = emptyList()
                    addLogs(init, false, pending)
                } else addLogs(init, !firstTime, pending)
                Shared.logsReady = true; Shared.logError = null; Shared.logVer++
                flush(true)

                r.setTimeout(3000)
                var idleMs = 0L
                val gen = myGen
                r.streamImpl(
                    arrayOf("/log/print", "=follow-only=", "=.proplist=.id,time,topics,message"),
                    stop = { !running || gen != Shared.cfgGen || idleMs > 300000 },
                    onIdle = { idleMs += 3000; flush(false) },
                    onRe = { m -> idleMs = 0; toLogEntry(m)?.let { addLogs(listOf(it), true, pending) }; flush(false) }
                )
            } catch (e: Trap) {
                Shared.logError = e.message; Shared.logVer++
                r?.close(); nap(15000); continue
            } catch (e: Exception) {
                wait = if (e.message == "stop") 200L else 5000L
            } finally {
                flush(true)
                r?.close()
            }
            nap(wait)
        }
    }

    // ---------- حلقة المودمات: فحص متوازي بعدة اتصالات (كل ~3 ثواني) ----------
    private fun modemLoop() {
        val conns = arrayOfNulls<Ros>(5)
        var myGen = Shared.cfgGen
        var lastDown = HashSet<String>()
        var firstDone = false

        while (running) {
            if (myGen != Shared.cfgGen) {
                for (i in conns.indices) { conns[i]?.close(); conns[i] = null }
                myGen = Shared.cfgGen
            }
            Shared.forceModem = false

            val raw = prefs.getString("modems", null)
            val list = parseModems(if (raw != null && raw.isNotBlank()) raw else DEFAULT_MODEMS)
            if (list.isEmpty()) {
                Shared.modems = emptyList()
                Shared.modemsReady = true
                nap(3000, true)
                continue
            }

            val prev = Shared.modems.associateBy { it.ip }
            val workers = if (list.size < conns.size) list.size else conns.size
            val results = arrayOfNulls<ModemStat>(list.size)
            val threads = ArrayList<Thread>()

            for (w in 0 until workers) {
                threads.add(Thread {
                    var i = w
                    while (i < list.size) {
                        val name = list[i].first
                        val mIp = list[i].second
                        val up: Boolean? = try {
                            val c = conns[w] ?: rosConnect(prefs).also { conns[w] = it }
                            c.cmd("/ping", "=address=$mIp", "=count=2", "=interval=0.5")
                                .any { (it["received"] ?: "0") != "0" || it["time"] != null }
                        } catch (e: Trap) {
                            false
                        } catch (e: Exception) {
                            conns[w]?.close(); conns[w] = null
                            null
                        }
                        val old = prev[mIp]
                        results[i] = if (up == null) {
                            ModemStat(name, mIp, old?.up ?: false, old?.downSince)
                        } else if (up) {
                            downSince.remove(mIp)
                            ModemStat(name, mIp, true, null)
                        } else {
                            val d = downSince.getOrPut(mIp) { System.currentTimeMillis() }
                            ModemStat(name, mIp, false, d)
                        }
                        i += workers
                    }
                })
            }
            for (t in threads) t.start()
            for (t in threads) { try { t.join() } catch (e: InterruptedException) { } }

            val stats = results.filterNotNull()
            Shared.modems = stats
            Shared.modemsReady = true

            val nowDown = HashSet<String>()
            for (m in stats) if (!m.up) nowDown.add(m.name)
            if (firstDone) {
                val newly = nowDown.filter { it !in lastDown }
                val back = lastDown.filter { it !in nowDown }
                if (newly.isNotEmpty()) alert("🔴 مودم مقطوع", newly.joinToString("، "))
                if (back.isNotEmpty()) alert("🟢 عاد الاتصال", back.joinToString("، "))
            }
            lastDown = nowDown
            firstDone = true

            nap(3000, true)
        }
        for (i in conns.indices) { conns[i]?.close() }
    }
}

// ======================= الواجهة =======================
class MainActivity : Activity() {
    private val prefs by lazy { getSharedPreferences("cfg", MODE_PRIVATE) }
    private val ui = Handler(Looper.getMainLooper())

    private lateinit var banner: TextView
    private lateinit var tvWanVal: TextView
    private lateinit var tvWanSub: TextView
    private lateinit var tvHostVal: TextView
    private lateinit var tvHostSub: TextView
    private lateinit var tvActiveVal: TextView
    private lateinit var tvModemVal: TextView
    private lateinit var tvTitle: TextView

    // بطاقة ونافذة سجل الراوتر
    private lateinit var logCard: LinearLayout
    private lateinit var tvLogVal: TextView
    private lateinit var tvLogSub: TextView
    private var logDialog: android.app.Dialog? = null
    private var logContainer: LinearLayout? = null
    private var logTitle: TextView? = null
    private var logFilter = 0          // 0 الكل ، 2 أخطاء ، 1 تحذيرات
    private var logQuery = ""
    private var lastLogVer = -1
    private val logChips = ArrayList<TextView>()

    private lateinit var tvViaBadge: TextView
    private lateinit var tvUptimeBadge: TextView
    private lateinit var tvTempBadge: TextView
    private lateinit var tvVoltBadge: TextView

    private lateinit var pbCpu: ProgressBar
    private lateinit var tvCpuVal: TextView
    private lateinit var pbRam: ProgressBar
    private lateinit var tvRamVal: TextView
    private lateinit var pbHdd: ProgressBar
    private lateinit var tvHddVal: TextView

    private lateinit var modemsContainer: LinearLayout
    // نافذة قائمة HOST / ACTIVE (تفتح عند الضغط على البطاقة)
    private var listDialog: android.app.Dialog? = null
    private var listIsHost = true
    private var listTitle: TextView? = null
    private var listContainer: LinearLayout? = null
    private var listQuery = ""
    private lateinit var tvIfTotal: TextView
    private lateinit var ifContainer: LinearLayout
    private lateinit var btnFilterIf: TextView

    private var showOnlyActiveIf = false
    private var lastIfList: List<IfStat> = emptyList()
    private var lastSnap: Snapshot? = null
    private var lastModems: List<ModemStat>? = null
    private var lastReady = false

    private val tick = object : Runnable {
        override fun run() {
            refreshUi()
            ui.postDelayed(this, 1000)
        }
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()
    private fun c(s: String) = Color.parseColor(s)

    private fun box(fill: String, stroke: String, radiusDp: Int = 12) = GradientDrawable().apply {
        setColor(c(fill))
        cornerRadius = dp(radiusDp).toFloat()
        if (stroke.isNotEmpty()) setStroke(dp(1), c(stroke))
    }

    private fun makeProgressDrawable(colorHex: String): LayerDrawable {
        val bg = GradientDrawable().apply { setColor(c("#21262d")); cornerRadius = dp(6).toFloat() }
        val fg = GradientDrawable().apply { setColor(c(colorHex)); cornerRadius = dp(6).toFloat() }
        val clip = ClipDrawable(fg, Gravity.RIGHT, ClipDrawable.HORIZONTAL)
        return LayerDrawable(arrayOf(bg, clip)).apply {
            setId(0, android.R.id.background)
            setId(1, android.R.id.progress)
        }
    }

    private fun makeBadge(textStr: String, colorHex: String): TextView {
        return TextView(this).apply {
            text = textStr
            setTextColor(c(colorHex))
            textSize = 12f
            setPadding(dp(10), dp(5), dp(10), dp(5))
            background = box("#21262d", "#30363d", 8)
        }
    }

    private fun makeSection(title: String): Triple<LinearLayout, TextView, LinearLayout> {
        val sec = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), dp(12), dp(14), dp(12))
            background = box("#161b22", "#30363d")
        }
        val t = TextView(this).apply {
            text = title
            setTextColor(c("#8b949e"))
            textSize = 13f
            setTypeface(null, Typeface.BOLD)
        }
        val cont = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dp(8), 0, 0)
        }
        sec.addView(t)
        sec.addView(cont)
        return Triple(sec, t, cont)
    }

    private fun startMonitor() = startMonitorService(this)

    // يطلب استثناء التطبيق من توفير البطارية حتى لا يوقفه النظام
    @SuppressLint("BatteryLife")
    private fun askBatteryExemption(force: Boolean) {
        if (Build.VERSION.SDK_INT < 23) return
        try {
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            if (pm.isIgnoringBatteryOptimizations(packageName)) {
                if (force) Toast.makeText(this, "✅ التطبيق مستثنى من توفير البطارية", Toast.LENGTH_SHORT).show()
                return
            }
            startActivity(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:$packageName")))
        } catch (e: Exception) {
            try { startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)) } catch (e2: Exception) { }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = c("#0d1117")

        if (Build.VERSION.SDK_INT >= 33) {
            try { requestPermissions(arrayOf("android.permission.POST_NOTIFICATIONS"), 1) } catch (e: Exception) { }
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(12), dp(12), dp(12), dp(28))
            layoutDirection = View.LAYOUT_DIRECTION_RTL
        }
        setContentView(ScrollView(this).apply { setBackgroundColor(c("#0d1117")); addView(root) })

        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        tvTitle = TextView(this)
        header.addView(tvTitle.apply {
            text = "📡 ${netName(prefs)}"
            setTextColor(c("#58a6ff"))
            textSize = 19f
            setTypeface(null, Typeface.BOLD)
            layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
        })

        fun actionBtn(label: String, onClick: () -> Unit) = TextView(this).apply {
            text = label
            textSize = 14f
            setTextColor(c("#e6edf3"))
            setPadding(dp(10), dp(6), dp(10), dp(6))
            background = box("#21262d", "#30363d", 8)
            setOnClickListener { onClick() }
            layoutParams = LinearLayout.LayoutParams(-2, -2).apply { rightMargin = dp(6) }
        }

        header.addView(actionBtn("🔄") {
            Toast.makeText(this, "جارٍ التحديث الفوري...", Toast.LENGTH_SHORT).show()
            Shared.forceModem = true
            startMonitor()
        })
        header.addView(actionBtn("🔋") { askBatteryExemption(true) })
        header.addView(actionBtn("⚙️") { settings() })
        root.addView(header)

        banner = TextView(this).apply {
            textSize = 15f
            setTypeface(null, Typeface.BOLD)
            gravity = Gravity.CENTER
            setPadding(dp(12), dp(12), dp(12), dp(12))
            text = "جارٍ الاتصال بالراوتر..."
            setTextColor(c("#8b949e"))
            background = box("#161b22", "#30363d")
        }
        root.addView(banner, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(12) })

        val gridRow1 = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val gridRow2 = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }

        fun makeStatCard(title: String, accentColor: String, hint: String, onClick: (() -> Unit)?): Triple<LinearLayout, TextView, TextView> {
            val cardLayout = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(12), dp(10), dp(12), dp(10))
                background = box("#161b22", "#30363d")
                if (onClick != null) {
                    isClickable = true
                    setOnClickListener { onClick() }
                }
            }
            cardLayout.addView(TextView(this).apply { text = title; setTextColor(c("#8b949e")); textSize = 12f })
            val mainVal = TextView(this).apply {
                text = "-"
                setTextColor(c(accentColor))
                textSize = 20f
                setTypeface(null, Typeface.BOLD)
                setPadding(0, dp(4), 0, dp(2))
            }
            val subVal = TextView(this).apply { text = hint; setTextColor(c("#6e7681")); textSize = 11f }
            cardLayout.addView(mainVal)
            cardLayout.addView(subVal)
            return Triple(cardLayout, mainVal, subVal)
        }

        val wanTriple = makeStatCard("🌐 حالة الإنترنت (WAN)", "#58a6ff", "اضغط لفحص البنق") { pingDialog("8.8.8.8", "فحص الإنترنت العالمي (Google DNS)") }
        tvWanVal = wanTriple.second; tvWanSub = wanTriple.third

        val hostTriple = makeStatCard("👥 HOST", "#3fb950", "اضغط لعرض القائمة") { openList(true) }
        tvHostVal = hostTriple.second; tvHostSub = hostTriple.third

        val activeTriple = makeStatCard("🔌 ACTIVE", "#a371f7", "اضغط لعرض القائمة") { openList(false) }
        tvActiveVal = activeTriple.second

        val modTriple = makeStatCard("📡 المودمات المتصلة", "#e3b341", "اضغط لإعادة الفحص") {
            Toast.makeText(this, "جارٍ فحص جميع المودمات الآن...", Toast.LENGTH_SHORT).show()
            Shared.forceModem = true
            startMonitor()
        }
        tvModemVal = modTriple.second

        gridRow1.addView(wanTriple.first, LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = dp(6) })
        gridRow1.addView(hostTriple.first, LinearLayout.LayoutParams(0, -2, 1f).apply { rightMargin = dp(6) })
        gridRow2.addView(activeTriple.first, LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = dp(6) })
        gridRow2.addView(modTriple.first, LinearLayout.LayoutParams(0, -2, 1f).apply { rightMargin = dp(6) })

        root.addView(gridRow1, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(12) })
        root.addView(gridRow2, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) })

        logCard = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(14), dp(12), dp(14), dp(12))
            background = box("#161b22", "#30363d")
            isClickable = true
            setOnClickListener { openLog() }
        }
        val logTexts = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; layoutParams = LinearLayout.LayoutParams(0, -2, 1f) }
        logTexts.addView(TextView(this).apply { text = "📜 سجل الراوتر (LOG)"; setTextColor(c("#8b949e")); textSize = 12f })
        tvLogSub = TextView(this).apply { text = "جارٍ تحميل السجل..."; setTextColor(c("#e6edf3")); textSize = 13f; maxLines = 2; setPadding(0, dp(4), 0, 0) }
        logTexts.addView(tvLogSub)
        logCard.addView(logTexts)
        tvLogVal = TextView(this).apply {
            text = "عرض ›"; textSize = 14f; setTypeface(null, Typeface.BOLD); setTextColor(c("#58a6ff"))
            setPadding(dp(10), dp(6), dp(10), dp(6)); background = box("#21262d", "#30363d", 8)
        }
        logCard.addView(tvLogVal)
        root.addView(logCard, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) })

        val routerCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), dp(12), dp(14), dp(14))
            background = box("#161b22", "#30363d")
        }
        val routerHeader = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        routerHeader.addView(TextView(this).apply {
            text = "🖥️ موارد الميكروتيك الرئيسي"
            setTextColor(c("#8b949e"))
            textSize = 13f
            setTypeface(null, Typeface.BOLD)
            layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
        })
        routerHeader.addView(TextView(this).apply {
            text = "⚡ إعادة تشغيل"
            setTextColor(c("#f85149"))
            textSize = 11f
            setPadding(dp(8), dp(4), dp(8), dp(4))
            background = box("#21262d", "#f85149", 6)
            setOnClickListener { confirmRebootRouter() }
        })
        routerCard.addView(routerHeader)

        val badgesRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, dp(10), 0, dp(6))
        }
        tvViaBadge = makeBadge("الاتصال: -", "#58a6ff")
        tvUptimeBadge = makeBadge("⏱ -", "#e6edf3")
        tvTempBadge = makeBadge("🌡 -°C", "#3fb950")
        tvVoltBadge = makeBadge("⚡ -V", "#e3b341")

        listOf(tvViaBadge, tvUptimeBadge, tvTempBadge, tvVoltBadge).forEach { b ->
            badgesRow.addView(b, LinearLayout.LayoutParams(-2, -2).apply { leftMargin = dp(6) })
        }
        routerCard.addView(HorizontalScrollView(this).apply { isHorizontalScrollBarEnabled = false; addView(badgesRow) })

        fun makeResourceBar(label: String): Pair<ProgressBar, TextView> {
            val wrap = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(0, dp(8), 0, 0) }
            val top = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
            top.addView(TextView(this).apply { text = label; setTextColor(c("#c9d1d9")); textSize = 13f; layoutParams = LinearLayout.LayoutParams(0, -2, 1f) })
            val valTxt = TextView(this).apply { text = "-"; setTextColor(c("#e6edf3")); textSize = 13f; setTypeface(null, Typeface.BOLD) }
            top.addView(valTxt)
            val pb = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
                max = 100
                progress = 0
                progressDrawable = makeProgressDrawable("#3fb950")
                layoutParams = LinearLayout.LayoutParams(-1, dp(8)).apply { topMargin = dp(5) }
            }
            wrap.addView(top)
            wrap.addView(pb)
            routerCard.addView(wrap)
            return Pair(pb, valTxt)
        }

        val cpuPair = makeResourceBar("المعالج (CPU Load)")
        pbCpu = cpuPair.first; tvCpuVal = cpuPair.second
        val ramPair = makeResourceBar("الذاكرة العشوائية (RAM)")
        pbRam = ramPair.first; tvRamVal = ramPair.second
        val hddPair = makeResourceBar("مساحة التخزين (Storage)")
        pbHdd = hddPair.first; tvHddVal = hddPair.second

        root.addView(routerCard, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(12) })

        val modSec = makeSection("🛰️ حالة المودمات والأكسسات (اضغط لفحص البنق)")
        modemsContainer = modSec.third
        note(modemsContainer, "جارٍ فحص المودمات...")
        root.addView(modSec.first, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(12) })

        val ifSection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), dp(12), dp(14), dp(12))
            background = box("#161b22", "#30363d")
        }
        val ifHeader = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        ifHeader.addView(TextView(this).apply {
            text = "⚡ الواجهات والسرعة اللحظية (اضغط للتحكم)"
            setTextColor(c("#8b949e"))
            textSize = 13f
            setTypeface(null, Typeface.BOLD)
            layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
        })
        btnFilterIf = TextView(this).apply {
            text = "الكل"
            setTextColor(c("#58a6ff"))
            textSize = 12f
            setPadding(dp(10), dp(4), dp(10), dp(4))
            background = box("#21262d", "#30363d", 6)
            setOnClickListener {
                showOnlyActiveIf = !showOnlyActiveIf
                text = if (showOnlyActiveIf) "النشط فقط ✓" else "الكل"
                renderInterfaces(lastIfList)
            }
        }
        ifHeader.addView(btnFilterIf)
        ifSection.addView(ifHeader)

        // مجموع الاستهلاك فوق قائمة الواجهات
        tvIfTotal = TextView(this).apply {
            text = "📊 مجموع الاستهلاك: -"
            setTextColor(c("#e6edf3"))
            textSize = 14f
            setTypeface(null, Typeface.BOLD)
            setPadding(dp(12), dp(10), dp(12), dp(10))
            background = box("#0d1117", "#58a6ff", 8)
        }
        ifSection.addView(tvIfTotal, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) })

        ifContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dp(8), 0, 0)
        }
        ifSection.addView(ifContainer)
        root.addView(ifSection, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(12) })

        if (!prefs.contains("user")) settings() else askBatteryExemption(false)
        if (intent?.getBooleanExtra("open_log", false) == true) ui.post { openLog() }
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        if (intent?.getBooleanExtra("open_log", false) == true) openLog()
    }

    override fun onResume() {
        super.onResume()
        if (prefs.contains("user")) startMonitor()
        lastSnap = null
        lastModems = null
        ui.removeCallbacks(tick)
        ui.post(tick)
    }

    override fun onPause() {
        super.onPause()
        ui.removeCallbacks(tick)
        // الخدمة تستمر بالعمل بالخلفية
    }

    // ---------- تحديث الواجهة من البيانات المشتركة ----------
    private fun refreshUi() {
        val s = Shared.snap
        val mods = Shared.modems
        val ready = Shared.modemsReady

        if (s !== lastSnap) {
            lastSnap = s
            if (s != null) renderSnap(s)
        }
        if (mods !== lastModems || ready != lastReady) {
            lastModems = mods
            lastReady = ready
            renderModems(mods)
        }
        tvModemVal.text = if (ready) "${mods.count { it.up }} / ${mods.size}" else "-"
        tvViaBadge.text = "🔗 ${if (Shared.via.isEmpty()) "-" else Shared.via}"
        updateBanner(s, Shared.error, mods)
        if (Shared.logVer != lastLogVer) {
            lastLogVer = Shared.logVer
            renderLogCard()
            if (logDialog != null) { Shared.logUnread = 0; renderLogList() }
        }
    }

    private fun updateBanner(s: Snapshot?, err: String?, mods: List<ModemStat>) {
        val dn = mods.filter { !it.up }
        val r = when {
            err != null -> "⚠️ تعذر الاتصال بالراوتر: $err" to "#f85149"
            s == null -> "جارٍ الاتصال بالراوتر..." to "#8b949e"
            !s.wanUp -> "🔴 انقطاع الإنترنت (الواجهة ${s.wan})" to "#f85149"
            dn.isNotEmpty() -> "⚠️ مودمات مقطوعة (${dn.joinToString("، ") { it.name }})" to "#e3b341"
            else -> "🟢 كل الأنظمة والخطوط تعمل بشكل طبيعي" to "#3fb950"
        }
        if (banner.text.toString() != r.first) setBanner(r.first, r.second)
    }

    private fun setBanner(t: String, col: String) {
        banner.text = t
        banner.setTextColor(c(col))
        banner.background = GradientDrawable().apply {
            setColor((c(col) and 0xFFFFFF) or 0x22000000)
            cornerRadius = dp(12).toFloat()
            setStroke(dp(1), c(col))
        }
    }

    private fun renderSnap(s: Snapshot) {
        tvWanVal.text = if (s.wanUp) "متصل ✓" else "مقطوع ✗"
        tvWanVal.setTextColor(c(if (s.wanUp) "#3fb950" else "#f85149"))
        tvWanSub.text = "IP: ${s.ip}"

        val authCount = s.hosts.count { it["authorized"] == "true" }
        tvHostVal.text = if (s.hostOk) s.hosts.size.toString() else "-"
        tvHostSub.text = if (s.hostOk) "منهم مسجلين: $authCount" else "الهوتسبوت غير مفعل"
        tvActiveVal.text = if (s.activeOk) s.active.size.toString() else "-"

        tvUptimeBadge.text = "⏱ ${s.uptime}"
        tvTempBadge.text = "🌡 ${s.temp}°C"
        tvVoltBadge.text = "⚡ ${s.volt}V"

        tvCpuVal.text = "${s.cpu}%"
        updateBar(pbCpu, s.cpu)
        tvRamVal.text = "${s.usedMem} / ${s.totalMem} MB (${s.ramPct}%)"
        updateBar(pbRam, s.ramPct)
        tvHddVal.text = "${s.usedHdd} / ${s.totalHdd} MB (${s.hddPct}%)"
        updateBar(pbHdd, s.hddPct)

        refreshListDialog(s)

        lastIfList = s.ifs
        renderInterfaces(s.ifs)
    }

    private fun updateBar(pb: ProgressBar, percent: Int) {
        val p = if (percent < 0) 0 else if (percent > 100) 100 else percent
        val col = when {
            p >= 85 -> "#f85149"
            p >= 65 -> "#e3b341"
            else -> "#3fb950"
        }
        pb.progressDrawable = makeProgressDrawable(col)
        pb.progress = p
    }

    private fun note(container: LinearLayout, msg: String) {
        container.addView(TextView(this).apply {
            text = msg
            setTextColor(c("#8b949e"))
            setPadding(0, dp(6), 0, dp(6))
        })
    }

    // ---------- نافذة قائمة HOST / ACTIVE ----------
    private fun openList(isHost: Boolean) {
        listIsHost = isHost
        listQuery = ""
        val d = android.app.Dialog(this, android.R.style.Theme_DeviceDefault_NoActionBar)
        val wrap = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(12), dp(12), dp(12), dp(12))
            setBackgroundColor(c("#0d1117"))
            layoutDirection = View.LAYOUT_DIRECTION_RTL
        }
        val head = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        val title = TextView(this).apply {
            setTextColor(c(if (isHost) "#3fb950" else "#a371f7"))
            textSize = 18f
            setTypeface(null, Typeface.BOLD)
            layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
        }
        head.addView(title)
        head.addView(TextView(this).apply {
            text = "✖ إغلاق"
            setTextColor(c("#e6edf3"))
            textSize = 13f
            setPadding(dp(10), dp(6), dp(10), dp(6))
            background = box("#21262d", "#30363d", 8)
            setOnClickListener { d.dismiss() }
        })
        wrap.addView(head)

        val search = EditText(this).apply {
            hint = if (isHost) "🔍 بحث بالماك أو IP" else "🔍 بحث باسم المستخدم أو IP"
            setHintTextColor(c("#6e7681"))
            setTextColor(c("#e6edf3"))
            isSingleLine = true
            textSize = 14f
            setPadding(dp(12), dp(8), dp(12), dp(8))
            background = box("#161b22", "#30363d", 8)
            addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, cnt: Int) {}
                override fun onTextChanged(s: CharSequence?, a: Int, b: Int, cnt: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    listQuery = s?.toString()?.trim() ?: ""
                    Shared.snap?.let { refreshListDialog(it) }
                }
            })
        }
        wrap.addView(search, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) })

        val cont = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(0, dp(10), 0, dp(20)) }
        wrap.addView(ScrollView(this).apply { addView(cont) }, LinearLayout.LayoutParams(-1, 0, 1f))

        d.setContentView(wrap)
        d.setOnDismissListener { listDialog = null; listTitle = null; listContainer = null }
        listDialog = d; listTitle = title; listContainer = cont
        d.show()
        val s = Shared.snap
        if (s != null) refreshListDialog(s) else { title.text = if (isHost) "👥 HOST" else "🔌 ACTIVE"; note(cont, "جارٍ التحميل...") }
    }

    private fun refreshListDialog(s: Snapshot) {
        val cont = listContainer ?: return
        val title = listTitle ?: return
        val isHost = listIsHost
        val ok = if (isHost) s.hostOk else s.activeOk
        val list = if (isHost) s.hosts else s.active
        val totalBytes = list.sumOf { (it["bytes-out"]?.toLongOrNull() ?: 0L) + (it["bytes-in"]?.toLongOrNull() ?: 0L) }
        title.text = (if (isHost) "👥 HOST" else "🔌 ACTIVE") +
                " (${if (ok) list.size.toString() else "-"}) • ${gb(totalBytes)}"
        renderUsers(cont, ok, list, isHost)
    }

    // isHost = true  -> قائمة HOST   (/ip/hotspot/host)
    // isHost = false -> قائمة ACTIVE (/ip/hotspot/active)
    // مرتبة من الأكثر استهلاكاً للأقل، مع التنزيل والرفع لكل واحد
    private fun renderUsers(container: LinearLayout, ok: Boolean, list: List<Map<String, String>>, isHost: Boolean) {
        container.removeAllViews()
        if (!ok) { note(container, "الهوتسبوت غير متوفر على الراوتر أو لا توجد صلاحية"); return }
        val q = listQuery.lowercase()
        val filtered = list.filter { u ->
            q.isEmpty() || listOf("user", "mac-address", "address", "comment").any { (u[it] ?: "").lowercase().contains(q) }
        }.sortedByDescending { (it["bytes-out"]?.toLongOrNull() ?: 0L) + (it["bytes-in"]?.toLongOrNull() ?: 0L) }

        if (filtered.isEmpty()) {
            note(container, if (q.isNotEmpty()) "لا توجد نتائج" else if (isHost) "لا توجد أجهزة في HOST حالياً" else "لا يوجد مستخدمون في ACTIVE حالياً")
            return
        }
        val path = if (isHost) "/ip/hotspot/host/remove" else "/ip/hotspot/active/remove"
        val maxShow = 300
        var shown = 0
        for (u in filtered) {
            if (shown >= maxShow) break
            val id = u[".id"] ?: continue
            val ip = u["address"] ?: "-"
            val up = u["uptime"] ?: "-"
            val dl = u["bytes-out"]?.toLongOrNull() ?: 0L   // من الراوتر للمستخدم = تنزيل
            val ul = u["bytes-in"]?.toLongOrNull() ?: 0L    // من المستخدم للراوتر = رفع
            val nm: String
            val st: String
            if (isHost) {
                val cm = u["comment"]
                nm = if (!cm.isNullOrBlank()) cm else (u["mac-address"] ?: "جهاز")
                st = when {
                    u["authorized"] == "true" -> " | ✅ مسجل"
                    u["bypassed"] == "true" -> " | ⏩ متجاوز"
                    else -> " | ⏳ غير مسجل"
                }
            } else {
                nm = u["user"] ?: "غير معروف"
                st = ""
            }

            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(dp(10), dp(8), dp(10), dp(8))
                background = box("#161b22", "#21262d", 8)
                isClickable = true
                setOnClickListener { confirmKick(path, id, nm) }
                layoutParams = LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(6) }
            }
            val info = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
            }
            info.addView(TextView(this).apply {
                text = "${if (isHost) "💻" else "👤"} $nm"
                setTextColor(c("#e6edf3"))
                textSize = 14f
                setTypeface(null, Typeface.BOLD)
            })
            info.addView(TextView(this).apply {
                text = "IP: $ip | ⏱ $up$st"
                setTextColor(c("#8b949e"))
                textSize = 12f
            })
            info.addView(TextView(this).apply {
                @Suppress("DEPRECATION")
                text = Html.fromHtml("<font color='#3fb950'>⬇ ${gb(dl)}</font> &nbsp; <font color='#58a6ff'>⬆ ${gb(ul)}</font> &nbsp; <font color='#e3b341'>Σ ${gb(dl + ul)}</font>")
                textSize = 13f
            })
            row.addView(info)
            row.addView(TextView(this).apply {
                text = if (isHost) "حذف ❌" else "طرد ❌"
                setTextColor(c("#f85149"))
                textSize = 12f
                setPadding(dp(8), dp(4), dp(8), dp(4))
                background = box("#21262d", "#f85149", 6)
            })
            container.addView(row)
            shown++
        }
        if (filtered.size > shown) note(container, "... و ${filtered.size - shown} آخرين (استخدم البحث)")
    }

    private fun renderInterfaces(list: List<IfStat>) {
        ifContainer.removeAllViews()

        // مجموع استهلاك كل الواجهات بالجيجا
        val sumRx = list.sumOf { it.totalRx }
        val sumTx = list.sumOf { it.totalTx }
        val wanIf = list.firstOrNull { it.name == (lastSnap?.wan ?: "ether1") }
        @Suppress("DEPRECATION")
        tvIfTotal.text = Html.fromHtml(
            "📊 مجموع الاستهلاك: <font color='#e3b341'>${gbx(sumRx + sumTx)}</font><br>" +
            "<small><font color='#3fb950'>⬇ ${gbx(sumRx)}</font> &nbsp; <font color='#58a6ff'>⬆ ${gbx(sumTx)}</font>" +
            (if (wanIf != null) " &nbsp;|&nbsp; 🌐 الإنترنت (${wanIf.name}): ${gbx(wanIf.totalRx + wanIf.totalTx)}" else "") +
            "</small>"
        )

        val filtered = if (showOnlyActiveIf) list.filter { it.running } else list
        if (filtered.isEmpty()) {
            note(ifContainer, "لا توجد منافذ نشطة مطابقة للفلتر.")
            return
        }
        var maxRate = 10000000L
        for (f in filtered) {
            val m = if (f.rxRate > f.txRate) f.rxRate else f.txRate
            if (m > maxRate) maxRate = m
        }

        for (item in filtered) {
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(10), dp(8), dp(10), dp(8))
                background = box("#0d1117", "#21262d", 8)
                isClickable = true
                setOnClickListener { showInterfaceDialog(item) }
                layoutParams = LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(6) }
            }
            val top = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
            val statusDot = if (item.disabled) "⚪" else if (item.running) "🟢" else "🔴"
            top.addView(TextView(this).apply {
                text = "$statusDot ${item.name}"
                setTextColor(c(if (item.running) "#e6edf3" else "#8b949e"))
                textSize = 14f
                setTypeface(null, Typeface.BOLD)
                layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
            })
            top.addView(TextView(this).apply {
                @Suppress("DEPRECATION")
                text = Html.fromHtml("<font color='#3fb950'>↓ ${bw(item.rxRate)}</font> &nbsp;&nbsp; <font color='#58a6ff'>↑ ${bw(item.txRate)}</font>")
                textSize = 13f
            })
            row.addView(top)

            // استهلاك هذه الواجهة منذ آخر تشغيل للراوتر
            row.addView(TextView(this).apply {
                @Suppress("DEPRECATION")
                text = Html.fromHtml("📊 الاستهلاك: <font color='#3fb950'>⬇ ${gbx(item.totalRx)}</font> &nbsp; <font color='#58a6ff'>⬆ ${gbx(item.totalTx)}</font> &nbsp; <font color='#e3b341'>Σ ${gbx(item.totalRx + item.totalTx)}</font>")
                setTextColor(c("#8b949e"))
                textSize = 12f
                setPadding(0, dp(4), 0, 0)
            })

            if (item.running && (item.rxRate > 0 || item.txRate > 0)) {
                val curMax = if (item.rxRate > item.txRate) item.rxRate else item.txRate
                val rawP = ((curMax.toDouble() / maxRate.toDouble()) * 100.0).toInt()
                val barPercent = if (rawP < 4) 4 else if (rawP > 100) 100 else rawP
                val miniBar = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
                    max = 100
                    progress = barPercent
                    progressDrawable = makeProgressDrawable("#238636")
                    layoutParams = LinearLayout.LayoutParams(-1, dp(4)).apply { topMargin = dp(6) }
                }
                row.addView(miniBar)
            }
            ifContainer.addView(row)
        }
    }

    // ---------- سجل الراوتر ----------
    private fun logColor(lvl: Int) = when (lvl) { 2 -> "#f85149"; 1 -> "#e3b341"; else -> "#c9d1d9" }

    private fun renderLogCard() {
        val logs = Shared.logs
        val unread = Shared.logUnread
        val lastRed = logs.lastOrNull { it.level == 2 }
        when {
            Shared.logError != null -> {
                tvLogSub.text = "⚠️ لا يمكن قراءة السجل: ${Shared.logError}\n(أعطِ مستخدم API صلاحية read)"
                tvLogSub.setTextColor(c("#e3b341"))
            }
            !Shared.logsReady -> { tvLogSub.text = "جارٍ تحميل السجل..."; tvLogSub.setTextColor(c("#8b949e")) }
            unread > 0 && lastRed != null -> {
                tvLogSub.text = "🔴 $unread أخطاء جديدة • ${lastRed.time}  ${lastRed.msg}"
                tvLogSub.setTextColor(c("#f85149"))
            }
            else -> {
                tvLogSub.text = "✅ لا توجد أخطاء جديدة • ${logs.size} سطر — اضغط لعرض السجل كاملاً"
                tvLogSub.setTextColor(c("#e6edf3"))
            }
        }
        tvLogVal.text = if (unread > 0) "🔴 $unread" else "عرض ›"
        tvLogVal.setTextColor(c(if (unread > 0) "#f85149" else "#58a6ff"))
        logCard.background = box("#161b22", if (unread > 0) "#f85149" else "#30363d")
    }

    private fun openLog() {
        logDialog?.dismiss()
        logFilter = 0; logQuery = ""
        Shared.logUnread = 0
        (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).cancel(NOTIF_LOG)
        val d = android.app.Dialog(this, android.R.style.Theme_DeviceDefault_NoActionBar)
        val wrap = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(12), dp(12), dp(12), dp(12))
            setBackgroundColor(c("#0d1117"))
            layoutDirection = View.LAYOUT_DIRECTION_RTL
        }
        val head = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        val title = TextView(this).apply {
            text = "📜 سجل الراوتر"; setTextColor(c("#58a6ff")); textSize = 18f; setTypeface(null, Typeface.BOLD)
            layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
        }
        head.addView(title)
        head.addView(TextView(this).apply {
            text = "✖ إغلاق"; setTextColor(c("#e6edf3")); textSize = 13f
            setPadding(dp(10), dp(6), dp(10), dp(6)); background = box("#21262d", "#30363d", 8)
            setOnClickListener { d.dismiss() }
        })
        wrap.addView(head)

        val chips = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        logChips.clear()
        for ((lvl, label) in listOf(0 to "الكل", 2 to "🔴 أخطاء", 1 to "🟡 تحذيرات")) {
            val chip = TextView(this).apply {
                text = label; textSize = 13f; setPadding(dp(12), dp(6), dp(12), dp(6)); tag = lvl
                setOnClickListener { logFilter = lvl; renderLogList() }
            }
            logChips.add(chip)
            chips.addView(chip, LinearLayout.LayoutParams(-2, -2).apply { leftMargin = dp(6) })
        }
        wrap.addView(chips, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) })

        wrap.addView(EditText(this).apply {
            hint = "🔍 بحث في السجل"
            setHintTextColor(c("#6e7681")); setTextColor(c("#e6edf3")); isSingleLine = true; textSize = 14f
            setPadding(dp(12), dp(8), dp(12), dp(8)); background = box("#161b22", "#30363d", 8)
            addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, cnt: Int) {}
                override fun onTextChanged(s: CharSequence?, a: Int, b: Int, cnt: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) { logQuery = s?.toString()?.trim()?.lowercase() ?: ""; renderLogList() }
            })
        }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) })

        val cont = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(0, dp(10), 0, dp(20)) }
        wrap.addView(ScrollView(this).apply { addView(cont) }, LinearLayout.LayoutParams(-1, 0, 1f))
        d.setContentView(wrap)
        d.setOnDismissListener { logDialog = null; logContainer = null; logTitle = null; renderLogCard() }
        logDialog = d; logContainer = cont; logTitle = title
        d.show()
        renderLogList()
        renderLogCard()
    }

    private fun renderLogList() {
        val cont = logContainer ?: return
        for (ch in logChips) {
            val on = ch.tag == logFilter
            ch.setTextColor(c(if (on) "#0d1117" else "#e6edf3"))
            ch.background = box(if (on) "#58a6ff" else "#21262d", if (on) "#58a6ff" else "#30363d", 8)
        }
        val all = Shared.logs
        val reds = all.count { it.level == 2 }
        val yel = all.count { it.level == 1 }
        logTitle?.text = "📜 سجل الراوتر (${all.size})  🔴$reds  🟡$yel"
        cont.removeAllViews()
        if (Shared.logError != null) { note(cont, "⚠️ لا يمكن قراءة السجل: ${Shared.logError}\nأعطِ مستخدم API صلاحية read من System → Users → Groups"); return }
        if (!Shared.logsReady) { note(cont, "جارٍ تحميل السجل..."); return }
        val q = logQuery
        val list = all.asReversed().filter { e ->
            (logFilter == 0 || e.level == logFilter) &&
                    (q.isEmpty() || e.msg.lowercase().contains(q) || e.topics.lowercase().contains(q))
        }
        if (list.isEmpty()) { note(cont, "لا توجد رسائل مطابقة"); return }
        var shown = 0
        for (e in list) {
            if (shown >= 300) break
            val col = logColor(e.level)
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(10), dp(7), dp(10), dp(7))
                background = box(if (e.level == 2) "#2a1215" else "#161b22", if (e.level == 2) "#f85149" else if (e.level == 1) "#5c4813" else "#21262d", 8)
                layoutParams = LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(5) }
            }
            row.addView(TextView(this).apply {
                text = "${e.time}   •   ${e.topics}"
                setTextColor(c("#8b949e")); textSize = 11f
                textDirection = View.TEXT_DIRECTION_LTR
            })
            row.addView(TextView(this).apply {
                text = e.msg; setTextColor(c(col)); textSize = 13f
                textDirection = View.TEXT_DIRECTION_ANY_RTL
                if (e.level == 2) setTypeface(null, Typeface.BOLD)
            })
            cont.addView(row)
            shown++
        }
        if (list.size > shown) note(cont, "... و ${list.size - shown} سطر أقدم (استخدم البحث أو الفلتر)")
    }

    private fun renderModems(list: List<ModemStat>) {
        modemsContainer.removeAllViews()
        if (list.isEmpty()) {
            note(modemsContainer, if (Shared.modemsReady) "لم يتم إدخال مودمات في الإعدادات." else "جارٍ فحص المودمات...")
            return
        }
        for (m in list) {
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(dp(10), dp(8), dp(10), dp(8))
                background = box("#0d1117", if (m.up) "#21262d" else "#f85149", 8)
                isClickable = true
                setOnClickListener { pingDialog(m.ip, "فحص المودم: ${m.name} (${m.ip})") }
                layoutParams = LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(6) }
            }
            val dot = if (m.up) "🟢" else "🔴"
            row.addView(TextView(this).apply {
                text = "$dot ${m.name}"
                setTextColor(c("#e6edf3"))
                textSize = 14f
                setTypeface(null, Typeface.BOLD)
                layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
            })
            val statusTxt = if (m.up) {
                "<font color='#3fb950'>متصل (${m.ip})</font>"
            } else {
                "<font color='#f85149'>مقطوع منذ ${ago(m.downSince ?: System.currentTimeMillis())}</font>"
            }
            row.addView(TextView(this).apply {
                @Suppress("DEPRECATION")
                text = Html.fromHtml(statusTxt)
                textSize = 12f
            })
            modemsContainer.addView(row)
        }
    }

    // ---------- أوامر الراوتر ----------
    private fun showInterfaceDialog(item: IfStat) {
        val msg = "الاسم: ${item.name}\n" +
                "الحالة: ${if (item.disabled) "معطل (Disabled)" else if (item.running) "متصل ونشط (Running)" else "غير متصل (No Link)"}\n" +
                "السرعة الحالية: ↓ ${bw(item.rxRate)} | ↑ ${bw(item.txRate)}\n" +
                "إجمالي التحميل (RX): ${gb(item.totalRx)}\n" +
                "إجمالي الرفع (TX): ${gb(item.totalTx)}"

        AlertDialog.Builder(this)
            .setTitle("⚙️ التحكم بالمنفذ ${item.name}")
            .setMessage(msg)
            .setPositiveButton(if (item.disabled) "تفعيل المنفذ (Enable)" else "إيقاف المنفذ (Disable)") { _, _ ->
                toggleInterface(item.name, !item.disabled)
            }
            .setNeutralButton("إعادة تشغيل المنفذ") { _, _ -> restartInterface(item.name) }
            .setNegativeButton("إغلاق", null)
            .show()
    }

    private fun toggleInterface(ifName: String, disable: Boolean) {
        Thread {
            try {
                val r = rosConnect(prefs)
                val id = r.cmd("/interface/print", "?name=$ifName").firstOrNull()?.get(".id")
                if (id != null) {
                    r.cmd("/interface/set", "=.id=$id", "=disabled=${if (disable) "yes" else "no"}")
                    runOnUiThread { Toast.makeText(this, "تم تحديث حالة $ifName بنجاح", Toast.LENGTH_SHORT).show() }
                }
                r.close()
            } catch (e: Exception) {
                runOnUiThread { Toast.makeText(this, "خطأ: ${e.message}", Toast.LENGTH_LONG).show() }
            }
        }.start()
    }

    private fun restartInterface(ifName: String) {
        Thread {
            try {
                val r = rosConnect(prefs)
                val id = r.cmd("/interface/print", "?name=$ifName").firstOrNull()?.get(".id")
                if (id != null) {
                    r.cmd("/interface/set", "=.id=$id", "=disabled=yes")
                    Thread.sleep(1500)
                    r.cmd("/interface/set", "=.id=$id", "=disabled=no")
                    runOnUiThread { Toast.makeText(this, "تم إعادة تشغيل المنفذ $ifName", Toast.LENGTH_SHORT).show() }
                }
                r.close()
            } catch (e: Exception) {
                runOnUiThread { Toast.makeText(this, "خطأ: ${e.message}", Toast.LENGTH_LONG).show() }
            }
        }.start()
    }

    private fun confirmKick(path: String, id: String, name: String) {
        AlertDialog.Builder(this)
            .setTitle("فصل المتصل")
            .setMessage("هل تريد فصل ($name) ؟")
            .setPositiveButton("نعم، افصل") { _, _ -> kickUser(path, id, name) }
            .setNegativeButton("إلغاء", null)
            .show()
    }

    private fun kickUser(path: String, id: String, name: String) {
        Thread {
            try {
                val r = rosConnect(prefs)
                r.cmd(path, "=.id=$id")
                r.close()
                runOnUiThread { Toast.makeText(this, "تم فصل المتصل ($name) بنجاح", Toast.LENGTH_SHORT).show() }
            } catch (e: Exception) {
                runOnUiThread { Toast.makeText(this, "تعذر الفصل: ${e.message}", Toast.LENGTH_LONG).show() }
            }
        }.start()
    }

    private fun pingDialog(address: String, title: String) {
        val pd = AlertDialog.Builder(this).setTitle(title).setMessage("جارٍ إرسال 4 نبضات Ping إلى $address...").show()
        Thread {
            try {
                val r = rosConnect(prefs)
                val res = r.cmd("/ping", "=address=$address", "=count=4")
                r.close()
                val sb = StringBuilder()
                var okCount = 0
                for ((idx, row) in res.withIndex()) {
                    val time = row["time"]
                    val status = row["status"]
                    if (time != null) {
                        okCount++
                        sb.append("نبضة ${idx + 1}: ✅ الرد خلال $time\n")
                    } else {
                        sb.append("نبضة ${idx + 1}: ❌ انقطاع (${status ?: "timeout"})\n")
                    }
                }
                sb.append("\nالنتيجة النهائية: وصل $okCount من 4")
                runOnUiThread {
                    pd.dismiss()
                    AlertDialog.Builder(this).setTitle(title).setMessage(sb.toString()).setPositiveButton("حسناً", null).show()
                }
            } catch (e: Exception) {
                runOnUiThread {
                    pd.dismiss()
                    Toast.makeText(this, "خطأ أثناء الفحص: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }.start()
    }

    private fun confirmRebootRouter() {
        AlertDialog.Builder(this)
            .setTitle("⚠️ تأكيد إعادة تشغيل الراوتر")
            .setMessage("هل أنت متأكد من رغبتك في إعادة تشغيل الميكروتيك الرئيسي الآن؟ سينقطع الاتصال مؤقتاً.")
            .setPositiveButton("نعم، أعد التشغيل") { _, _ ->
                Thread {
                    try {
                        val r = rosConnect(prefs)
                        r.cmd("/system/reboot")
                        r.close()
                    } catch (e: Exception) { }
                    runOnUiThread { Toast.makeText(this, "تم إرسال أمر إعادة التشغيل للراوتر", Toast.LENGTH_LONG).show() }
                }.start()
            }
            .setNegativeButton("إلغاء", null)
            .show()
    }

    private fun settings() {
        val defs = mapOf("port" to "8728", "wan" to "ether1", "modems" to DEFAULT_MODEMS)
        val keys = listOf(
            Triple("name", "🏷️ اسم الشبكة", "مثال: شبكة النور"),
            Triple("local", "عنوان الراوتر المحلي", "192.168.88.1"),
            Triple("cloud", "عنوان الكلاود (للمراقبة من خارج الشبكة)", "xxxx.sn.mynetname.net"),
            Triple("port", "منفذ API", "8728"),
            Triple("user", "اسم المستخدم", ""),
            Triple("pass", "كلمة المرور", ""),
            Triple("wan", "واجهة الإنترنت", "ether1"),
            Triple("modems", "المودمات — سطر لكل مودم: IP والاسم", "90.90.2.2 شيبان")
        )
        val l = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(18), dp(8), dp(18), dp(8)) }
        val es = keys.map { (k, label, h) ->
            l.addView(TextView(this).apply {
                text = label; textSize = 12f; setTextColor(c("#8b949e")); setPadding(0, dp(10), 0, 0)
            })
            EditText(this).apply {
                hint = h
                setText(prefs.getString(k, null) ?: defs[k] ?: "")
                if (k == "pass") inputType = 129
                if (k == "modems") { isSingleLine = false; minLines = 4; gravity = Gravity.TOP or Gravity.START } else isSingleLine = true
                l.addView(this)
            }
        }
        l.addView(TextView(this).apply {
            text = "🔔 إشعارات سجل الراوتر (LOG)"; textSize = 13f; setTextColor(c("#8b949e"))
            setTypeface(null, Typeface.BOLD); setPadding(0, dp(16), 0, dp(2))
        })
        val cbErr = CheckBox(this).apply { text = "🔴 إشعار فوري عند أي خطأ أحمر (موصى به)"; isChecked = prefs.getBoolean("notif_err", true); l.addView(this) }
        val cbWarn = CheckBox(this).apply { text = "🟡 إشعار للتحذيرات الصفراء أيضاً"; isChecked = prefs.getBoolean("notif_warn", false); l.addView(this) }

        AlertDialog.Builder(this).setTitle("⚙️ إعدادات الشبكة والمراقبة").setView(ScrollView(this).apply { addView(l) })
            .setPositiveButton("حفظ واتصال") { _, _ ->
                val e = prefs.edit()
                keys.forEachIndexed { i, p -> e.putString(p.first, es[i].text.toString().trim()) }
                e.putBoolean("notif_err", cbErr.isChecked).putBoolean("notif_warn", cbWarn.isChecked)
                e.apply()
                tvTitle.text = "📡 ${netName(prefs)}"
                Shared.cfgGen++
                Shared.forceModem = true
                Shared.modemsReady = false
                Shared.error = null
                Shared.snap = null
                Shared.modems = emptyList()
                lastSnap = null; lastModems = null
                startMonitor()
                askBatteryExemption(false)
            }.setNegativeButton("إلغاء", null).show()
    }

}

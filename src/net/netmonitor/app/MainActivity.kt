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
import android.view.ViewGroup
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

// اتصال API واحد مشترك: كل الأوامر تمر على نفس الجلسة (وسوم .tag) فلا تتكرر عمليات الدخول
class Ros(host: String, port: Int, timeout: Int) {
    private val s = Socket()
    private val ins: InputStream
    private val out: OutputStream
    @Volatile var dead = false
    private val tagSeq = java.util.concurrent.atomic.AtomicInteger(1)
    private val calls = ConcurrentHashMap<String, Call>()
    private val wlock = Any()
    private var reader: Thread? = null

    private class Call(val onRe: ((Map<String, String>) -> Unit)?) {
        val rows = ArrayList<Map<String, String>>()
        @Volatile var err: String? = null
        @Volatile var fatal: Exception? = null
        @Volatile var ret: String? = null
        val latch = java.util.concurrent.CountDownLatch(1)
    }

    init {
        s.connect(InetSocketAddress(host, port), timeout)
        s.soTimeout = 15000
        s.keepAlive = true
        s.tcpNoDelay = true
        ins = s.getInputStream()
        out = s.getOutputStream()
    }

    fun close() {
        dead = true
        try { s.close() } catch (e: Exception) { }
        failAll(IOException("closed"))
    }

    private fun failAll(e: Exception) {
        for (c in calls.values) { c.fatal = e; c.latch.countDown() }
        calls.clear()
    }

    private fun wlen(n: Int) {
        when {
            n < 0x80 -> out.write(n)
            n < 0x4000 -> { out.write((n shr 8) or 0x80); out.write(n and 0xFF) }
            else -> { out.write((n shr 16) or 0xC0); out.write((n shr 8) and 0xFF); out.write(n and 0xFF) }
        }
    }

    private fun rb(): Int { val c = ins.read(); if (c < 0) throw IOException("closed"); return c }

    private fun rlenFrom(c: Int): Int {
        return when {
            (c and 0x80) == 0 -> c
            (c and 0xC0) == 0x80 -> ((c and 0x3F) shl 8) or rb()
            (c and 0xE0) == 0xC0 -> { var v = c and 0x1F; repeat(2) { v = (v shl 8) or rb() }; v }
            (c and 0xF0) == 0xE0 -> { var v = c and 0x0F; repeat(3) { v = (v shl 8) or rb() }; v }
            else -> { var v = 0; repeat(4) { v = (v shl 8) or rb() }; v }
        }
    }

    private fun readSentence(): List<String> {
        val w = ArrayList<String>()
        while (true) {
            val n = rlenFrom(rb())
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

    private fun tagOf(sn: List<String>): String? {
        for (w in sn) if (w.startsWith(".tag=")) return w.substring(5)
        return null
    }

    private fun send(words: List<String>) {
        synchronized(wlock) {
            for (w in words) { val b = w.toByteArray(Charsets.UTF_8); wlen(b.size); out.write(b) }
            out.write(0)
            out.flush()
        }
    }

    // تسجيل الدخول: مرة واحدة فقط لكل اتصال، قبل تشغيل قارئ الردود
    fun login(user: String, pass: String) {
        send(listOf("/login", "=name=$user", "=password=$pass"))
        var err: String? = null
        while (true) {
            val sn = readSentence()
            if (sn.isEmpty()) continue
            when (sn[0]) {
                "!trap" -> err = attrs(sn)["message"] ?: "error"
                "!fatal" -> throw IOException("fatal")
                "!done" -> { if (err != null) throw Trap(err); break }
            }
        }
        s.soTimeout = 0
        reader = Thread { readLoop() }.apply { isDaemon = true; start() }
    }

    private fun readLoop() {
        try {
            while (!dead) {
                val sn = readSentence()
                if (sn.isEmpty()) continue
                val tag = tagOf(sn) ?: continue
                val c = calls[tag] ?: continue
                when (sn[0]) {
                    "!re" -> { val a = attrs(sn); if (c.onRe != null) c.onRe.invoke(a) else synchronized(c.rows) { c.rows.add(a) } }
                    "!trap" -> c.err = attrs(sn)["message"] ?: "error"
                    "!fatal" -> { c.fatal = IOException("fatal"); calls.remove(tag); c.latch.countDown() }
                    "!done" -> { c.ret = attrs(sn)["ret"]; calls.remove(tag); c.latch.countDown() }
                }
            }
        } catch (e: Exception) {
            dead = true
            try { s.close() } catch (x: Exception) { }
            failAll(if (e is IOException) e else IOException(e.message))
        }
    }

    private fun start(words: Array<out String>, onRe: ((Map<String, String>) -> Unit)?): Pair<String, Call> {
        if (dead) throw IOException("closed")
        val tag = tagSeq.getAndIncrement().toString()
        val c = Call(onRe)
        calls[tag] = c
        try { send(words.toList() + ".tag=$tag") } catch (e: Exception) { calls.remove(tag); close(); throw e }
        return tag to c
    }

    // أمر عادي: ينتظر الرد (يمكن تشغيل عدة أوامر بالتوازي على نفس الاتصال)
    fun cmd(vararg words: String): List<Map<String, String>> {
        val (tag, c) = start(words, null)
        if (!c.latch.await(20, java.util.concurrent.TimeUnit.SECONDS)) {
            calls.remove(tag); close(); throw IOException("timeout")
        }
        c.fatal?.let { throw if (it is IOException) it else IOException(it.message) }
        c.err?.let { throw Trap(it) }
        val res = ArrayList<Map<String, String>>(synchronized(c.rows) { c.rows })
        val ret = c.ret
        if (ret != null && res.isEmpty()) res.add(mapOf("ret" to ret))
        return res
    }

    // بث مستمر (سجل الراوتر المباشر) على نفس الاتصال
    fun streamImpl(words: Array<String>, stop: () -> Boolean, onIdle: () -> Unit, onRe: (Map<String, String>) -> Unit) {
        val (tag, c) = start(words, onRe)
        try {
            while (true) {
                if (stop()) { try { send(listOf("/cancel", "=tag=$tag")) } catch (e: Exception) { }; throw IOException("stop") }
                if (c.latch.await(3, java.util.concurrent.TimeUnit.SECONDS)) break
                onIdle()
            }
        } finally { calls.remove(tag) }
        c.fatal?.let { throw if (it is IOException) it else IOException(it.message) }
        c.err?.let { if (it != "interrupted") throw Trap(it) }
    }
}

// مدير الاتصال: جلسة واحدة فقط مع الراوتر يستخدمها الجميع
object Net {
    private val lock = Any()
    private var cur: Ros? = null
    private var lastFail = 0L
    private var lastErr: Exception? = null

    fun get(prefs: SharedPreferences): Ros {
        synchronized(lock) {
            val c = cur
            if (c != null && !c.dead) return c
            val now = System.currentTimeMillis()
            val le = lastErr
            if (le != null && now - lastFail < 2500) throw le
            try {
                val r = rosConnect(prefs)
                cur = r; lastErr = null
                return r
            } catch (e: Exception) {
                lastErr = e; lastFail = System.currentTimeMillis()
                throw e
            }
        }
    }

    fun drop(r: Ros?) {
        synchronized(lock) {
            if (r != null) { try { r.close() } catch (e: Exception) { } }
            if (cur === r || cur?.dead == true) cur = null
        }
    }

    fun reset() { synchronized(lock) { try { cur?.close() } catch (e: Exception) { }; cur = null; lastErr = null } }
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
    @Volatile var activity: java.lang.ref.WeakReference<Activity>? = null
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
            r.login(prefs.getString("user", "").orEmpty(), prefs.getString("pass", "").orEmpty())
            Shared.via = if (k == "local") "محلي LAN" else "كلاود Cloud"
            return r
        } catch (e: Exception) { r?.close(); last = e }
    }
    throw last
}

class RouterCfg(
    val id: String, var name: String, var local: String, var cloud: String, var port: String,
    var user: String, var pass: String, var wan: String, var modems: String,
    var nErr: Boolean = true, var nWarn: Boolean = false
) {
    fun sig() = listOf(local, cloud, port, user, pass, nErr, nWarn).joinToString("|")
    fun title() = name.ifBlank { local.ifBlank { cloud.ifBlank { "راوتر" } } }
    fun address() = local.ifBlank { cloud }
}

object Routers {
    private fun sp(ctx: Context) = ctx.getSharedPreferences("routers", Context.MODE_PRIVATE)
    private fun cfg(ctx: Context) = ctx.getSharedPreferences("cfg", Context.MODE_PRIVATE)

    fun load(ctx: Context): MutableList<RouterCfg> {
        val out = ArrayList<RouterCfg>()
        try {
            val a = org.json.JSONArray(sp(ctx).getString("list", "[]"))
            for (i in 0 until a.length()) {
                val o = a.getJSONObject(i)
                out.add(RouterCfg(o.getString("id"), o.optString("name"), o.optString("local").ifBlank { o.optString("cloud") }, if (o.optString("local").isBlank()) "" else o.optString("cloud"),
                    o.optString("port", "8728"), o.optString("user"), o.optString("pass"), o.optString("wan", "ether1"), o.optString("modems"), o.optBoolean("nErr", true), o.optBoolean("nWarn", false)))
            }
        } catch (e: Exception) { }
        return out
    }

    fun save(ctx: Context, list: List<RouterCfg>) {
        val a = org.json.JSONArray()
        for (r in list) a.put(org.json.JSONObject().put("id", r.id).put("name", r.name).put("local", r.local).put("cloud", r.cloud)
            .put("port", r.port).put("user", r.user).put("pass", r.pass).put("wan", r.wan).put("modems", r.modems).put("nErr", r.nErr).put("nWarn", r.nWarn))
        sp(ctx).edit().putString("list", a.toString()).apply()
    }

    fun activeId(ctx: Context): String = sp(ctx).getString("active", "") ?: ""
    fun setActive(ctx: Context, id: String) { sp(ctx).edit().putString("active", id).apply() }
    fun newId(): String = "r" + java.lang.Long.toString(System.currentTimeMillis(), 36) + (Math.random() * 1000).toInt()

    fun fromCfg(ctx: Context, id: String, keepPass: Boolean = true): RouterCfg {
        val p = cfg(ctx)
        fun g(k: String, d: String = "") = p.getString(k, d) ?: d
        return RouterCfg(id, g("name"), g("local"), g("cloud"), g("port", "8728"), g("user"), if (keepPass) g("pass") else "", g("wan", "ether1"), g("modems"), p.getBoolean("notif_err", true), p.getBoolean("notif_warn", false))
    }

    // الإعدادات القديمة (راوتر واحد) تصير أول راوتر محفوظ
    fun ensure(ctx: Context) {
        val list = load(ctx)
        if (list.isEmpty()) {
            if (cfg(ctx).contains("user")) {
                val r = fromCfg(ctx, newId())
                save(ctx, listOf(r)); setActive(ctx, r.id)
            }
            return
        }
        if (list.none { it.id == activeId(ctx) }) setActive(ctx, list[0].id)
    }

    fun upsert(ctx: Context, r: RouterCfg) {
        val list = load(ctx)
        val i = list.indexOfFirst { it.id == r.id }
        if (i >= 0) list[i] = r else list.add(r)
        save(ctx, list)
    }

    fun remove(ctx: Context, id: String) { save(ctx, load(ctx).filter { it.id != id }) }

    fun applyToCfg(ctx: Context, r: RouterCfg) {
        cfg(ctx).edit().putString("name", r.name).putString("local", r.local).putString("cloud", r.cloud).putString("port", r.port)
            .putString("user", r.user).putString("pass", r.pass).putString("wan", r.wan).putString("modems", r.modems).putBoolean("notif_err", r.nErr).putBoolean("notif_warn", r.nWarn).apply()
    }
}

// اتصال بحقول راوتر محدد (للمراقبة بالخلفية للراوترات الأخرى)
fun rosConnectTo(r: RouterCfg): Ros {
    val port = r.port.toIntOrNull() ?: 8728
    var last: Exception = IOException("أدخل عنوان الراوتر")
    for ((h, t) in listOf(r.local to 2500, r.cloud to 8000)) {
        if (h.isBlank()) continue
        var c: Ros? = null
        try {
            c = Ros(h, port, t)
            c.login(r.user, r.pass)
            return c
        } catch (e: Exception) { c?.close(); last = e }
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
            Net.reset()
            stopWatches()
            try {
                val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                nm.cancelAll()
            } catch (e: Exception) { }
            stopForeground(true)
            stopSelf()
            val act = Shared.activity?.get()
            Handler(Looper.getMainLooper()).post { try { act?.finishAndRemoveTask() } catch (e: Exception) { } }
            // إنهاء العملية بالكامل حتى لا يبقى شيء يعمل بالخلفية
            Handler(Looper.getMainLooper()).postDelayed({ android.os.Process.killProcess(android.os.Process.myPid()) }, 600)
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
            Thread { watchSync() }.apply { isDaemon = true; start() }
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
        Net.reset()
        stopWatches()
        try { stopForeground(true) } catch (e: Exception) { }
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
                Net.reset(); ros = null
                myGen = Shared.cfgGen
                prevIf.clear()
            }
            try {
                val r = Net.get(prefs).also { ros = it }
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
                if (e !is Trap) Net.drop(ros)
                ros = null
                Shared.error = e.message ?: "خطأ غير معروف"
                updateNotif("⚠️ تعذر الاتصال بالراوتر — جارٍ إعادة المحاولة")
            }
            nap(2000)
        }
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
                r = Net.get(prefs)
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

                var idleMs = 0L
                val gen = myGen
                r.streamImpl(
                    arrayOf("/log/print", "=follow-only=", "=.proplist=.id,time,topics,message"),
                    stop = { !running || gen != Shared.cfgGen },
                    onIdle = { idleMs += 3000; flush(false) },
                    onRe = { m -> idleMs = 0; toLogEntry(m)?.let { addLogs(listOf(it), true, pending) }; flush(false) }
                )
            } catch (e: Trap) {
                Shared.logError = e.message; Shared.logVer++
                nap(15000); continue
            } catch (e: Exception) {
                if (e.message == "stop") wait = 200L else { wait = 5000L; Net.drop(r) }
            } finally {
                flush(true)
            }
            nap(wait)
        }
    }

    // ---------- مراقبة بقية الراوترات بالخلفية: اتصال واحد لكل راوتر (سجل + انقطاع) ----------
    private class Watch(val cfg: RouterCfg) { @Volatile var stop = false; @Volatile var ros: Ros? = null }
    private val watches = HashMap<String, Watch>()

    private fun watchSync() {
        while (running) {
            try {
                val list = Routers.load(this)
                val act = Routers.activeId(this)
                val want = list.filter { it.id != act && it.user.isNotBlank() && (it.local.isNotBlank() || it.cloud.isNotBlank()) }
                synchronized(watches) {
                    val it = watches.entries.iterator()
                    while (it.hasNext()) {
                        val (id, w) = it.next()
                        val cur = want.firstOrNull { x -> x.id == id }
                        if (cur == null || cur.sig() != w.cfg.sig() || cur.name != w.cfg.name) {
                            w.stop = true; try { w.ros?.close() } catch (e: Exception) { }; it.remove()
                        }
                    }
                    for (r in want) if (!watches.containsKey(r.id)) {
                        val w = Watch(r); watches[r.id] = w
                        Thread { watchLoop(w) }.apply { isDaemon = true; start() }
                    }
                }
            } catch (e: Exception) { }
            nap(3000)
        }
        stopWatches()
    }

    private fun stopWatches() {
        synchronized(watches) {
            for (w in watches.values) { w.stop = true; try { w.ros?.close() } catch (e: Exception) { } }
            watches.clear()
        }
    }

    private fun watchNotify(w: Watch, title: String, text: String) {
        try {
            val open = PendingIntent.getActivity(this, 7, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            val n = builder(CH_ALERT)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentTitle(title)
                .setContentText(text.lineSequence().firstOrNull() ?: text)
                .setSubText(w.cfg.title())
                .setStyle(Notification.BigTextStyle().bigText(text))
                .setContentIntent(open)
                .setAutoCancel(true)
                .build()
            (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).notify(3000 + (w.cfg.id.hashCode() and 0xff) * 4 + (alertCnt++ % 4), n)
        } catch (e: Exception) { }
    }

    private fun watchLoop(w: Watch) {
        var fails = 0
        var downAlerted = false
        var lastId = -1L
        while (running && !w.stop) {
            var r: Ros? = null
            try {
                r = rosConnectTo(w.cfg)
                w.ros = r
                if (downAlerted) { watchNotify(w, "✅ عاد الاتصال بالراوتر", w.cfg.title()); downAlerted = false }
                fails = 0
                val init = r.cmd("/log/print", "=.proplist=.id,time,topics,message").mapNotNull { toLogEntry(it) }
                if (init.isNotEmpty()) lastId = maxOf(lastId, init.last().id)
                val pend = ArrayList<LogEntry>()
                var lastFlush = 0L
                fun flush(force: Boolean) {
                    val now = System.currentTimeMillis()
                    if (pend.isNotEmpty() && (force || now - lastFlush > 5000)) {
                        val reds = pend.count { it.level == 2 }
                        val title = if (reds > 0) "🔴 ${w.cfg.title()}: خطأ في السجل" else "🟡 ${w.cfg.title()}: تحذير في السجل"
                        watchNotify(w, title, pend.takeLast(6).joinToString("\n") { "${it.time}  ${it.msg}" })
                        pend.clear(); lastFlush = now
                    }
                }
                r.streamImpl(
                    arrayOf("/log/print", "=follow-only=", "=.proplist=.id,time,topics,message"),
                    stop = { !running || w.stop },
                    onIdle = { flush(false) },
                    onRe = { m ->
                        toLogEntry(m)?.let { e ->
                            if (e.id > lastId) {
                                lastId = e.id
                                if ((e.level == 2 && w.cfg.nErr) || (e.level == 1 && w.cfg.nWarn)) pend.add(e)
                            }
                        }
                        flush(false)
                    }
                )
            } catch (e: Exception) {
                try { r?.close() } catch (x: Exception) { }
                w.ros = null
                fails++
                if (fails >= 3 && !downAlerted && !w.stop) { downAlerted = true; watchNotify(w, "🔌 الراوتر لا يستجيب", w.cfg.title()) }
            }
            nap(if (fails > 0) 10000L else 3000L)
        }
        try { w.ros?.close() } catch (e: Exception) { }
    }

    // ---------- حلقة المودمات: فحص متوازي بعدة اتصالات (كل ~3 ثواني) ----------
    private fun modemLoop() {
        var myGen = Shared.cfgGen
        var lastDown = HashSet<String>()
        var firstDone = false

        while (running) {
            if (myGen != Shared.cfgGen) {
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
            val workers = if (list.size < 5) list.size else 5
            val results = arrayOfNulls<ModemStat>(list.size)
            val threads = ArrayList<Thread>()

            for (w in 0 until workers) {
                threads.add(Thread {
                    var i = w
                    while (i < list.size) {
                        val name = list[i].first
                        val mIp = list[i].second
                        var cc: Ros? = null
                        val up: Boolean? = try {
                            val c = Net.get(prefs).also { cc = it }
                            c.cmd("/ping", "=address=$mIp", "=count=2", "=interval=0.5")
                                .any { (it["received"] ?: "0") != "0" || it["time"] != null }
                        } catch (e: Trap) {
                            false
                        } catch (e: Exception) {
                            Net.drop(cc)
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

    private fun grad(c1: String, c2: String, radiusDp: Int = 20) = GradientDrawable(
        GradientDrawable.Orientation.TL_BR, intArrayOf(c(c1), c(c2))
    ).apply { cornerRadius = dp(radiusDp).toFloat() }

    private val NAV1 = "#1a2c50"
    private val NAV2 = "#121f3c"

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
            background = grad(NAV1, NAV2, 22)
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
        Shared.activity = java.lang.ref.WeakReference(this)
        window.statusBarColor = c("#EEF3FB")
        if (Build.VERSION.SDK_INT >= 23) window.decorView.systemUiVisibility = View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR

        if (Build.VERSION.SDK_INT >= 33) {
            try { requestPermissions(arrayOf("android.permission.POST_NOTIFICATIONS"), 1) } catch (e: Exception) { }
        }

        Routers.ensure(this)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(12), dp(12), dp(12), dp(28))
            layoutDirection = View.LAYOUT_DIRECTION_RTL
        }
        setContentView(ScrollView(this).apply { setBackgroundColor(c("#EEF3FB")); addView(root) })

        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        tvTitle = TextView(this)
        header.addView(tvTitle.apply {
            text = "📡 ${netName(prefs)}"
            setTextColor(c("#0f1932"))
            textSize = 19f
            setTypeface(null, Typeface.BOLD)
            layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
        })

        fun actionBtn(label: String, onClick: () -> Unit) = TextView(this).apply {
            text = label
            textSize = 14f
            setTextColor(c("#0f1932"))
            setPadding(dp(10), dp(6), dp(10), dp(6))
            background = grad("#ffffff", "#dfe8f8", 14)
            setOnClickListener { onClick() }
            layoutParams = LinearLayout.LayoutParams(-2, -2).apply { rightMargin = dp(6) }
        }

        header.addView(actionBtn("🔄") {
            Toast.makeText(this, "جارٍ التحديث الفوري...", Toast.LENGTH_SHORT).show()
            Shared.forceModem = true
            startMonitor()
        })
        header.addView(actionBtn("🔋") { askBatteryExemption(true) })
        header.addView(actionBtn("🔀") { routersScreen() })
        header.addView(actionBtn("⚙️") { settings() })
        header.addView(actionBtn("✖ خروج") { confirmExit() }.apply {
            setTextColor(c("#ffffff")); setTypeface(null, Typeface.BOLD); textSize = 13f
            background = grad("#ff6a5c", "#d6362a", 14)
        })
        root.addView(header)

        banner = TextView(this).apply {
            textSize = 15f
            setTypeface(null, Typeface.BOLD)
            gravity = Gravity.CENTER
            setPadding(dp(12), dp(12), dp(12), dp(12))
            text = "جارٍ الاتصال بالراوتر..."
            setTextColor(c("#ffffff"))
            background = grad("#6b7a99", "#4a5875", 18)
        }
        root.addView(banner, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(12) })

        val gridRow1 = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val gridRow2 = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }

        fun makeStatCard(title: String, g1: String, g2: String, hint: String, onClick: (() -> Unit)?): Triple<LinearLayout, TextView, TextView> {
            val cardLayout = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(12), dp(10), dp(12), dp(10))
                background = grad(g1, g2, 20)
                if (onClick != null) {
                    isClickable = true
                    setOnClickListener { onClick() }
                }
            }
            cardLayout.addView(TextView(this).apply { text = title; setTextColor(c("#ffffff")); textSize = 12f })
            val mainVal = TextView(this).apply {
                text = "-"
                setTextColor(c("#ffffff"))
                textSize = 22f
                setTypeface(null, Typeface.BOLD)
                setPadding(0, dp(4), 0, dp(2))
            }
            val subVal = TextView(this).apply { text = hint; setTextColor(c("#e6ecff")); textSize = 11f }
            cardLayout.addView(mainVal)
            cardLayout.addView(subVal)
            return Triple(cardLayout, mainVal, subVal)
        }

        val wanTriple = makeStatCard("🌐 حالة الإنترنت (WAN)", "#18be82", "#109664", "اضغط لفحص البنق") { pingDialog("8.8.8.8", "فحص الإنترنت العالمي (Google DNS)") }
        tvWanVal = wanTriple.second; tvWanSub = wanTriple.third

        val hostTriple = makeStatCard("👥 HOST", "#14aac8", "#0a6eaa", "اضغط لعرض القائمة") { openList(true) }
        tvHostVal = hostTriple.second; tvHostSub = hostTriple.third

        val activeTriple = makeStatCard("🔌 ACTIVE", "#e65a96", "#be326e", "اضغط لعرض القائمة") { openList(false) }
        tvActiveVal = activeTriple.second

        val modTriple = makeStatCard("📡 المودمات المتصلة", "#ffb020", "#f07a0a", "اضغط لإعادة الفحص") {
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
            background = grad("#ffffff", "#e8f0ff", 20)
            isClickable = true
            setOnClickListener { openLog() }
        }
        val logTexts = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; layoutParams = LinearLayout.LayoutParams(0, -2, 1f) }
        logTexts.addView(TextView(this).apply { text = "📜 سجل الراوتر (LOG)"; setTextColor(c("#64708a")); textSize = 12f })
        tvLogSub = TextView(this).apply { text = "جارٍ تحميل السجل..."; setTextColor(c("#0f1932")); textSize = 13f; maxLines = 2; setPadding(0, dp(4), 0, 0) }
        logTexts.addView(tvLogSub)
        logCard.addView(logTexts)
        tvLogVal = TextView(this).apply {
            text = "عرض ›"; textSize = 14f; setTypeface(null, Typeface.BOLD); setTextColor(c("#ffffff"))
            setPadding(dp(12), dp(6), dp(12), dp(6)); background = grad("#1e6eff", "#0a32be", 14)
        }
        logCard.addView(tvLogVal)
        root.addView(logCard, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) })

        val routerCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), dp(12), dp(14), dp(14))
            background = grad(NAV1, NAV2, 22)
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
            background = grad(NAV1, NAV2, 22)
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
            background = grad("#1e6eff", "#0a32be", 16)
        }
        ifSection.addView(tvIfTotal, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) })

        ifContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dp(8), 0, 0)
        }
        ifSection.addView(ifContainer)
        root.addView(ifSection, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(12) })

        if (intent?.getBooleanExtra("open_log", false) == true) ui.post { openLog() }
        else ui.post { routersScreen(); if (Routers.load(this).isEmpty()) loginPage(null) }
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

    // ---------- الخروج: نهائي أو تشغيل بالخلفية ----------
    @Deprecated("Deprecated in Java")
    override fun onBackPressed() = confirmExit()

    private fun confirmExit() {
        AlertDialog.Builder(this, R.style.NMDialog)
            .setTitle("الخروج من التطبيق")
            .setMessage("خروج نهائي: يوقف المراقبة والتنبيهات تماماً حتى تفتح التطبيق مرة أخرى.\n\nتشغيل بالخلفية: يغلق الواجهة وتستمر المراقبة والتنبيهات.")
            .setPositiveButton("⏻ خروج نهائي") { _, _ -> exitCompletely() }
            .setNeutralButton("بالخلفية") { _, _ -> moveTaskToBack(true) }
            .setNegativeButton("إلغاء", null)
            .show()
    }

    private fun exitCompletely() {
        ui.removeCallbacks(tick)
        // enabled=false يمنع إعادة التشغيل التلقائي (بعد إعادة تشغيل الجوال أو سحب التطبيق)
        prefs.edit().putBoolean("enabled", false).commit()
        try { stopService(Intent(this, MonitorService::class.java)) } catch (e: Exception) { }
        Net.reset()
        try { (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).cancelAll() } catch (e: Exception) { }
        finishAndRemoveTask()
        Handler(Looper.getMainLooper()).postDelayed({ android.os.Process.killProcess(android.os.Process.myPid()) }, 600)
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
        banner.setTextColor(c("#ffffff"))
        banner.background = when (col) {
            "#f85149" -> grad("#ff6a5c", "#d6362a", 18)
            "#e3b341" -> grad("#ffb020", "#f07a0a", 18)
            "#3fb950" -> grad("#18be82", "#109664", 18)
            else -> grad("#6b7a99", "#4a5875", 18)
        }
    }

    private fun renderSnap(s: Snapshot) {
        tvWanVal.text = if (s.wanUp) "متصل ✓" else "مقطوع ✗"
        tvWanVal.setTextColor(c("#ffffff"))
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
            setTextColor(c("#64708a"))
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
            setBackgroundColor(c("#EEF3FB"))
            layoutDirection = View.LAYOUT_DIRECTION_RTL
        }
        val head = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL; setPadding(dp(14), dp(10), dp(10), dp(10)); background = grad(NAV1, NAV2, 22) }
        val title = TextView(this).apply {
            setTextColor(c("#ffffff"))
            textSize = 18f
            setTypeface(null, Typeface.BOLD)
            layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
        }
        head.addView(title)
        head.addView(TextView(this).apply {
            text = "✖ إغلاق"
            setTextColor(c("#ffffff"))
            textSize = 13f
            setPadding(dp(12), dp(6), dp(12), dp(6))
            background = grad("#1e6eff", "#0a32be", 14)
            setOnClickListener { d.dismiss() }
        })
        wrap.addView(head)

        val search = EditText(this).apply {
            hint = if (isHost) "🔍 بحث بالماك أو IP" else "🔍 بحث باسم المستخدم أو IP"
            setHintTextColor(c("#8a94ab"))
            setTextColor(c("#1f2a44"))
            isSingleLine = true
            textSize = 14f
            setPadding(dp(12), dp(8), dp(12), dp(8))
            background = box("#ffffff", "#c9d6ee", 14)
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
                background = grad("#ffffff", "#e8f0ff", 16)
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
                setTextColor(c("#1f2a44"))
                textSize = 14f
                setTypeface(null, Typeface.BOLD)
            })
            info.addView(TextView(this).apply {
                text = "IP: $ip | ⏱ $up$st"
                setTextColor(c("#64708a"))
                textSize = 12f
            })
            info.addView(TextView(this).apply {
                @Suppress("DEPRECATION")
                text = Html.fromHtml("<font color='#0f7a50'>⬇ ${gb(dl)}</font> &nbsp; <font color='#1e6eff'>⬆ ${gb(ul)}</font> &nbsp; <font color='#b07800'>Σ ${gb(dl + ul)}</font>")
                textSize = 13f
            })
            row.addView(info)
            row.addView(TextView(this).apply {
                text = if (isHost) "حذف ❌" else "طرد ❌"
                setTextColor(c("#ffffff"))
                textSize = 12f
                setPadding(dp(10), dp(5), dp(10), dp(5))
                background = grad("#ff6a5c", "#d6362a", 12)
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
                background = if (item.disabled) grad("#5b6b8c", "#3e4c6a", 16) else if (item.running) grad("#18be82", "#109664", 16) else grad("#ff6a5c", "#c82828", 16)
                isClickable = true
                setOnClickListener { showInterfaceDialog(item) }
                layoutParams = LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(6) }
            }
            val top = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
            val statusDot = if (item.disabled) "⚪" else if (item.running) "🟢" else "🔴"
            top.addView(TextView(this).apply {
                text = "$statusDot ${item.name}"
                setTextColor(c("#ffffff"))
                textSize = 15f
                setTypeface(null, Typeface.BOLD)
                layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
            })
            top.addView(TextView(this).apply {
                @Suppress("DEPRECATION")
                text = Html.fromHtml("<font color='#ffffff'>↓ ${bw(item.rxRate)}</font> &nbsp;&nbsp; <font color='#fff3c4'>↑ ${bw(item.txRate)}</font>")
                textSize = 13f
            })
            row.addView(top)

            // استهلاك هذه الواجهة منذ آخر تشغيل للراوتر
            row.addView(TextView(this).apply {
                @Suppress("DEPRECATION")
                text = Html.fromHtml("📊 الاستهلاك: <font color='#ffffff'>⬇ ${gbx(item.totalRx)}</font> &nbsp; <font color='#fff3c4'>⬆ ${gbx(item.totalTx)}</font> &nbsp; <font color='#ffffff'>Σ ${gbx(item.totalRx + item.totalTx)}</font>")
                setTextColor(c("#e6f6ee"))
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
                    progressDrawable = makeProgressDrawable("#ffffff")
                    layoutParams = LinearLayout.LayoutParams(-1, dp(4)).apply { topMargin = dp(6) }
                }
                row.addView(miniBar)
            }
            ifContainer.addView(row)
        }
    }

    // ---------- سجل الراوتر ----------
    private fun logColor(lvl: Int) = when (lvl) { 2 -> "#d6362a"; 1 -> "#9a6a00"; else -> "#1f2a44" }

    private fun renderLogCard() {
        val logs = Shared.logs
        val unread = Shared.logUnread
        val lastRed = logs.lastOrNull { it.level == 2 }
        when {
            Shared.logError != null -> {
                tvLogSub.text = "⚠️ لا يمكن قراءة السجل: ${Shared.logError}\n(أعطِ مستخدم API صلاحية read)"
                tvLogSub.setTextColor(c("#c26a00"))
            }
            !Shared.logsReady -> { tvLogSub.text = "جارٍ تحميل السجل..."; tvLogSub.setTextColor(c("#64708a")) }
            unread > 0 && lastRed != null -> {
                tvLogSub.text = "🔴 $unread أخطاء جديدة • ${lastRed.time}  ${lastRed.msg}"
                tvLogSub.setTextColor(c("#d6362a"))
            }
            else -> {
                tvLogSub.text = "✅ لا توجد أخطاء جديدة • ${logs.size} سطر — اضغط لعرض السجل كاملاً"
                tvLogSub.setTextColor(c("#0f7a50"))
            }
        }
        tvLogVal.text = if (unread > 0) "🔴 $unread" else "عرض ›"
        tvLogVal.setTextColor(c("#ffffff"))
        tvLogVal.background = if (unread > 0) grad("#ff6a5c", "#d6362a", 14) else grad("#1e6eff", "#0a32be", 14)
        logCard.background = if (unread > 0) grad("#fff1ef", "#ffd9d4", 20) else grad("#ffffff", "#e8f0ff", 20)
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
            setBackgroundColor(c("#EEF3FB"))
            layoutDirection = View.LAYOUT_DIRECTION_RTL
        }
        val head = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL; setPadding(dp(14), dp(10), dp(10), dp(10)); background = grad(NAV1, NAV2, 22) }
        val title = TextView(this).apply {
            text = "📜 سجل الراوتر"; setTextColor(c("#ffffff")); textSize = 18f; setTypeface(null, Typeface.BOLD)
            layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
        }
        head.addView(title)
        head.addView(TextView(this).apply {
            text = "✖ إغلاق"; setTextColor(c("#ffffff")); textSize = 13f
            setPadding(dp(12), dp(6), dp(12), dp(6)); background = grad("#1e6eff", "#0a32be", 14)
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
            setHintTextColor(c("#8a94ab")); setTextColor(c("#1f2a44")); isSingleLine = true; textSize = 14f
            setPadding(dp(12), dp(8), dp(12), dp(8)); background = box("#ffffff", "#c9d6ee", 14)
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
            ch.setTextColor(c(if (on) "#ffffff" else "#1f2a44"))
            ch.background = if (on) grad("#1e6eff", "#0a32be", 14) else grad("#ffffff", "#e8f0ff", 14)
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
                background = if (e.level == 2) grad("#fff1ef", "#ffd0ca", 16) else if (e.level == 1) grad("#fffaf0", "#ffeab8", 16) else grad("#ffffff", "#e8f0ff", 16)
                layoutParams = LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(5) }
            }
            row.addView(TextView(this).apply {
                text = "${e.time}   •   ${e.topics}"
                setTextColor(c("#64708a")); textSize = 11f
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
                background = if (m.up) grad("#18be82", "#109664", 16) else grad("#ff6a5c", "#c82828", 16)
                isClickable = true
                setOnClickListener { pingDialog(m.ip, "فحص المودم: ${m.name} (${m.ip})") }
                layoutParams = LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(6) }
            }
            val dot = if (m.up) "🟢" else "🔴"
            row.addView(TextView(this).apply {
                text = "$dot ${m.name}"
                setTextColor(c("#ffffff"))
                textSize = 14f
                setTypeface(null, Typeface.BOLD)
                layoutParams = LinearLayout.LayoutParams(0, -2, 1f)
            })
            val statusTxt = if (m.up) {
                "<font color='#ffffff'>متصل (${m.ip})</font>"
            } else {
                "<font color='#ffffff'>مقطوع منذ ${ago(m.downSince ?: System.currentTimeMillis())}</font>"
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

        AlertDialog.Builder(this, R.style.NMDialog)
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
                val r = Net.get(prefs)
                val id = r.cmd("/interface/print", "?name=$ifName").firstOrNull()?.get(".id")
                if (id != null) {
                    r.cmd("/interface/set", "=.id=$id", "=disabled=${if (disable) "yes" else "no"}")
                    runOnUiThread { Toast.makeText(this, "تم تحديث حالة $ifName بنجاح", Toast.LENGTH_SHORT).show() }
                }
            } catch (e: Exception) {
                runOnUiThread { Toast.makeText(this, "خطأ: ${e.message}", Toast.LENGTH_LONG).show() }
            }
        }.start()
    }

    private fun restartInterface(ifName: String) {
        Thread {
            try {
                val r = Net.get(prefs)
                val id = r.cmd("/interface/print", "?name=$ifName").firstOrNull()?.get(".id")
                if (id != null) {
                    r.cmd("/interface/set", "=.id=$id", "=disabled=yes")
                    Thread.sleep(1500)
                    r.cmd("/interface/set", "=.id=$id", "=disabled=no")
                    runOnUiThread { Toast.makeText(this, "تم إعادة تشغيل المنفذ $ifName", Toast.LENGTH_SHORT).show() }
                }
            } catch (e: Exception) {
                runOnUiThread { Toast.makeText(this, "خطأ: ${e.message}", Toast.LENGTH_LONG).show() }
            }
        }.start()
    }

    private fun confirmKick(path: String, id: String, name: String) {
        AlertDialog.Builder(this, R.style.NMDialog)
            .setTitle("فصل المتصل")
            .setMessage("هل تريد فصل ($name) ؟")
            .setPositiveButton("نعم، افصل") { _, _ -> kickUser(path, id, name) }
            .setNegativeButton("إلغاء", null)
            .show()
    }

    private fun kickUser(path: String, id: String, name: String) {
        Thread {
            try {
                val r = Net.get(prefs)
                r.cmd(path, "=.id=$id")
                runOnUiThread { Toast.makeText(this, "تم فصل المتصل ($name) بنجاح", Toast.LENGTH_SHORT).show() }
            } catch (e: Exception) {
                runOnUiThread { Toast.makeText(this, "تعذر الفصل: ${e.message}", Toast.LENGTH_LONG).show() }
            }
        }.start()
    }

    private fun pingDialog(address: String, title: String) {
        val pd = AlertDialog.Builder(this, R.style.NMDialog).setTitle(title).setMessage("جارٍ إرسال 4 نبضات Ping إلى $address...").show()
        Thread {
            try {
                val r = Net.get(prefs)
                val res = r.cmd("/ping", "=address=$address", "=count=4")
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
                    AlertDialog.Builder(this, R.style.NMDialog).setTitle(title).setMessage(sb.toString()).setPositiveButton("حسناً", null).show()
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
        AlertDialog.Builder(this, R.style.NMDialog)
            .setTitle("⚠️ تأكيد إعادة تشغيل الراوتر")
            .setMessage("هل أنت متأكد من رغبتك في إعادة تشغيل الميكروتيك الرئيسي الآن؟ سينقطع الاتصال مؤقتاً.")
            .setPositiveButton("نعم، أعد التشغيل") { _, _ ->
                Thread {
                    try {
                        val r = Net.get(prefs)
                        r.cmd("/system/reboot")
                    } catch (e: Exception) { }
                    runOnUiThread { Toast.makeText(this, "تم إرسال أمر إعادة التشغيل للراوتر", Toast.LENGTH_LONG).show() }
                }.start()
            }
            .setNegativeButton("إلغاء", null)
            .show()
    }

    // تطبيق تغيير الراوتر النشط: تصفير الجلسة والحالة وإعادة الاتصال (جلسة واحدة جديدة)
    private fun applyConfigChange() {
        tvTitle.text = "📡 ${netName(prefs)}"
        Net.reset()
        Shared.cfgGen++
        Shared.forceModem = true
        Shared.modemsReady = false
        Shared.error = null
        Shared.snap = null
        Shared.modems = emptyList()
        lastSnap = null; lastModems = null
        startMonitor()
    }

    private fun switchRouter(r: RouterCfg) {
        Routers.applyToCfg(this, r)
        Routers.setActive(this, r.id)
        applyConfigChange()
    }

    // ---------- تحديث التطبيق ----------
    private var updInfo: UpdateInfo? = null
    private var updRow: TextView? = null
    private var updBusy = false

    private fun updateRow(): TextView {
        val v = TextView(this).apply {
            textSize = 12f; gravity = Gravity.CENTER; setPadding(dp(12), dp(8), dp(12), dp(8))
            setTextColor(c("#46618f")); background = grad("#ffffff", "#e8f0ff", 14)
        }
        updRow = v
        renderUpdateRow()
        v.setOnClickListener { onUpdateTap() }
        checkForUpdate(false)
        return v
    }

    private fun renderUpdateRow(msg: String? = null) {
        val v = updRow ?: return
        val cur = Updater.currentVersion(this).second
        val u = updInfo
        if (msg != null) { v.text = msg; return }
        if (u != null) {
            v.text = "⬆ تحديث متوفر: ${u.versionName} (الحالي $cur) - اضغط للتنزيل والتثبيت"
            v.setTextColor(c("#ffffff")); v.background = grad("#1fbf75", "#0e8f55", 14)
        } else {
            v.text = "الإصدار $cur • اضغط للتحقق من التحديث"
            v.setTextColor(c("#46618f")); v.background = grad("#ffffff", "#e8f0ff", 14)
        }
    }

    private fun checkForUpdate(manual: Boolean) {
        if (updBusy) return
        updBusy = true
        if (manual) renderUpdateRow("جارٍ التحقق من التحديث...")
        Thread {
            var err: String? = null
            try { updInfo = Updater.check(this) } catch (e: Exception) { err = e.message ?: "فشل الاتصال" }
            runOnUiThread {
                updBusy = false
                renderUpdateRow()
                if (manual) {
                    if (err != null) Toast.makeText(this, "تعذر التحقق: $err", Toast.LENGTH_LONG).show()
                    else if (updInfo == null) Toast.makeText(this, "أنت على آخر إصدار", Toast.LENGTH_SHORT).show()
                }
            }
        }.start()
    }

    private fun onUpdateTap() {
        val u = updInfo
        if (u == null) { checkForUpdate(true); return }
        if (updBusy) return
        if (!Updater.canInstall(this)) {
            Toast.makeText(this, "فعّل السماح بتثبيت التطبيقات لهذا التطبيق ثم ارجع واضغط تحديث", Toast.LENGTH_LONG).show()
            Updater.openInstallPermission(this); return
        }
        updBusy = true
        Thread {
            try {
                val f = Updater.download(this, u) { p -> runOnUiThread { renderUpdateRow("جارٍ التنزيل... $p%") } }
                runOnUiThread { updBusy = false; renderUpdateRow(); Updater.install(this, f) }
            } catch (e: Exception) {
                runOnUiThread { updBusy = false; renderUpdateRow(); Toast.makeText(this, "فشل التحديث: ${e.message}", Toast.LENGTH_LONG).show() }
            }
        }.start()
    }

    private var routersDlg: android.app.Dialog? = null

    private fun fullDialog(root: View): android.app.Dialog {
        val d = android.app.Dialog(this, android.R.style.Theme_DeviceDefault_Light_NoActionBar)
        d.setContentView(root)
        d.window?.setSoftInputMode(android.view.WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
        return d
    }

    // الشاشة الأولى: قائمة الراوترات المحفوظة (اضغط راوتر للدخول)
    private fun routersScreen() {
        Routers.ensure(this)
        routersDlg?.dismiss()
        val frame = FrameLayout(this).apply { setBackgroundColor(c("#EEF3FB")); layoutDirection = View.LAYOUT_DIRECTION_RTL }
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(14), dp(12), dp(14), dp(12)) }
        val head = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(16), dp(12), dp(12), dp(12)); background = grad(NAV1, NAV2, 24)
        }
        val ht = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; layoutParams = LinearLayout.LayoutParams(0, -2, 1f) }
        ht.addView(TextView(this).apply { text = "Net Microtik Monitor"; setTextColor(c("#ffffff")); textSize = 18f; setTypeface(null, Typeface.BOLD) })
        ht.addView(TextView(this).apply { text = "اختر الراوتر للمراقبة"; setTextColor(c("#b8c6e6")); textSize = 12f })
        head.addView(ht)
        head.addView(TextView(this).apply {
            text = "✖ خروج"; setTextColor(c("#ffffff")); textSize = 13f; setTypeface(null, Typeface.BOLD)
            setPadding(dp(12), dp(6), dp(12), dp(6)); background = grad("#ff6a5c", "#d6362a", 14)
            setOnClickListener { confirmExit() }
        })
        col.addView(head)
        col.addView(updateRow(), LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
        val listBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        col.addView(ScrollView(this).apply { addView(listBox) }, LinearLayout.LayoutParams(-1, 0, 1f).apply { topMargin = dp(10) })
        frame.addView(col, FrameLayout.LayoutParams(-1, -1))
        val d = fullDialog(frame)
        frame.addView(TextView(this).apply {
            text = "+"; textSize = 30f; setTextColor(c("#ffffff")); gravity = Gravity.CENTER
            background = grad("#1e6eff", "#0a32be", 22)
            setOnClickListener { loginPage(null) }
        }, FrameLayout.LayoutParams(dp(64), dp(64), Gravity.BOTTOM or Gravity.LEFT).apply { leftMargin = dp(18); bottomMargin = dp(22) })
        d.setOnKeyListener { _, k, ev -> if (k == android.view.KeyEvent.KEYCODE_BACK && ev.action == android.view.KeyEvent.ACTION_UP) { confirmExit(); true } else k == android.view.KeyEvent.KEYCODE_BACK }
        routersDlg = d
        refreshRoutersScreen(listBox)
        d.show()
    }

    private fun refreshRoutersScreen(box: LinearLayout? = null) {
        val listBox = box ?: ((routersDlg?.window?.decorView?.let { findFirstLinear(it) }) ?: return)
        listBox.removeAllViews()
        val list = Routers.load(this)
        val act = Routers.activeId(this)
        if (list.isEmpty()) note(listBox, "لا توجد راوترات محفوظة. اضغط + لإضافة راوتر.")
        for (r in list) {
            val isAct = r.id == act
            val card = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
                setPadding(dp(14), dp(12), dp(10), dp(12))
                background = if (isAct) grad("#e9fbf3", "#c9f1de", 20) else grad("#ffffff", "#e8f0ff", 20)
                isClickable = true
                setOnClickListener { enterRouter(r) }
            }
            card.addView(TextView(this).apply {
                text = "📡"; textSize = 22f; gravity = Gravity.CENTER; setPadding(dp(10), dp(8), dp(10), dp(8))
                background = grad("#dbe6fb", "#c3d6f7", 16)
            })
            val info = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; layoutParams = LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = dp(10); rightMargin = dp(10) } }
            info.addView(TextView(this).apply { text = r.title() + if (isAct) "  ● مراقَب الآن" else ""; textSize = 16f; setTypeface(null, Typeface.BOLD); setTextColor(c(if (isAct) "#0f7a50" else "#1f2a44")) })
            info.addView(TextView(this).apply { text = "${r.user}@${r.address()}:${r.port}"; textSize = 12f; setTextColor(c("#64708a")); textDirection = View.TEXT_DIRECTION_LTR })
            card.addView(info)
            card.addView(TextView(this).apply {
                text = "✏️"; textSize = 18f; setPadding(dp(10), dp(6), dp(10), dp(6))
                setOnClickListener { loginPage(r.id) }
            })
            card.addView(TextView(this).apply {
                text = "🗑"; textSize = 18f; setPadding(dp(10), dp(6), dp(6), dp(6))
                setOnClickListener { confirmDeleteRouter(r) }
            })
            listBox.addView(card, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = dp(10) })
        }
    }

    private fun findFirstLinear(v: View): LinearLayout? {
        if (v is ScrollView) return v.getChildAt(0) as? LinearLayout
        if (v is ViewGroup) for (i in 0 until v.childCount) findFirstLinear(v.getChildAt(i))?.let { return it }
        return null
    }

    private fun enterRouter(r: RouterCfg) {
        if (r.id != Routers.activeId(this)) switchRouter(r) else { startMonitor(); Shared.forceModem = true }
        routersDlg?.dismiss(); routersDlg = null
        askBatteryExemption(false)
    }

    private fun confirmDeleteRouter(r: RouterCfg) {
        AlertDialog.Builder(this, R.style.NMDialog)
            .setTitle("حذف الراوتر")
            .setMessage("حذف \"${r.title()}\" من القائمة المحفوظة؟")
            .setPositiveButton("حذف") { _, _ ->
                val wasActive = r.id == Routers.activeId(this)
                Routers.remove(this, r.id)
                val rest = Routers.load(this)
                if (wasActive) {
                    if (rest.isNotEmpty()) { Routers.applyToCfg(this, rest[0]); Routers.setActive(this, rest[0].id) }
                    else {
                        prefs.edit().remove("user").remove("pass").remove("local").remove("cloud").apply()
                        Routers.setActive(this, "")
                    }
                    applyConfigChange()
                }
                refreshRoutersScreen()
            }
            .setNegativeButton("إلغاء", null)
            .show()
    }

    private fun lbl(label: String, e: EditText): FrameLayout {
        val fr = FrameLayout(this)
        e.apply { setHintTextColor(c("#a3adc2")); setTextColor(c("#1f2a44")); textSize = 14f; setPadding(dp(12), dp(10), dp(12), dp(8)); background = box("#ffffff", "#9fb3d9", 14) }
        fr.addView(e, FrameLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
        fr.addView(TextView(this).apply {
            text = label; textSize = 11f; setTextColor(c("#1e6eff")); setBackgroundColor(c("#EEF3FB")); setPadding(dp(4), 0, dp(4), 0)
        }, FrameLayout.LayoutParams(-2, -2, Gravity.TOP or Gravity.START).apply { marginStart = dp(12) })
        return fr
    }

    private fun pageShell(title: String, onClose: () -> Unit): Pair<LinearLayout, LinearLayout> {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(12), dp(10), dp(12), dp(10))
            setBackgroundColor(c("#EEF3FB")); layoutDirection = View.LAYOUT_DIRECTION_RTL
        }
        val head = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(14), dp(8), dp(10), dp(8)); background = grad(NAV1, NAV2, 22)
        }
        head.addView(TextView(this).apply { text = title; setTextColor(c("#ffffff")); textSize = 16f; setTypeface(null, Typeface.BOLD); layoutParams = LinearLayout.LayoutParams(0, -2, 1f) })
        head.addView(TextView(this).apply {
            text = "✖"; setTextColor(c("#ffffff")); textSize = 13f
            setPadding(dp(12), dp(5), dp(12), dp(5)); background = grad("#1e6eff", "#0a32be", 14)
            setOnClickListener { onClose() }
        })
        root.addView(head)
        return root to root
    }

    private fun addRow(root: LinearLayout, vararg cols: View, weights: FloatArray? = null) {
        val r = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        cols.forEachIndexed { i, cl -> r.addView(cl, LinearLayout.LayoutParams(0, -2, weights?.get(i) ?: 1f).apply { if (i > 0) leftMargin = dp(8) }) }
        root.addView(r, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
    }

    private fun saveButtons(root: LinearLayout, d: android.app.Dialog, label: String, onSave: () -> Unit) {
        val btns = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        btns.addView(TextView(this).apply {
            text = label; setTextColor(c("#ffffff")); textSize = 15f; gravity = Gravity.CENTER; setTypeface(null, Typeface.BOLD)
            setPadding(0, dp(12), 0, dp(12)); background = grad("#18be82", "#109664", 16)
            setOnClickListener { onSave() }
        }, LinearLayout.LayoutParams(0, -2, 2f))
        btns.addView(TextView(this).apply {
            text = "إلغاء"; setTextColor(c("#1f2a44")); textSize = 15f; gravity = Gravity.CENTER
            setPadding(0, dp(12), 0, dp(12)); background = grad("#ffffff", "#dbe6fb", 16)
            setOnClickListener { d.dismiss() }
        }, LinearLayout.LayoutParams(0, -2, 1f).apply { leftMargin = dp(8) })
        root.addView(btns, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(14) })
    }

    // صفحة تسجيل الدخول: راوتر جديد (editId = null) أو تعديل بيانات راوتر محفوظ. بدون مودمات ولا تنبيهات.
    private fun loginPage(editId: String?) {
        val old = if (editId != null) Routers.load(this).firstOrNull { it.id == editId } else null
        lateinit var d: android.app.Dialog
        val (root, _) = pageShell(if (old == null) "➕ إضافة راوتر" else "✏️ تعديل الراوتر") { d.dismiss() }
        fun ed(v: String, hint: String, pwd: Boolean = false) = EditText(this).apply { setText(v); this.hint = hint; isSingleLine = true; if (pwd) inputType = 129 }
        val eName = ed(old?.name ?: "", "شبكة النور")
        val eLocal = ed((old?.local ?: "").ifBlank { old?.cloud ?: "" }, "192.168.88.1 أو xxxx.sn.mynetname.net")
        val eUser = ed(old?.user ?: "", "admin")
        val ePass = ed(old?.pass ?: "", "", true)
        val ePort = ed(old?.port ?: "8728", "8728")
        addRow(root, lbl("🏷️ اسم الراوتر", eName))
        addRow(root, lbl("عنوان الراوتر (IP أو كلاود DNS)", eLocal))
        addRow(root, lbl("اسم المستخدم", eUser), lbl("منفذ API", ePort), weights = floatArrayOf(2f, 1f))
        addRow(root, lbl("كلمة المرور", ePass))
        val cbRemember = CheckBox(this).apply { text = "🔐 حفظ بيانات الدخول"; textSize = 14f; setTextColor(c("#1f2a44")); isChecked = prefs.getBoolean("remember", true) }
        root.addView(LinearLayout(this).apply {
            setPadding(dp(10), dp(4), dp(10), dp(4)); background = grad("#ffffff", "#e8f0ff", 16); addView(cbRemember)
        }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) })
        d = fullDialog(root)
        saveButtons(root, d, "حفظ") {
            val local = eLocal.text.toString().trim(); val cloud = if (old?.local.isNullOrBlank()) "" else (old?.cloud ?: "")
            if (local.isEmpty() && cloud.isEmpty() || eUser.text.isNullOrBlank()) {
                Toast.makeText(this, "أدخل العنوان واسم المستخدم", Toast.LENGTH_LONG).show(); return@saveButtons
            }
            val keep = cbRemember.isChecked
            prefs.edit().putBoolean("remember", keep).apply()
            val r = RouterCfg(old?.id ?: Routers.newId(), eName.text.toString().trim(), local, cloud,
                ePort.text.toString().trim().ifEmpty { "8728" }, eUser.text.toString().trim(),
                if (keep) ePass.text.toString() else "", old?.wan ?: "ether1", old?.modems ?: "", old?.nErr ?: true, old?.nWarn ?: false)
            // لو ما حفظنا كلمة المرور، نبقيها بالذاكرة للراوتر الحالي حتى يتصل
            Routers.upsert(this, r)
            d.dismiss()
            if (old == null) {
                // راوتر جديد: ندخل عليه مباشرة بكلمة المرور المكتوبة
                val live = RouterCfg(r.id, r.name, r.local, r.cloud, r.port, r.user, ePass.text.toString(), r.wan, r.modems, r.nErr, r.nWarn)
                Routers.setActive(this, r.id); Routers.applyToCfg(this, live); applyConfigChange()
                routersDlg?.dismiss(); routersDlg = null
                askBatteryExemption(false)
            } else {
                if (r.id == Routers.activeId(this)) { Routers.applyToCfg(this, RouterCfg(r.id, r.name, r.local, r.cloud, r.port, r.user, ePass.text.toString(), r.wan, r.modems, r.nErr, r.nWarn)); applyConfigChange() }
                refreshRoutersScreen()
            }
        }
        d.show()
    }

    // إعدادات الراوتر الحالي داخل اللوحة: المودمات + واجهة الإنترنت + التنبيهات
    private fun settings() {
        Routers.ensure(this)
        lateinit var d: android.app.Dialog
        val (root, _) = pageShell("⚙️ إعدادات ${netName(prefs)}") { d.dismiss() }
        val eWan = EditText(this).apply { setText(prefs.getString("wan", "ether1") ?: "ether1"); hint = "ether1"; isSingleLine = true }
        val eModems = EditText(this).apply {
            setText(prefs.getString("modems", "") ?: ""); hint = "90.90.2.2 شيبان"
            isSingleLine = false; minLines = 6; maxLines = 8; gravity = Gravity.TOP or Gravity.START
        }
        addRow(root, lbl("واجهة الإنترنت (WAN)", eWan))
        addRow(root, lbl("المودمات: سطر لكل مودم (IP ثم الاسم)", eModems))
        val cbErr = CheckBox(this).apply { text = "🔴 إشعار فوري عند أي خطأ أحمر في السجل"; textSize = 13f; setTextColor(c("#1f2a44")); isChecked = prefs.getBoolean("notif_err", true) }
        val cbWarn = CheckBox(this).apply { text = "🟡 إشعار للتحذيرات الصفراء أيضاً"; textSize = 13f; setTextColor(c("#1f2a44")); isChecked = prefs.getBoolean("notif_warn", false) }
        root.addView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(dp(10), dp(4), dp(10), dp(4)); background = grad("#ffffff", "#e8f0ff", 16)
            addView(cbErr); addView(cbWarn)
        }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10) })
        d = fullDialog(root)
        saveButtons(root, d, "حفظ") {
            prefs.edit().putString("wan", eWan.text.toString().trim().ifEmpty { "ether1" }).putString("modems", eModems.text.toString().trim())
                .putBoolean("notif_err", cbErr.isChecked).putBoolean("notif_warn", cbWarn.isChecked).apply()
            val id = Routers.activeId(this)
            if (id.isNotEmpty()) {
                val keepPass = prefs.getBoolean("remember", true)
                val cur = Routers.load(this).firstOrNull { it.id == id }
                val upd = Routers.fromCfg(this, id, true)
                if (cur != null && !keepPass) upd.pass = cur.pass else if (!keepPass) upd.pass = ""
                Routers.upsert(this, upd)
            }
            Shared.cfgGen++; Shared.forceModem = true; Shared.modemsReady = false; Shared.modems = emptyList(); lastModems = null
            startMonitor()
            d.dismiss()
        }
        d.show()
    }

}

package net.netmonitor.app

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.database.Cursor
import android.net.Uri
import android.os.Build
import android.os.ParcelFileDescriptor
import android.provider.Settings
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

class UpdateInfo(val versionCode: Int, val versionName: String, val apkUrl: String, val sha256: String, val notes: String)

/** تحديث التطبيق من ملف manifest عام (لا يُنشر شيء إلا بموافقة المستخدم). */
object Updater {
    const val MANIFEST_URL = "https://raw.githubusercontent.com/haitham266/NetMonitor-updates/main/update.json"

    fun currentVersion(ctx: Context): Pair<Int, String> {
        val pi = ctx.packageManager.getPackageInfo(ctx.packageName, 0)
        @Suppress("DEPRECATION")
        val code = if (Build.VERSION.SDK_INT >= 28) pi.longVersionCode.toInt() else pi.versionCode
        return Pair(code, pi.versionName ?: "")
    }

    private fun open(url: String): HttpURLConnection {
        val c = URL(url).openConnection() as HttpURLConnection
        c.connectTimeout = 10000; c.readTimeout = 20000; c.instanceFollowRedirects = true
        return c
    }

    /** يرجع UpdateInfo إذا وُجد إصدار أحدث لنفس الحزمة، وإلا null. يرمي استثناء عند فشل الاتصال. */
    fun check(ctx: Context, manifestUrl: String = MANIFEST_URL): UpdateInfo? {
        val c = open(manifestUrl)
        try {
            if (c.responseCode != 200) throw RuntimeException("HTTP ${c.responseCode}")
            val j = JSONObject(c.inputStream.bufferedReader().readText())
            val pkg = j.optString("package", "")
            if (pkg.isNotEmpty() && pkg != ctx.packageName) return null
            val code = j.getInt("versionCode")
            if (code <= currentVersion(ctx).first) return null
            val url = j.getString("apkUrl")
            if (!url.startsWith("https://")) return null
            return UpdateInfo(code, j.optString("versionName", code.toString()), url, j.optString("sha256", "").lowercase(), j.optString("notes", ""))
        } finally { c.disconnect() }
    }

    fun updatesDir(ctx: Context): File = File(ctx.cacheDir, "updates").apply { mkdirs() }

    /** ينزّل الـ APK ويتحقق من sha256 (إلزامي). onProgress(0..100) */
    fun download(ctx: Context, info: UpdateInfo, onProgress: (Int) -> Unit): File {
        if (info.sha256.length != 64) throw RuntimeException("manifest بدون بصمة sha256")
        val dir = updatesDir(ctx)
        dir.listFiles()?.forEach { it.delete() }
        val out = File(dir, "update.apk")
        val c = open(info.apkUrl)
        try {
            if (c.responseCode != 200) throw RuntimeException("HTTP ${c.responseCode}")
            val total = c.contentLength.toLong()
            val md = MessageDigest.getInstance("SHA-256")
            var done = 0L; var last = -1
            c.inputStream.use { ins ->
                out.outputStream().use { os ->
                    val buf = ByteArray(32768)
                    while (true) {
                        val n = ins.read(buf); if (n < 0) break
                        os.write(buf, 0, n); md.update(buf, 0, n); done += n
                        if (total > 0) { val p = (done * 100 / total).toInt(); if (p != last) { last = p; onProgress(p) } }
                    }
                }
            }
            val hex = md.digest().joinToString("") { "%02x".format(it) }
            if (hex != info.sha256) { out.delete(); throw RuntimeException("البصمة غير مطابقة، أُلغي التحديث") }
        } finally { c.disconnect() }
        return out
    }

    fun canInstall(ctx: Context): Boolean = Build.VERSION.SDK_INT < 26 || ctx.packageManager.canRequestPackageInstalls()

    fun openInstallPermission(ctx: Context) {
        ctx.startActivity(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${ctx.packageName}")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }

    fun install(ctx: Context, apk: File) {
        val uri = Uri.parse("content://${ctx.packageName}.updates/update.apk")
        val i = Intent(Intent.ACTION_VIEW).setDataAndType(uri, "application/vnd.android.package-archive")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        ctx.startActivity(i)
    }
}

/** يقدّم ملف التحديث فقط (قراءة) لمثبّت الحزم. */
class UpdateProvider : ContentProvider() {
    override fun onCreate() = true
    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        val f = File(Updater.updatesDir(context!!), "update.apk")
        if (uri.lastPathSegment != "update.apk" || !f.exists()) throw java.io.FileNotFoundException()
        return ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY)
    }
    override fun getType(uri: Uri) = "application/vnd.android.package-archive"
    override fun query(u: Uri, p: Array<out String>?, s: String?, a: Array<out String>?, o: String?): Cursor? = null
    override fun insert(u: Uri, v: ContentValues?): Uri? = null
    override fun delete(u: Uri, s: String?, a: Array<out String>?) = 0
    override fun update(u: Uri, v: ContentValues?, s: String?, a: Array<out String>?) = 0
}

package uts.sdk.modules.csTransport

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import io.dcloud.uts.UTSAndroid
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicBoolean

/** Staying alive while this phone is the one being connected to (spec §6).
 *
 *  A receiver has no words to say about itself, it only answers, and Android reads that as something to
 *  freeze: once this app leaves the foreground the kernel can stop handing it the peer's next 4 MiB body,
 *  and the peer's honest verdict is then `对端没答话`. The contract's answer for Android is a foreground
 *  service of the data-transfer type, so the system sees a notification it can show and keeps the process
 *  scheduled. Nothing here touches the protocol; it only keeps the owner of the socket running.
 *
 *  Three things can stop that from being true on a given install, and this file reads each of them off
 *  the device instead of assuming it: the component has to be in the *installed package's* manifest
 *  (DCloud's 标准调试基座 is somebody else's APK and has no slot for it), Android 14 refuses a foreground
 *  type whose permission the package does not hold, and the notification itself is a 13+ runtime
 *  permission. What `begin` returns is whichever of those it found, so the card can say why it is still
 *  asking the user to keep 传书 in the foreground. */
class CsKeepAliveService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val text = intent?.getStringExtra(EXTRA_TEXT) ?: DEFAULT_TEXT
        return try {
            post(text)
            CsKeepAlive.started.set(true)
            // START_NOT_STICKY on purpose. After the system kills this process there is no listener, no
            // pair code in memory and no roster loaded; a peer that still holds this device's broadcast
            // would be talking to a half-built app. The card re-arms keep-alive when the user opens it.
            START_NOT_STICKY
        } catch (e: Throwable) {
            CsKeepAlive.refusal = e.toString()
            CsKeepAlive.started.set(false)
            stopSelf()
            START_NOT_STICKY
        }
    }

    override fun onDestroy() {
        CsKeepAlive.started.set(false)
    }

    private fun post(text: String) {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(CsKeepAlive.CHANNEL, "传书接收", NotificationManager.IMPORTANCE_LOW)
                    .apply { setShowBadge(false) }
            )
        }
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CsKeepAlive.CHANNEL)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        val notification = builder
            .setContentTitle("传书在收")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setOngoing(true)
            .build()
        // The type is an Android 14 rule, and on 29-33 that constant is not a type the OS knows, so the
        // older two-argument call is what those releases get.
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(CsKeepAlive.NOTIFICATION, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(CsKeepAlive.NOTIFICATION, notification)
        }
    }
}

private const val EXTRA_TEXT = "text"
private const val DEFAULT_TEXT = "传书正在监听对端发来"

object CsKeepAlive {

    internal const val CHANNEL = "chuanshu-receive"
    internal const val NOTIFICATION = 43720

    internal val started = AtomicBoolean(false)

    @Volatile
    internal var refusal = ""

    /** `begin` is only called while this app is in the foreground, which is also the condition Android 12
     *  puts on starting a foreground service from an app - so the caller does not have to know that rule,
     *  it only has to read back the answer.
     *
     *  The answer is `{ok, note}`, the same shape every other entry in this plugin returns: the card has
     *  to promise one thing or the other, and reading that off a sentence would make the UI's promise a
     *  string match on this file's wording. */
    fun begin(text: String): String {
        refusal = ""
        val context = UTSAndroid.getAppContext()
        if (context == null) {
            return answer(false, "拿不到本机上下文，保活没挂上")
        }
        if (!declared(context)) {
            return answer(false, "这个包的清单里没有保活服务这一项，所以保活挂不上：它要打进自定义基座才生效")
        }
        val gone = missingPermissions(context)
        if (gone != "") {
            return answer(false, "保活缺系统权限：$gone")
        }
        val intent = Intent(context, CsKeepAliveService::class.java).putExtra(EXTRA_TEXT, text)
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
            settle()
        } catch (e: Throwable) {
            answer(false, "保活没挂上：$e")
        }
    }

    /** Closing the listener closes the promise too: stop the component so the OS may freeze us again, and
     *  cancel the row so no stale 正在监听 outlives the socket. */
    fun end(): String {
        val context = UTSAndroid.getAppContext() ?: return "拿不到本机上下文"
        val was = started.get()
        try {
            context.stopService(Intent(context, CsKeepAliveService::class.java))
        } catch (e: Throwable) {
            return "保活没能收回：$e"
        }
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
        manager?.cancel(NOTIFICATION)
        started.set(false)
        return if (was) "保活已收回" else "本来就没有保活挂着"
    }

    private fun declared(context: Context): Boolean = try {
        context.packageManager.getServiceInfo(ComponentName(context, CsKeepAliveService::class.java), 0)
        true
    } catch (e: Throwable) {
        // NameNotFoundException: the class is in the dex, the manifest entry is not in this package.
        false
    }

    /** Read off the *installed* package, because on a debug base the permissions that arrive are not the
     *  ones this plugin asked for. Below 23 these are install-time grants, so nothing is ever missing. */
    private fun missingPermissions(context: Context): String {
        if (Build.VERSION.SDK_INT < 23) {
            return ""
        }
        val want = mutableListOf("android.permission.FOREGROUND_SERVICE")
        if (Build.VERSION.SDK_INT >= 34) {
            want.add("android.permission.FOREGROUND_SERVICE_DATA_SYNC")
        }
        if (Build.VERSION.SDK_INT >= 33) {
            want.add("android.permission.POST_NOTIFICATIONS")
        }
        val gone = want.filter {
            context.checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED
        }
        return gone.joinToString("、")
    }

    /** `startForegroundService` is a request, not a done deal: the service has to come up and call
     *  startForeground within the OS's window. Polling for that here is what lets the store report the
     *  refusal in the same tap that asked for it, instead of one tick later. */
    private fun settle(): String {
        var waited = 0
        while (!started.get() && waited < 1500) {
            try {
                Thread.sleep(50)
            } catch (e: InterruptedException) {
                break
            }
            waited += 50
        }
        if (started.get()) {
            return answer(true, "保活挂上了（前台服务，收在做什么写在通知里）")
        }
        return answer(false, if (refusal == "") "保活没挂上：那个服务没有起来" else "保活没挂上：$refusal")
    }

    private fun answer(ok: Boolean, note: String): String =
        JSONObject().put("ok", ok).put("note", note).toString()
}

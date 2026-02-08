package com.vault.push

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import com.vault.VaultAuth
import com.vault.models.VaultAuthException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Push notification types
 */
enum class PushNotificationType {
    MFA_REQUEST,
    SESSION_REVOKED,
    PASSWORD_CHANGED,
    SECURITY_ALERT,
    GENERAL
}

/**
 * MFA push request data
 */
data class MfaPushRequestData(
    val requestId: String,
    val deviceName: String? = null,
    val location: String? = null,
    val ipAddress: String? = null,
    val timestamp: Long = System.currentTimeMillis()
)

/**
 * Push notification manager for handling Vault push notifications
 */
class PushNotificationManager(private val context: Context) {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    companion object {
        const val CHANNEL_ID_MFA = "vault_mfa"
        const val CHANNEL_ID_SECURITY = "vault_security"
        const val CHANNEL_ID_GENERAL = "vault_general"
        
        const val NOTIFICATION_ID_MFA = 1001
        const val NOTIFICATION_ID_SECURITY = 1002
        const val NOTIFICATION_ID_GENERAL = 1003
        
        // Intent actions
        const val ACTION_APPROVE_MFA = "com.vault.action.APPROVE_MFA"
        const val ACTION_DENY_MFA = "com.vault.action.DENY_MFA"
        const val EXTRA_REQUEST_ID = "request_id"
    }

    init {
        createNotificationChannels()
    }

    /**
     * Create notification channels (required for Android O+)
     */
    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            // MFA channel
            val mfaChannel = NotificationChannel(
                CHANNEL_ID_MFA,
                "MFA Requests",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Multi-factor authentication requests"
                enableVibration(true)
                enableLights(true)
            }

            // Security channel
            val securityChannel = NotificationChannel(
                CHANNEL_ID_SECURITY,
                "Security Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Security-related notifications"
                enableVibration(true)
                enableLights(true)
            }

            // General channel
            val generalChannel = NotificationChannel(
                CHANNEL_ID_GENERAL,
                "General",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "General notifications"
            }

            notificationManager.createNotificationChannels(
                listOf(mfaChannel, securityChannel, generalChannel)
            )
        }
    }

    /**
     * Register device for push notifications
     * 
     * @param token FCM registration token
     */
    fun registerDevice(token: String) {
        scope.launch {
            try {
                VaultAuth.getInstance().registerForPushNotifications(token)
            } catch (e: VaultAuthException) {
                // Log error but don't crash
            }
        }
    }

    /**
     * Handle incoming push notification
     * 
     * @param data The notification data payload
     */
    fun handleNotification(data: Map<String, String>) {
        val type = data["type"] ?: return
        
        when (type) {
            "mfa_request" -> handleMfaRequest(data)
            "session_revoked" -> handleSessionRevoked(data)
            "password_changed" -> handlePasswordChanged(data)
            "security_alert" -> handleSecurityAlert(data)
            else -> handleGeneralNotification(data)
        }
    }

    /**
     * Handle MFA push notification
     */
    private fun handleMfaRequest(data: Map<String, String>) {
        val requestId = data["request_id"] ?: return
        val deviceName = data["device_name"]
        val location = data["location"]
        val ipAddress = data["ip_address"]

        val title = "Sign-in Request"
        val content = buildString {
            append("Approve sign-in from ")
            append(deviceName ?: "Unknown device")
            location?.let { append(" in $it") }
        }

        // Approve action
        val approveIntent = Intent(context, PushActionReceiver::class.java).apply {
            action = ACTION_APPROVE_MFA
            putExtra(EXTRA_REQUEST_ID, requestId)
        }
        val approvePendingIntent = PendingIntent.getBroadcast(
            context,
            requestId.hashCode(),
            approveIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        // Deny action
        val denyIntent = Intent(context, PushActionReceiver::class.java).apply {
            action = ACTION_DENY_MFA
            putExtra(EXTRA_REQUEST_ID, requestId)
        }
        val denyPendingIntent = PendingIntent.getBroadcast(
            context,
            requestId.hashCode() + 1,
            denyIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(context, CHANNEL_ID_MFA)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle(title)
            .setContentText(content)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setAutoCancel(true)
            .addAction(android.R.drawable.ic_media_play, "Approve", approvePendingIntent)
            .addAction(android.R.drawable.ic_media_pause, "Deny", denyPendingIntent)
            .build()

        notificationManager.notify(requestId.hashCode(), notification)
    }

    /**
     * Handle session revoked notification
     */
    private fun handleSessionRevoked(data: Map<String, String>) {
        val deviceName = data["device_name"] ?: "Another device"
        
        val notification = NotificationCompat.Builder(context, CHANNEL_ID_SECURITY)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("Session Ended")
            .setContentText("Your session was ended from $deviceName")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_SECURITY)
            .setAutoCancel(true)
            .build()

        notificationManager.notify(NOTIFICATION_ID_SECURITY, notification)
    }

    /**
     * Handle password changed notification
     */
    private fun handlePasswordChanged(data: Map<String, String>) {
        val notification = NotificationCompat.Builder(context, CHANNEL_ID_SECURITY)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("Password Changed")
            .setContentText("Your password was changed successfully")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_SECURITY)
            .setAutoCancel(true)
            .build()

        notificationManager.notify(NOTIFICATION_ID_SECURITY + 1, notification)
    }

    /**
     * Handle security alert notification
     */
    private fun handleSecurityAlert(data: Map<String, String>) {
        val title = data["title"] ?: "Security Alert"
        val message = data["message"] ?: "A security-related event occurred"

        val notification = NotificationCompat.Builder(context, CHANNEL_ID_SECURITY)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(title)
            .setContentText(message)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_SECURITY)
            .setAutoCancel(true)
            .build()

        notificationManager.notify(NOTIFICATION_ID_SECURITY + 2, notification)
    }

    /**
     * Handle general notification
     */
    private fun handleGeneralNotification(data: Map<String, String>) {
        val title = data["title"] ?: "Vault"
        val message = data["message"] ?: ""

        val notification = NotificationCompat.Builder(context, CHANNEL_ID_GENERAL)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle(title)
            .setContentText(message)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .build()

        notificationManager.notify(NOTIFICATION_ID_GENERAL, notification)
    }

    /**
     * Approve an MFA request via push notification
     * 
     * @param requestId The MFA request ID
     */
    suspend fun approveMfaRequest(requestId: String) {
        VaultAuth.getInstance().approveMfaRequest(requestId)
        notificationManager.cancel(requestId.hashCode())
    }

    /**
     * Deny an MFA request via push notification
     * 
     * @param requestId The MFA request ID
     */
    suspend fun denyMfaRequest(requestId: String) {
        VaultAuth.getInstance().denyMfaRequest(requestId)
        notificationManager.cancel(requestId.hashCode())
    }

    /**
     * Cancel a notification
     * 
     * @param notificationId The notification ID
     */
    fun cancelNotification(notificationId: Int) {
        notificationManager.cancel(notificationId)
    }

    /**
     * Cancel all notifications
     */
    fun cancelAllNotifications() {
        notificationManager.cancelAll()
    }
}

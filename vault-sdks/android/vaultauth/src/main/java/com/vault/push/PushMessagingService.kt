package com.vault.push

import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import com.vault.VaultAuth

/**
 * Firebase Messaging Service for handling Vault push notifications
 * 
 * To use this service, add the following to your AndroidManifest.xml:
 * 
 * ```xml
 * <service
 *     android:name="com.vault.push.VaultMessagingService"
 *     android:exported="false">
 *     <intent-filter>
 *         <action android:name="com.google.firebase.MESSAGING_EVENT" />
 *     </intent-filter>
 * </service>
 * ```
 * 
 * Also ensure you have Firebase configured in your project.
 */
open class VaultMessagingService : FirebaseMessagingService() {

    private lateinit var pushManager: PushNotificationManager

    override fun onCreate() {
        super.onCreate()
        pushManager = PushNotificationManager(applicationContext)
    }

    /**
     * Called when a new FCM token is generated
     * This happens when:
     * - The app is installed
     * - The app is restored on a new device
     * - The user uninstalls/reinstalls the app
     * - The user clears app data
     */
    override fun onNewToken(token: String) {
        super.onNewToken(token)
        
        // Register the new token with Vault
        if (VaultAuth.getInstance().isConfigured()) {
            pushManager.registerDevice(token)
        }
    }

    /**
     * Called when a message is received
     * This is called for both notification and data messages
     */
    override fun onMessageReceived(message: RemoteMessage) {
        super.onMessageReceived(message)

        // Handle data payload
        val data = message.data
        if (data.isNotEmpty()) {
            pushManager.handleNotification(data)
        }

        // Handle notification payload (when app is in foreground)
        message.notification?.let { notification ->
            // If it's a Vault notification, handle it
            if (isVaultNotification(notification)) {
                val vaultData = mutableMapOf<String, String>()
                vaultData["type"] = data["type"] ?: "general"
                vaultData["title"] = notification.title ?: ""
                vaultData["message"] = notification.body ?: ""
                vaultData.putAll(data)
                
                pushManager.handleNotification(vaultData)
            }
        }
    }

    /**
     * Called when there is an error sending an upstream message
     */
    override fun onSendError(msgId: String, exception: Exception) {
        super.onSendError(msgId, exception)
        // Log the error but don't crash
    }

    /**
     * Called when a message was successfully sent upstream
     */
    override fun onMessageSent(msgId: String) {
        super.onMessageSent(msgId)
    }

    /**
     * Called when the app is deleted from the device
     */
    override fun onDeletedMessages() {
        super.onDeletedMessages()
    }

    /**
     * Check if this is a Vault notification
     */
    private fun isVaultNotification(notification: RemoteMessage.Notification): Boolean {
        // You can identify Vault notifications by their title, data, or channel
        return notification.channelId?.startsWith("vault_") == true
    }

    /**
     * Get the PushNotificationManager for handling notifications
     */
    protected fun getPushManager(): PushNotificationManager = pushManager
}

/**
 * Push action receiver for handling notification actions (Approve/Deny)
 */
class PushActionReceiver : android.content.BroadcastReceiver() {
    
    override fun onReceive(context: android.content.Context, intent: android.content.Intent) {
        val requestId = intent.getStringExtra(PushNotificationManager.EXTRA_REQUEST_ID) ?: return
        
        kotlinx.coroutines.GlobalScope.launch(kotlinx.coroutines.Dispatchers.IO) {
            try {
                val pushManager = PushNotificationManager(context)
                
                when (intent.action) {
                    PushNotificationManager.ACTION_APPROVE_MFA -> {
                        pushManager.approveMfaRequest(requestId)
                    }
                    PushNotificationManager.ACTION_DENY_MFA -> {
                        pushManager.denyMfaRequest(requestId)
                    }
                }
            } catch (e: Exception) {
                // Log error but don't crash
            }
        }
    }
}

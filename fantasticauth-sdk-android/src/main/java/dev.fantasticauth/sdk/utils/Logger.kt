package dev.vault.sdk.utils

import android.util.Log
import dev.vault.sdk.BuildConfig

/**
 * Internal logger for Vault SDK
 * Uses Android Log with SDK tag prefix
 */
internal object VaultLogger {
    
    private const val TAG_PREFIX = "VaultSDK"
    
    @Volatile
    private var isEnabled = BuildConfig.DEBUG
    
    @Volatile
    private var logLevel = LogLevel.DEBUG
    
    /**
     * Log levels
     */
    enum class LogLevel {
        VERBOSE,
        DEBUG,
        INFO,
        WARN,
        ERROR,
        NONE
    }
    
    /**
     * Configure logger
     * 
     * @param enabled Whether logging is enabled
     * @param level Minimum log level
     */
    fun configure(enabled: Boolean, level: LogLevel = LogLevel.DEBUG) {
        isEnabled = enabled
        logLevel = level
    }
    
    /**
     * Verbose log
     */
    fun v(message: String, throwable: Throwable? = null) {
        log(LogLevel.VERBOSE, message, throwable)
    }
    
    /**
     * Debug log
     */
    fun d(message: String, throwable: Throwable? = null) {
        log(LogLevel.DEBUG, message, throwable)
    }
    
    /**
     * Info log
     */
    fun i(message: String, throwable: Throwable? = null) {
        log(LogLevel.INFO, message, throwable)
    }
    
    /**
     * Warning log
     */
    fun w(message: String, throwable: Throwable? = null) {
        log(LogLevel.WARN, message, throwable)
    }
    
    /**
     * Error log
     */
    fun e(message: String, throwable: Throwable? = null) {
        log(LogLevel.ERROR, message, throwable)
    }
    
    private fun log(level: LogLevel, message: String, throwable: Throwable?) {
        if (!isEnabled || level.ordinal < logLevel.ordinal) {
            return
        }
        
        val fullMessage = "[$TAG_PREFIX] $message"
        
        when (level) {
            LogLevel.VERBOSE -> {
                if (throwable != null) {
                    Log.v(TAG_PREFIX, message, throwable)
                } else {
                    Log.v(TAG_PREFIX, message)
                }
            }
            LogLevel.DEBUG -> {
                if (throwable != null) {
                    Log.d(TAG_PREFIX, message, throwable)
                } else {
                    Log.d(TAG_PREFIX, message)
                }
            }
            LogLevel.INFO -> {
                if (throwable != null) {
                    Log.i(TAG_PREFIX, message, throwable)
                } else {
                    Log.i(TAG_PREFIX, message)
                }
            }
            LogLevel.WARN -> {
                if (throwable != null) {
                    Log.w(TAG_PREFIX, message, throwable)
                } else {
                    Log.w(TAG_PREFIX, message)
                }
            }
            LogLevel.ERROR -> {
                if (throwable != null) {
                    Log.e(TAG_PREFIX, message, throwable)
                } else {
                    Log.e(TAG_PREFIX, message)
                }
            }
            LogLevel.NONE -> { /* No-op */ }
        }
    }
}

/**
 * Public logging interface for SDK consumers
 */
interface VaultLogListener {
    fun onLog(level: LogLevel, message: String, throwable: Throwable?)
    
    enum class LogLevel {
        VERBOSE, DEBUG, INFO, WARN, ERROR
    }
}

/**
 * Configure external log listener
 */
object VaultLogging {
    private var listener: VaultLogListener? = null
    
    /**
     * Set a log listener to receive SDK logs
     * 
     * @param logListener Listener or null to disable
     */
    fun setLogListener(logListener: VaultLogListener?) {
        listener = logListener
    }
    
    internal fun notify(level: VaultLogListener.LogLevel, message: String, throwable: Throwable?) {
        listener?.onLog(level, message, throwable)
    }
}

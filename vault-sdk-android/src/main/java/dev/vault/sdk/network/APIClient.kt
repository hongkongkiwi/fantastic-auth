package dev.vault.sdk.network

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.reflect.TypeToken
import dev.vault.sdk.VaultConfig
import dev.vault.sdk.utils.VaultLogger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.*
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.logging.HttpLoggingInterceptor
import java.io.IOException
import java.util.Date
import java.util.concurrent.TimeUnit

/**
 * HTTP client for Vault API
 */
internal class APIClient private constructor(private val config: VaultConfig) {
    
    private val client: OkHttpClient
    private val gson: Gson
    private var organizationId: String? = null
    
    companion object {
        @Volatile
        private var instance_: APIClient? = null
        
        val instance: APIClient
            get() = instance_ ?: throw IllegalStateException("APIClient not initialized")
        
        fun initialize(config: VaultConfig) {
            instance_ = APIClient(config)
        }
        
        fun reset() {
            instance_ = null
        }
    }
    
    init {
        gson = GsonBuilder()
            .setDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
            .create()
        
        val loggingInterceptor = HttpLoggingInterceptor { message ->
            VaultLogger.d("HTTP: $message")
        }.apply {
            level = if (dev.vault.sdk.BuildConfig.DEBUG) {
                HttpLoggingInterceptor.Level.BODY
            } else {
                HttpLoggingInterceptor.Level.NONE
            }
        }
        
        client = OkHttpClient.Builder()
            .connectTimeout(config.timeout, TimeUnit.SECONDS)
            .readTimeout(config.timeout, TimeUnit.SECONDS)
            .writeTimeout(config.timeout, TimeUnit.SECONDS)
            .addInterceptor(AuthInterceptor())
            .addInterceptor(TenantInterceptor(config.tenantId))
            .addInterceptor(loggingInterceptor)
            .build()
    }
    
    /**
     * Set organization ID for subsequent requests
     */
    fun setOrganizationId(orgId: String) {
        organizationId = orgId
    }
    
    /**
     * Clear organization ID
     */
    fun clearOrganizationId() {
        organizationId = null
    }
    
    /**
     * Execute GET request
     */
    suspend inline fun <reified T> get(endpoint: String): T {
        return request("GET", endpoint, null)
    }
    
    /**
     * Execute POST request
     */
    suspend inline fun <reified B, reified T> post(endpoint: String, body: B): T {
        return request("POST", endpoint, body)
    }
    
    /**
     * Execute PUT request
     */
    suspend inline fun <reified B, reified T> put(endpoint: String, body: B): T {
        return request("PUT", endpoint, body)
    }
    
    /**
     * Execute PATCH request
     */
    suspend inline fun <reified B, reified T> patch(endpoint: String, body: B): T {
        return request("PATCH", endpoint, body)
    }
    
    /**
     * Execute DELETE request
     */
    suspend inline fun <reified T> delete(endpoint: String): T {
        return request("DELETE", endpoint, null)
    }
    
    /**
     * Upload file
     */
    suspend inline fun <reified T> uploadFile(
        endpoint: String,
        fileBytes: ByteArray,
        contentType: String,
        fieldName: String = "file"
    ): T = withContext(Dispatchers.IO) {
        val url = buildUrl(endpoint)
        
        val requestBody = MultipartBody.Builder()
            .setType(MultipartBody.FORM)
            .addFormDataPart(
                fieldName,
                "upload",
                fileBytes.toRequestBody(contentType.toMediaType())
            )
            .build()
        
        val request = Request.Builder()
            .url(url)
            .post(requestBody)
            .build()
        
        executeRequest(request)
    }
    
    @PublishedApi
    internal suspend inline fun <reified B, reified T> request(
        method: String,
        endpoint: String,
        body: B?
    ): T = withContext(Dispatchers.IO) {
        val url = buildUrl(endpoint)
        
        val requestBuilder = Request.Builder()
            .url(url)
        
        // Add organization header if set
        organizationId?.let {
            requestBuilder.header("X-Organization-ID", it)
        }
        
        // Add body for appropriate methods
        if (body != null && method in listOf("POST", "PUT", "PATCH")) {
            val json = gson.toJson(body)
            val requestBody = json.toRequestBody("application/json".toMediaType())
            requestBuilder.method(method, requestBody)
        } else {
            requestBuilder.method(method, null)
        }
        
        executeRequest(requestBuilder.build())
    }
    
    @PublishedApi
    internal inline fun <reified T> executeRequest(request: Request): T {
        return try {
            client.newCall(request).execute().use { response ->
                handleResponse(response)
            }
        } catch (e: IOException) {
            VaultLogger.e("Network error: ${e.message}")
            throw VaultException(
                code = "network_error",
                message = "Network error: ${e.message}",
                cause = e
            )
        }
    }
    
    @PublishedApi
    internal inline fun <reified T> handleResponse(response: Response): T {
        val body = response.body?.string()
        
        if (!response.isSuccessful) {
            val error = parseError(response.code, body)
            throw error
        }
        
        // Handle Unit return type (empty body)
        if (T::class == Unit::class) {
            @Suppress("UNCHECKED_CAST")
            return Unit as T
        }
        
        if (body.isNullOrEmpty()) {
            throw VaultException(
                code = "empty_response",
                message = "Empty response body"
            )
        }
        
        return try {
            gson.fromJson(body, object : TypeToken<T>() {}.type)
        } catch (e: Exception) {
            VaultLogger.e("Parse error: ${e.message}")
            throw VaultException(
                code = "parse_error",
                message = "Failed to parse response: ${e.message}",
                cause = e
            )
        }
    }
    
    fun buildUrl(endpoint: String): String {
        return if (endpoint.startsWith("http")) {
            endpoint
        } else {
            val base = config.baseUrl
            val path = if (endpoint.startsWith("/")) endpoint else "/$endpoint"
            "$base$path"
        }
    }
    
    fun parseError(code: Int, body: String?): VaultException {
        return try {
            if (!body.isNullOrEmpty()) {
                val error = gson.fromJson(body, ErrorResponse::class.java)
                VaultException(
                    code = error.code ?: "http_$code",
                    message = error.message ?: "HTTP $code",
                    statusCode = code
                )
            } else {
                VaultException(
                    code = "http_$code",
                    message = "HTTP $code",
                    statusCode = code
                )
            }
        } catch (e: Exception) {
            VaultException(
                code = "http_$code",
                message = body ?: "HTTP $code",
                statusCode = code
            )
        }
    }
    
    // Interceptors
    
    private inner class AuthInterceptor : Interceptor {
        override fun intercept(chain: Interceptor.Chain): Response {
            val request = chain.request()
            val builder = request.newBuilder()
            
            // Add auth token if available
            val token = getCurrentToken()
            if (token != null) {
                builder.header("Authorization", "Bearer $token")
            }
            
            // Add default headers
            builder.header("Accept", "application/json")
            builder.header("X-SDK-Version", dev.vault.sdk.BuildConfig.SDK_VERSION)
            builder.header("X-Platform", "android")
            
            return chain.proceed(builder.build())
        }
        
        private fun getCurrentToken(): String? {
            // Get token from TokenStore
            return try {
                val context = dev.vault.sdk.Vault.context
                val store = dev.vault.sdk.session.TokenStore(context)
                store.getAccessToken()
            } catch (e: Exception) {
                null
            }
        }
    }
    
    private class TenantInterceptor(private val tenantId: String) : Interceptor {
        override fun intercept(chain: Interceptor.Chain): Response {
            val request = chain.request().newBuilder()
                .header("X-Tenant-ID", tenantId)
                .build()
            return chain.proceed(request)
        }
    }
    
    // Data classes
    
    private data class ErrorResponse(
        val code: String?,
        val message: String?,
        val details: Map<String, Any>?
    )
}

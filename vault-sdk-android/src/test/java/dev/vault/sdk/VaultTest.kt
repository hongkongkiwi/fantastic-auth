package dev.vault.sdk

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import dev.vault.sdk.auth.VaultAuth
import dev.vault.sdk.biometric.VaultBiometric
import dev.vault.sdk.network.VaultException
import dev.vault.sdk.organizations.VaultOrganizations
import dev.vault.sdk.session.VaultSession
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class VaultTest {
    
    private lateinit var mockServer: MockWebServer
    private lateinit var context: Context
    
    @Before
    fun setup() {
        mockServer = MockWebServer()
        mockServer.start()
        context = ApplicationProvider.getApplicationContext()
    }
    
    @After
    fun tearDown() {
        mockServer.shutdown()
        Vault.reset()
    }
    
    @Test
    fun `configure should initialize SDK with valid config`() {
        val baseUrl = mockServer.url("/").toString()
        
        Vault.configure(
            context = context,
            apiUrl = baseUrl,
            tenantId = "test-tenant"
        )
        
        assertTrue(Vault.isInitialized)
        assertEquals(baseUrl.removeSuffix("/"), Vault.config.apiUrl)
        assertEquals("test-tenant", Vault.config.tenantId)
    }
    
    @Test(expected = IllegalStateException::class)
    fun `config should throw when not initialized`() {
        Vault.config
    }
    
    @Test
    fun `configure should ignore duplicate calls`() {
        val baseUrl = mockServer.url("/").toString()
        
        Vault.configure(
            context = context,
            apiUrl = baseUrl,
            tenantId = "tenant-1"
        )
        
        // Second configure should be ignored
        Vault.configure(
            context = context,
            apiUrl = "https://other.com",
            tenantId = "tenant-2"
        )
        
        assertEquals("tenant-1", Vault.config.tenantId)
    }
    
    @Test
    fun `reset should clear configuration`() {
        val baseUrl = mockServer.url("/").toString()
        
        Vault.configure(
            context = context,
            apiUrl = baseUrl,
            tenantId = "test-tenant"
        )
        
        Vault.reset()
        
        assertFalse(Vault.isInitialized)
    }
    
    @Test
    fun `auth factory should create new instance`() {
        val baseUrl = mockServer.url("/").toString()
        
        Vault.configure(
            context = context,
            apiUrl = baseUrl,
            tenantId = "test-tenant"
        )
        
        val auth1 = Vault.auth()
        val auth2 = Vault.auth()
        
        assertNotNull(auth1)
        assertNotNull(auth2)
        assertNotSame(auth1, auth2)
    }
    
    @Test
    fun `session factory should create new instance`() {
        val baseUrl = mockServer.url("/").toString()
        
        Vault.configure(
            context = context,
            apiUrl = baseUrl,
            tenantId = "test-tenant"
        )
        
        val session = Vault.session()
        assertNotNull(session)
    }
    
    @Test
    fun `organizations factory should create new instance`() {
        val baseUrl = mockServer.url("/").toString()
        
        Vault.configure(
            context = context,
            apiUrl = baseUrl,
            tenantId = "test-tenant"
        )
        
        val orgs = Vault.organizations()
        assertNotNull(orgs)
    }
    
    @Test
    fun `biometric factory should create new instance`() {
        val baseUrl = mockServer.url("/").toString()
        
        Vault.configure(
            context = context,
            apiUrl = baseUrl,
            tenantId = "test-tenant"
        )
        
        val biometric = Vault.biometric(context)
        assertNotNull(biometric)
    }
    
    @Test
    fun `version should be defined`() {
        assertNotNull(Vault.VERSION)
        assertTrue(Vault.VERSION.isNotEmpty())
    }
}

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class VaultAuthTest {
    
    private lateinit var mockServer: MockWebServer
    private lateinit var context: Context
    
    @Before
    fun setup() {
        mockServer = MockWebServer()
        mockServer.start()
        context = ApplicationProvider.getApplicationContext()
        
        Vault.configure(
            context = context,
            apiUrl = mockServer.url("/").toString(),
            tenantId = "test-tenant"
        )
    }
    
    @After
    fun tearDown() {
        mockServer.shutdown()
        Vault.reset()
    }
    
    @Test
    fun `signIn should return session on success`() = runBlocking {
        val response = """
            {
                "user": {
                    "id": "user-123",
                    "email": "test@example.com",
                    "email_verified": true,
                    "name": "Test User",
                    "created_at": "2024-01-01T00:00:00.000Z",
                    "updated_at": "2024-01-01T00:00:00.000Z"
                },
                "access_token": "test-access-token",
                "refresh_token": "test-refresh-token",
                "expires_in": 3600
            }
        """.trimIndent()
        
        mockServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(response)
                .setHeader("Content-Type", "application/json")
        )
        
        val auth = VaultAuth()
        val session = auth.signIn("test@example.com", "password123")
        
        assertNotNull(session)
        assertEquals("user-123", session.user.id)
        assertEquals("test@example.com", session.user.email)
        assertEquals("test-access-token", session.accessToken)
    }
    
    @Test(expected = VaultException::class)
    fun `signIn should throw on invalid credentials`() = runBlocking {
        val response = """
            {
                "code": "invalid_credentials",
                "message": "Invalid email or password"
            }
        """.trimIndent()
        
        mockServer.enqueue(
            MockResponse()
                .setResponseCode(401)
                .setBody(response)
                .setHeader("Content-Type", "application/json")
        )
        
        val auth = VaultAuth()
        auth.signIn("test@example.com", "wrongpassword")
    }
    
    @Test
    fun `signUp should create user and return session`() = runBlocking {
        val response = """
            {
                "user": {
                    "id": "user-new",
                    "email": "new@example.com",
                    "email_verified": false,
                    "name": "New User",
                    "created_at": "2024-01-01T00:00:00.000Z",
                    "updated_at": "2024-01-01T00:00:00.000Z"
                },
                "access_token": "new-access-token",
                "refresh_token": "new-refresh-token",
                "expires_in": 3600
            }
        """.trimIndent()
        
        mockServer.enqueue(
            MockResponse()
                .setResponseCode(201)
                .setBody(response)
                .setHeader("Content-Type", "application/json")
        )
        
        val auth = VaultAuth()
        val session = auth.signUp("new@example.com", "password123", "New User")
        
        assertNotNull(session)
        assertEquals("new@example.com", session.user.email)
        assertEquals("New User", session.user.name)
    }
    
    @Test
    fun `forgotPassword should succeed`() = runBlocking {
        mockServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody("{}")
                .setHeader("Content-Type", "application/json")
        )
        
        val auth = VaultAuth()
        auth.forgotPassword("test@example.com")
        
        // Should not throw
        assertTrue(true)
    }
    
    @Test
    fun `requestMagicLink should succeed`() = runBlocking {
        mockServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody("{}")
                .setHeader("Content-Type", "application/json")
        )
        
        val auth = VaultAuth()
        auth.requestMagicLink("test@example.com")
        
        // Should not throw
        assertTrue(true)
    }
}

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class VaultSessionTest {
    
    private lateinit var mockServer: MockWebServer
    private lateinit var context: Context
    
    @Before
    fun setup() {
        mockServer = MockWebServer()
        mockServer.start()
        context = ApplicationProvider.getApplicationContext()
        
        Vault.configure(
            context = context,
            apiUrl = mockServer.url("/").toString(),
            tenantId = "test-tenant"
        )
    }
    
    @After
    fun tearDown() {
        mockServer.shutdown()
        Vault.reset()
    }
    
    @Test
    fun `isAuthenticated should return false initially`() {
        val session = VaultSession()
        assertFalse(session.isAuthenticated)
    }
    
    @Test
    fun `currentUser should return null initially`() {
        val session = VaultSession()
        assertNull(session.currentUser)
    }
    
    @Test
    fun `getToken should return null initially`() {
        val session = VaultSession()
        assertNull(session.getToken())
    }
    
    @Test
    fun `refreshUser should return user on success`() = runBlocking {
        val response = """
            {
                "id": "user-123",
                "email": "test@example.com",
                "email_verified": true,
                "name": "Test User",
                "created_at": "2024-01-01T00:00:00.000Z",
                "updated_at": "2024-01-01T00:00:00.000Z"
            }
        """.trimIndent()
        
        mockServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(response)
                .setHeader("Content-Type", "application/json")
        )
        
        val session = VaultSession()
        val user = session.refreshUser()
        
        assertNotNull(user)
        assertEquals("user-123", user.id)
        assertEquals("test@example.com", user.email)
    }
}

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class VaultOrganizationsTest {
    
    private lateinit var mockServer: MockWebServer
    private lateinit var context: Context
    
    @Before
    fun setup() {
        mockServer = MockWebServer()
        mockServer.start()
        context = ApplicationProvider.getApplicationContext()
        
        Vault.configure(
            context = context,
            apiUrl = mockServer.url("/").toString(),
            tenantId = "test-tenant"
        )
    }
    
    @After
    fun tearDown() {
        mockServer.shutdown()
        Vault.reset()
    }
    
    @Test
    fun `list should return organizations`() = runBlocking {
        val response = """
            {
                "organizations": [
                    {
                        "id": "org-1",
                        "name": "Test Org",
                        "slug": "test-org",
                        "owner_id": "user-123",
                        "metadata": {},
                        "created_at": "2024-01-01T00:00:00.000Z",
                        "updated_at": "2024-01-01T00:00:00.000Z"
                    }
                ]
            }
        """.trimIndent()
        
        mockServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(response)
                .setHeader("Content-Type", "application/json")
        )
        
        val orgs = VaultOrganizations()
        val list = orgs.list()
        
        assertEquals(1, list.size)
        assertEquals("org-1", list[0].id)
        assertEquals("Test Org", list[0].name)
    }
    
    @Test
    fun `create should return new organization`() = runBlocking {
        val response = """
            {
                "id": "org-new",
                "name": "New Org",
                "slug": "new-org",
                "owner_id": "user-123",
                "metadata": {},
                "created_at": "2024-01-01T00:00:00.000Z",
                "updated_at": "2024-01-01T00:00:00.000Z"
            }
        """.trimIndent()
        
        mockServer.enqueue(
            MockResponse()
                .setResponseCode(201)
                .setBody(response)
                .setHeader("Content-Type", "application/json")
        )
        
        val orgs = VaultOrganizations()
        val org = orgs.create("New Org")
        
        assertNotNull(org)
        assertEquals("New Org", org.name)
        assertEquals("new-org", org.slug)
    }
    
    @Test
    fun `setActive should update active organization`() = runBlocking {
        val response = """
            {
                "id": "org-1",
                "name": "Test Org",
                "slug": "test-org",
                "owner_id": "user-123",
                "metadata": {},
                "created_at": "2024-01-01T00:00:00.000Z",
                "updated_at": "2024-01-01T00:00:00.000Z"
            }
        """.trimIndent()
        
        mockServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(response)
                .setHeader("Content-Type", "application/json")
        )
        
        val orgs = VaultOrganizations()
        orgs.setActive("org-1")
        
        assertNotNull(orgs.activeOrganization)
        assertEquals("org-1", orgs.activeOrganization?.id)
    }
}

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class VaultBiometricTest {
    
    private lateinit var context: Context
    
    @Before
    fun setup() {
        context = ApplicationProvider.getApplicationContext()
        
        Vault.configure(
            context = context,
            apiUrl = "https://api.test.com",
            tenantId = "test-tenant"
        )
    }
    
    @After
    fun tearDown() {
        Vault.reset()
    }
    
    @Test
    fun `isAvailable should return false on emulator`() {
        val biometric = VaultBiometric(context)
        // Biometric is not available on emulator without setup
        assertFalse(biometric.isAvailable)
    }
    
    @Test
    fun `availabilityStatus should return valid status`() {
        val biometric = VaultBiometric(context)
        val status = biometric.availabilityStatus
        assertNotNull(status)
    }
}

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class CryptoUtilsTest {
    
    @Test
    fun `generateSecureRandom should return different values`() {
        val random1 = dev.vault.sdk.utils.Crypto.generateSecureRandom()
        val random2 = dev.vault.sdk.utils.Crypto.generateSecureRandom()
        
        assertNotEquals(random1, random2)
        assertTrue(random1.isNotEmpty())
    }
    
    @Test
    fun `sha256 should return consistent hash`() {
        val input = "test"
        val hash1 = dev.vault.sdk.utils.Crypto.sha256(input)
        val hash2 = dev.vault.sdk.utils.Crypto.sha256(input)
        
        assertEquals(hash1, hash2)
        assertEquals(64, hash1.length) // SHA-256 produces 64 hex characters
    }
    
    @Test
    fun `sha256 should return different hashes for different inputs`() {
        val hash1 = dev.vault.sdk.utils.Crypto.sha256("input1")
        val hash2 = dev.vault.sdk.utils.Crypto.sha256("input2")
        
        assertNotEquals(hash1, hash2)
    }
    
    @Test
    fun `aesEncrypt and aesDecrypt should work together`() {
        val key = ByteArray(32) { it.toByte() } // 256-bit key
        val plaintext = "Hello, World!".toByteArray()
        
        val encrypted = dev.vault.sdk.utils.Crypto.aesEncrypt(plaintext, key)
        val decrypted = dev.vault.sdk.utils.Crypto.aesDecrypt(encrypted, key)
        
        assertArrayEquals(plaintext, decrypted)
    }
    
    @Test
    fun `base64Encode and base64Decode should work together`() {
        val original = "Hello, World!"
        val encoded = original.toByteArray().toBase64()
        val decoded = encoded.fromBase64()
        
        assertEquals(original, String(decoded))
    }
    
    @Test
    fun `hexToBytes and toHex should work together`() {
        val original = "48656c6c6f2c20576f726c6421" // "Hello, World!" in hex
        val bytes = original.fromHex()
        val hex = bytes.toHex()
        
        assertEquals(original, hex)
    }
    
    @Test
    fun `constantTimeEquals should return true for equal arrays`() {
        val a = "test".toByteArray()
        val b = "test".toByteArray()
        
        assertTrue(dev.vault.sdk.utils.Crypto.constantTimeEquals(a, b))
    }
    
    @Test
    fun `constantTimeEquals should return false for different arrays`() {
        val a = "test1".toByteArray()
        val b = "test2".toByteArray()
        
        assertFalse(dev.vault.sdk.utils.Crypto.constantTimeEquals(a, b))
    }
    
    @Test
    fun `extension sha256 should work`() {
        val hash = "test".sha256()
        assertEquals(64, hash.length)
    }
}

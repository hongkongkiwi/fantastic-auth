package com.vault

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.vault.models.*
import com.vault.storage.InMemoryTokenStorage
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
@Config(sdk = [28])
class VaultAuthTest {

    private lateinit var mockServer: MockWebServer
    private lateinit var storage: InMemoryTokenStorage
    private lateinit var context: Context
    private val baseUrl: String
        get() = mockServer.url("/").toString()

    @Before
    fun setup() {
        mockServer = MockWebServer()
        mockServer.start()
        storage = InMemoryTokenStorage()
        context = ApplicationProvider.getApplicationContext()
        
        // Clear any previous instance
        VaultAuth.clearInstance()
    }

    @After
    fun tearDown() {
        mockServer.shutdown()
        VaultAuth.clearInstance()
    }

    @Test
    fun `configure should initialize the SDK`() {
        VaultAuth.getInstance().configure(
            context = context,
            apiKey = "test_api_key",
            baseUrl = baseUrl,
            storage = storage
        )

        assertTrue(VaultAuth.getInstance().isConfigured())
    }

    @Test(expected = VaultAuthException.NotConfigured::class)
    fun `login should throw NotConfigured when not initialized`() = runBlocking {
        VaultAuth.getInstance().login("test@example.com", "password")
    }

    @Test
    fun `login should succeed with valid credentials`() = runBlocking {
        // Arrange
        VaultAuth.getInstance().configure(
            context = context,
            apiKey = "test_api_key",
            baseUrl = baseUrl,
            storage = storage
        )

        val mockResponse = """
            {
                "user": {
                    "id": "user_123",
                    "tenant_id": "tenant_123",
                    "email": "test@example.com",
                    "email_verified": true,
                    "status": "active",
                    "profile": {
                        "name": "Test User"
                    },
                    "mfa_enabled": false,
                    "created_at": "2024-01-01T00:00:00.000Z",
                    "updated_at": "2024-01-01T00:00:00.000Z"
                },
                "session": {
                    "id": "session_123",
                    "access_token": "access_token_123",
                    "refresh_token": "refresh_token_123",
                    "expires_at": "2025-01-01T00:00:00.000Z",
                    "user": {
                        "id": "user_123",
                        "tenant_id": "tenant_123",
                        "email": "test@example.com",
                        "email_verified": true,
                        "status": "active",
                        "profile": {},
                        "mfa_enabled": false,
                        "created_at": "2024-01-01T00:00:00.000Z",
                        "updated_at": "2024-01-01T00:00:00.000Z"
                    }
                }
            }
        """.trimIndent()

        mockServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(mockResponse)
                .addHeader("Content-Type", "application/json")
        )

        // Act
        val user = VaultAuth.getInstance().login("test@example.com", "password")

        // Assert
        assertEquals("user_123", user.id)
        assertEquals("test@example.com", user.email)
        assertTrue(VaultAuth.getInstance().isAuthenticated)
        assertEquals("access_token_123", storage.getToken(TokenStorage.KEY_ACCESS_TOKEN))
    }

    @Test(expected = VaultAuthException.InvalidCredentials::class)
    fun `login should throw InvalidCredentials on 401`() = runBlocking {
        // Arrange
        VaultAuth.getInstance().configure(
            context = context,
            apiKey = "test_api_key",
            baseUrl = baseUrl,
            storage = storage
        )

        val mockResponse = """
            {
                "error": "invalid_credentials",
                "message": "Invalid email or password"
            }
        """.trimIndent()

        mockServer.enqueue(
            MockResponse()
                .setResponseCode(401)
                .setBody(mockResponse)
                .addHeader("Content-Type", "application/json")
        )

        // Act
        VaultAuth.getInstance().login("test@example.com", "wrong_password")
    }

    @Test
    fun `logout should clear authentication state`() = runBlocking {
        // Arrange
        VaultAuth.getInstance().configure(
            context = context,
            apiKey = "test_api_key",
            baseUrl = baseUrl,
            storage = storage
        )

        storage.saveToken(TokenStorage.KEY_ACCESS_TOKEN, "test_token")
        storage.saveToken(TokenStorage.KEY_REFRESH_TOKEN, "test_refresh")

        mockServer.enqueue(MockResponse().setResponseCode(200))

        // Act
        VaultAuth.getInstance().logout()

        // Assert
        assertFalse(VaultAuth.getInstance().isAuthenticated)
        assertNull(storage.getToken(TokenStorage.KEY_ACCESS_TOKEN))
    }

    @Test
    fun `isAuthenticated should return false when no tokens stored`() {
        // Arrange
        VaultAuth.getInstance().configure(
            context = context,
            apiKey = "test_api_key",
            baseUrl = baseUrl,
            storage = storage
        )

        // Assert
        assertFalse(VaultAuth.getInstance().isAuthenticated)
    }

    @Test
    fun `getOrganizations should return list of organizations`() = runBlocking {
        // Arrange
        VaultAuth.getInstance().configure(
            context = context,
            apiKey = "test_api_key",
            baseUrl = baseUrl,
            storage = storage
        )

        // Setup authenticated user
        storage.saveToken(TokenStorage.KEY_ACCESS_TOKEN, "test_token")

        val mockResponse = """
            {
                "organizations": [
                    {
                        "id": "org_123",
                        "tenant_id": "tenant_123",
                        "name": "Test Org",
                        "slug": "test-org",
                        "role": "owner",
                        "created_at": "2024-01-01T00:00:00.000Z",
                        "updated_at": "2024-01-01T00:00:00.000Z"
                    }
                ],
                "total": 1,
                "page": 1,
                "per_page": 20,
                "has_more": false
            }
        """.trimIndent()

        mockServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(mockResponse)
                .addHeader("Content-Type", "application/json")
        )

        // Act
        val organizations = VaultAuth.getInstance().getOrganizations()

        // Assert
        assertEquals(1, organizations.size)
        assertEquals("org_123", organizations[0].id)
        assertEquals("Test Org", organizations[0].name)
        assertEquals(OrganizationRole.OWNER, organizations[0].role)
    }

    @Test
    fun `signup should create new user`() = runBlocking {
        // Arrange
        VaultAuth.getInstance().configure(
            context = context,
            apiKey = "test_api_key",
            baseUrl = baseUrl,
            storage = storage
        )

        val mockResponse = """
            {
                "user": {
                    "id": "user_new",
                    "tenant_id": "tenant_123",
                    "email": "newuser@example.com",
                    "email_verified": false,
                    "status": "pending",
                    "profile": {
                        "name": "New User"
                    },
                    "mfa_enabled": false,
                    "created_at": "2024-01-01T00:00:00.000Z",
                    "updated_at": "2024-01-01T00:00:00.000Z"
                },
                "session": {
                    "id": "session_new",
                    "access_token": "new_access_token",
                    "refresh_token": "new_refresh_token",
                    "expires_at": "2025-01-01T00:00:00.000Z",
                    "user": {
                        "id": "user_new",
                        "tenant_id": "tenant_123",
                        "email": "newuser@example.com",
                        "email_verified": false,
                        "status": "pending",
                        "profile": {},
                        "mfa_enabled": false,
                        "created_at": "2024-01-01T00:00:00.000Z",
                        "updated_at": "2024-01-01T00:00:00.000Z"
                    }
                }
            }
        """.trimIndent()

        mockServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(mockResponse)
                .addHeader("Content-Type", "application/json")
        )

        // Act
        val user = VaultAuth.getInstance().signup(
            email = "newuser@example.com",
            password = "SecurePass123!",
            name = "New User"
        )

        // Assert
        assertEquals("user_new", user.id)
        assertEquals("newuser@example.com", user.email)
        assertEquals(UserStatus.PENDING, user.status)
    }

    @Test
    fun `biometric availability check`() {
        // Arrange
        VaultAuth.getInstance().configure(
            context = context,
            apiKey = "test_api_key",
            baseUrl = baseUrl,
            storage = storage
        )

        // Assert - Biometric won't be available in test environment
        assertFalse(VaultAuth.getInstance().isBiometricAvailable(context))
    }

    @Test
    fun `token storage should persist tokens`() {
        // Arrange
        val testToken = "test_access_token"
        val testKey = "test_key"

        // Act
        storage.saveToken(testKey, testToken)

        // Assert
        assertEquals(testToken, storage.getToken(testKey))
        assertTrue(storage.hasToken(testKey))

        // Test delete
        storage.deleteToken(testKey)
        assertNull(storage.getToken(testKey))
        assertFalse(storage.hasToken(testKey))
    }

    @Test
    fun `User should return full name correctly`() {
        // Test with name
        val userWithName = User(
            id = "1",
            tenantId = "t1",
            email = "test@example.com",
            emailVerified = true,
            status = UserStatus.ACTIVE,
            profile = UserProfile(name = "John Doe"),
            mfaEnabled = false
        )
        assertEquals("John Doe", userWithName.getFullName())

        // Test with given and family name
        val userWithGivenFamily = User(
            id = "1",
            tenantId = "t1",
            email = "test@example.com",
            emailVerified = true,
            status = UserStatus.ACTIVE,
            profile = UserProfile(givenName = "Jane", familyName = "Smith"),
            mfaEnabled = false
        )
        assertEquals("Jane Smith", userWithGivenFamily.getFullName())

        // Test with email fallback
        val userWithEmail = User(
            id = "1",
            tenantId = "t1",
            email = "test@example.com",
            emailVerified = true,
            status = UserStatus.ACTIVE,
            profile = UserProfile(),
            mfaEnabled = false
        )
        assertEquals("test@example.com", userWithEmail.getFullName())
    }
}

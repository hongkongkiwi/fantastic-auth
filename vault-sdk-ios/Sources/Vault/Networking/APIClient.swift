import Foundation

/// The API client for making HTTP requests to Vault.
///
/// This is an internal class that handles all network communication.
internal actor APIClient {
    
    // MARK: - Properties
    
    private let configuration: Vault.Configuration
    private let urlSession: URLSession
    private let decoder: JSONDecoder
    private let encoder: JSONEncoder
    
    // MARK: - Initialization
    
    init(configuration: Vault.Configuration) {
        self.configuration = configuration
        
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = configuration.timeout
        config.timeoutIntervalForResource = configuration.timeout * 2
        config.httpAdditionalHeaders = [
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Vault-SDK": "ios-\(configuration.sdkVersion)",
            "X-Vault-Tenant": configuration.tenantId
        ]
        
        self.urlSession = URLSession(configuration: config)
        
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        decoder.dateDecodingStrategy = .iso8601
        self.decoder = decoder
        
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        encoder.dateEncodingStrategy = .iso8601
        self.encoder = encoder
    }
    
    // MARK: - HTTP Methods
    
    /// Performs a GET request.
    func get<T: Decodable>(
        path: String,
        requiresAuth: Bool = true
    ) async throws -> T {
        try await request(method: "GET", path: path, requiresAuth: requiresAuth)
    }
    
    /// Performs a POST request.
    func post<T: Decodable, B: Encodable>(
        path: String,
        body: B,
        requiresAuth: Bool = true
    ) async throws -> T {
        try await request(method: "POST", path: path, body: body, requiresAuth: requiresAuth)
    }
    
    /// Performs a PUT request.
    func put<T: Decodable, B: Encodable>(
        path: String,
        body: B,
        requiresAuth: Bool = true
    ) async throws -> T {
        try await request(method: "PUT", path: path, body: body, requiresAuth: requiresAuth)
    }
    
    /// Performs a PATCH request.
    func patch<T: Decodable, B: Encodable>(
        path: String,
        body: B,
        requiresAuth: Bool = true
    ) async throws -> T {
        try await request(method: "PATCH", path: path, body: body, requiresAuth: requiresAuth)
    }
    
    /// Performs a DELETE request.
    func delete<T: Decodable>(
        path: String,
        requiresAuth: Bool = true
    ) async throws -> T {
        try await request(method: "DELETE", path: path, requiresAuth: requiresAuth)
    }
    
    // MARK: - Request Building
    
    /// Performs an HTTP request.
    func request<T: Decodable, B: Encodable>(
        method: String,
        path: String,
        body: B? = nil,
        requiresAuth: Bool = true
    ) async throws -> T {
        guard let url = URL(string: "\(configuration.apiUrl)\(path)") else {
            throw VaultError.invalidURL
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = method
        
        if let body = body {
            request.httpBody = try encoder.encode(body)
        }
        
        if requiresAuth, let token = await getAccessToken() {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        
        if let apiKey = configuration.apiKey {
            request.setValue(apiKey, forHTTPHeaderField: "X-API-Key")
        }
        
        return try await perform(request)
    }
    
    /// Performs a raw request without type constraints.
    func request(
        method: String,
        path: String,
        body: Encodable? = nil,
        requiresAuth: Bool = true
    ) async throws -> Data {
        guard let url = URL(string: "\(configuration.apiUrl)\(path)") else {
            throw VaultError.invalidURL
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = method
        
        if let body = body {
            request.httpBody = try encoder.encode(body)
        }
        
        if requiresAuth, let token = await getAccessToken() {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        
        if let apiKey = configuration.apiKey {
            request.setValue(apiKey, forHTTPHeaderField: "X-API-Key")
        }
        
        let (data, response) = try await urlSession.data(for: request)
        try validateResponse(response, data: data)
        return data
    }
    
    // MARK: - Request Execution
    
    private func perform<T: Decodable>(_ request: URLRequest) async throws -> T {
        Vault.shared.logger.logRequest(request)
        
        do {
            let (data, response) = try await urlSession.data(for: request)
            
            Vault.shared.logger.logResponse(response, data: data)
            
            try validateResponse(response, data: data)
            
            if T.self == EmptyResponse.self {
                return EmptyResponse() as! T
            }
            
            return try decoder.decode(T.self, from: data)
        } catch let error as VaultError {
            throw error
        } catch let error as DecodingError {
            Vault.shared.logger.logError("Decoding error: \(error)")
            throw VaultError.decodingFailed(error)
        } catch {
            Vault.shared.logger.logError("Network error: \(error)")
            throw VaultError.networkError(error)
        }
    }
    
    private func validateResponse(_ response: URLResponse, data: Data) throws {
        guard let httpResponse = response as? HTTPURLResponse else {
            throw VaultError.invalidResponse
        }
        
        switch httpResponse.statusCode {
        case 200...299:
            return
        case 401:
            throw VaultError.unauthorized
        case 403:
            throw VaultError.forbidden
        case 404:
            throw VaultError.notFound
        case 409:
            let errorResponse = try? decoder.decode(ErrorResponse.self, from: data)
            throw VaultError.conflict(errorResponse?.message ?? "Conflict")
        case 422:
            let errorResponse = try? decoder.decode(ValidationErrorResponse.self, from: data)
            throw VaultError.validationFailed(errorResponse?.errors ?? [:])
        case 429:
            throw VaultError.rateLimited
        case 500...599:
            throw VaultError.serverError(httpResponse.statusCode)
        default:
            throw VaultError.unknown(httpResponse.statusCode)
        }
    }
    
    // MARK: - Token Management
    
    private func getAccessToken() async -> String? {
        await Vault.shared.tokenStore.getAccessToken()
    }
}

// MARK: - Response Types

/// An empty response for endpoints that return no data.
internal struct EmptyResponse: Decodable, Equatable {
    init() {}
}

/// Standard error response from the API.
internal struct ErrorResponse: Decodable {
    let error: String
    let message: String
    let code: String?
}

/// Validation error response from the API.
internal struct ValidationErrorResponse: Decodable {
    let error: String
    let message: String
    let errors: [String: [String]]
}

// MARK: - Request Body Types

/// Sign in request body.
internal struct SignInRequest: Encodable {
    let email: String
    let password: String
}

/// Sign up request body.
internal struct SignUpRequest: Encodable {
    let email: String
    let password: String
    let firstName: String?
    let lastName: String?
}

/// OAuth sign in request body.
internal struct OAuthRequest: Encodable {
    let provider: String
    let code: String
    let redirectUri: String
}

/// Refresh token request body.
internal struct RefreshTokenRequest: Encodable {
    let refreshToken: String
}

/// Password reset request body.
internal struct PasswordResetRequest: Encodable {
    let email: String
}

/// Update password request body.
internal struct UpdatePasswordRequest: Encodable {
    let currentPassword: String
    let newPassword: String
}

/// Update profile request body.
internal struct UpdateProfileRequest: Encodable {
    let firstName: String?
    let lastName: String?
    let phoneNumber: String?
}

/// Verify email request body.
internal struct VerifyEmailRequest: Encodable {
    let token: String
}

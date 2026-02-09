import Foundation

// MARK: - VaultClient

public class VaultClient {
    
    // MARK: - Properties
    
    private let baseURL: URL
    private let apiKey: String
    private let tenantId: String?
    private let urlSession: URLSession
    private let decoder: JSONDecoder
    private let encoder: JSONEncoder
    
    private var accessToken: String?
    
    // MARK: - Initialization
    
    public init(
        baseURL: URL,
        apiKey: String,
        tenantId: String? = nil,
        urlSession: URLSession = .shared,
        decoder: JSONDecoder = JSONDecoder(),
        encoder: JSONEncoder = JSONEncoder()
    ) {
        self.baseURL = baseURL
        self.apiKey = apiKey
        self.tenantId = tenantId
        self.urlSession = urlSession
        self.decoder = decoder
        self.encoder = encoder
        
        // Configure decoder for API dates
        let dateFormatter = ISO8601DateFormatter()
        dateFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        
        self.decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let dateString = try container.decode(String.self)
            
            // Try ISO8601 with fractional seconds
            dateFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let date = dateFormatter.date(from: dateString) {
                return date
            }
            
            // Try ISO8601 without fractional seconds
            dateFormatter.formatOptions = [.withInternetDateTime]
            if let date = dateFormatter.date(from: dateString) {
                return date
            }
            
            // Try Unix timestamp
            if let timestamp = TimeInterval(dateString) {
                return Date(timeIntervalSince1970: timestamp)
            }
            
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Cannot decode date: \(dateString)"
            )
        }
        
        // Configure encoder for API dates
        self.encoder.dateEncodingStrategy = .iso8601
        self.encoder.keyEncodingStrategy = .convertToSnakeCase
    }
    
    // MARK: - Token Management
    
    func setAccessToken(_ token: String?) {
        self.accessToken = token
    }
    
    // MARK: - HTTP Methods
    
    @discardableResult
    public func get(_ path: String, parameters: [String: Any]? = nil) async throws -> Data {
        return try await request(method: "GET", path: path, parameters: parameters)
    }
    
    @discardableResult
    public func post(_ path: String, body: Encodable? = nil) async throws -> Data {
        return try await request(method: "POST", path: path, body: body)
    }
    
    @discardableResult
    public func put(_ path: String, body: Encodable? = nil) async throws -> Data {
        return try await request(method: "PUT", path: path, body: body)
    }
    
    @discardableResult
    public func patch(_ path: String, body: Encodable? = nil) async throws -> Data {
        return try await request(method: "PATCH", path: path, body: body)
    }
    
    @discardableResult
    public func delete(_ path: String, parameters: [String: Any]? = nil) async throws -> Data {
        return try await request(method: "DELETE", path: path, parameters: parameters)
    }
    
    // MARK: - Typed Request Methods
    
    public func get<T: Decodable>(_ path: String, parameters: [String: Any]? = nil) async throws -> T {
        let data = try await get(path, parameters: parameters)
        return try decoder.decode(T.self, from: data)
    }
    
    public func post<T: Decodable>(_ path: String, body: Encodable? = nil) async throws -> T {
        let data = try await post(path, body: body)
        return try decoder.decode(T.self, from: data)
    }
    
    public func put<T: Decodable>(_ path: String, body: Encodable? = nil) async throws -> T {
        let data = try await put(path, body: body)
        return try decoder.decode(T.self, from: data)
    }
    
    public func patch<T: Decodable>(_ path: String, body: Encodable? = nil) async throws -> T {
        let data = try await patch(path, body: body)
        return try decoder.decode(T.self, from: data)
    }
    
    // MARK: - Private Methods
    
    private func request(
        method: String,
        path: String,
        parameters: [String: Any]? = nil,
        body: Encodable? = nil
    ) async throws -> Data {
        // Build URL
        var urlComponents = URLComponents(url: baseURL.appendingPathComponent(path), resolvingAgainstBaseURL: false)!
        
        // Add query parameters
        if let parameters = parameters {
            urlComponents.queryItems = parameters.map { key, value in
                URLQueryItem(name: key, value: String(describing: value))
            }
        }
        
        guard let url = urlComponents.url else {
            throw VaultAuthError.invalidConfiguration("Invalid URL")
        }
        
        // Create request
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(apiKey, forHTTPHeaderField: "X-API-Key")
        
        // Add tenant ID if available
        if let tenantId = tenantId {
            request.setValue(tenantId, forHTTPHeaderField: "X-Tenant-ID")
        }
        
        // Add authorization if available
        if let accessToken = accessToken {
            request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        }
        
        // Add body if available
        if let body = body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try encoder.encode(body)
        }
        
        // Perform request
        let (data, response): (Data, URLResponse)
        
        do {
            (data, response) = try await urlSession.data(for: request)
        } catch {
            throw VaultAuthError.networkError(error)
        }
        
        // Check response
        guard let httpResponse = response as? HTTPURLResponse else {
            throw VaultAuthError.unknown("Invalid response")
        }
        
        // Handle status codes
        switch httpResponse.statusCode {
        case 200...299:
            return data
            
        case 400:
            throw parseError(data, statusCode: 400) ?? VaultAuthError.invalidCredentials
            
        case 401:
            throw VaultAuthError.sessionExpired
            
        case 403:
            throw VaultAuthError.accountLocked
            
        case 404:
            throw VaultAuthError.userNotFound
            
        case 409:
            throw VaultAuthError.invalidConfiguration("Conflict")
            
        case 422:
            throw parseError(data, statusCode: 422) ?? VaultAuthError.invalidConfiguration("Validation error")
            
        case 429:
            throw VaultAuthError.serverError(429, "Rate limited")
            
        case 500...599:
            throw VaultAuthError.serverError(httpResponse.statusCode, "Server error")
            
        default:
            throw VaultAuthError.serverError(httpResponse.statusCode, nil)
        }
    }
    
    private func parseError(_ data: Data, statusCode: Int) -> VaultAuthError? {
        if let errorResponse = try? decoder.decode(APIErrorResponse.self, from: data) {
            switch errorResponse.error {
            case "mfa_required":
                return .mfaRequired
            case "invalid_credentials":
                return .invalidCredentials
            case "session_expired":
                return .sessionExpired
            case "token_invalid":
                return .tokenInvalid
            default:
                return .serverError(statusCode, errorResponse.message)
            }
        }
        return nil
    }
}

// MARK: - APIRequest

public protocol APIRequest {
    associatedtype Response: Decodable
    var path: String { get }
    var method: String { get }
    var body: Encodable? { get }
    var requiresAuth: Bool { get }
}

public extension APIRequest {
    var body: Encodable? { nil }
    var requiresAuth: Bool { true }
}

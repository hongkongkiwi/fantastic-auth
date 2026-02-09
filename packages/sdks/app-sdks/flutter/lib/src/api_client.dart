import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;

import 'exceptions.dart';
import 'session.dart';

/// HTTP client for Vault API
class VaultApiClient {
  static VaultApiClient? _instance;
  
  /// Base URL for the Vault API
  final String baseUrl;
  
  /// Tenant ID for multi-tenancy
  final String? tenantId;
  
  /// Tenant slug for multi-tenancy
  final String? tenantSlug;
  
  /// HTTP client
  final http.Client _client;
  
  /// Request timeout
  final Duration timeout;
  
  /// Optional session for authenticated requests
  VaultSession? _session;

  VaultApiClient._({
    required this.baseUrl,
    this.tenantId,
    this.tenantSlug,
    http.Client? client,
    this.timeout = const Duration(seconds: 30),
  }) : _client = client ?? http.Client();

  /// Initialize the API client
  factory VaultApiClient({
    required String baseUrl,
    String? tenantId,
    String? tenantSlug,
    http.Client? client,
    Duration timeout = const Duration(seconds: 30),
  }) {
    _instance ??= VaultApiClient._(
      baseUrl: baseUrl,
      tenantId: tenantId,
      tenantSlug: tenantSlug,
      client: client,
      timeout: timeout,
    );
    return _instance!;
  }

  /// Get the singleton instance
  static VaultApiClient get instance {
    if (_instance == null) {
      throw const VaultConfigurationException(
        'VaultApiClient not initialized. Call Vault.initialize() first.',
      );
    }
    return _instance!;
  }

  /// Set the session for authenticated requests
  void setSession(VaultSession session) {
    _session = session;
  }

  /// Clear the session
  void clearSession() {
    _session = null;
  }

  /// Get default headers for all requests
  Map<String, String> get _defaultHeaders {
    final headers = <String, String>{
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };

    if (tenantId != null) {
      headers['X-Tenant-ID'] = tenantId!;
    }
    if (tenantSlug != null) {
      headers['X-Tenant-Slug'] = tenantSlug!;
    }

    return headers;
  }

  /// Get authentication headers
  Future<Map<String, String>> get _authHeaders async {
    final headers = <String, String>{};
    
    if (_session != null) {
      final token = await _session!.getToken();
      if (token != null) {
        headers['Authorization'] = 'Bearer $token';
      }
    }
    
    return headers;
  }

  /// Build full URL
  Uri _buildUri(String path, {Map<String, String>? queryParams}) {
    final cleanBaseUrl = baseUrl.replaceAll(RegExp(r'/+$'), '');
    final cleanPath = path.replaceAll(RegExp(r'^/+'), '');
    
    final uri = Uri.parse('$cleanBaseUrl/$cleanPath');
    
    if (queryParams != null && queryParams.isNotEmpty) {
      return uri.replace(queryParameters: queryParams);
    }
    
    return uri;
  }

  /// Parse API response and handle errors
  dynamic _handleResponse(http.Response response) {
    // Check for rate limiting
    final rateLimitRemaining = response.headers['x-ratelimit-remaining'];
    if (rateLimitRemaining == '0') {
      final resetTimestamp = int.tryParse(
        response.headers['x-ratelimit-reset'] ?? '',
      );
      throw VaultRateLimitException(
        'Rate limit exceeded. Please try again later.',
        resetTimestamp: resetTimestamp,
      );
    }

    // Parse response body
    dynamic body;
    try {
      if (response.body.isNotEmpty) {
        body = jsonDecode(response.body);
      }
    } catch (e) {
      // Not JSON, ignore
    }

    // Handle success
    if (response.statusCode >= 200 && response.statusCode < 300) {
      return body;
    }

    // Handle errors
    _handleError(response, body);
  }

  /// Handle API errors
  Never _handleError(http.Response response, dynamic body) {
    final errorMessage = body?['error']?['message'] ?? 
                         body?['message'] ?? 
                         'Request failed';
    final errorCode = body?['error']?['code'];
    final details = body?['error']?['details'];

    switch (response.statusCode) {
      case 400:
        if (body?['error']?['details'] != null) {
          final fieldErrors = <String, List<String>>{};
          final details = body['error']['details'] as Map<String, dynamic>?;
          details?.forEach((key, value) {
            if (value is List) {
              fieldErrors[key] = value.cast<String>();
            } else if (value is String) {
              fieldErrors[key] = [value];
            }
          });
          throw VaultValidationException(
            errorMessage,
            fieldErrors: fieldErrors.isNotEmpty ? fieldErrors : null,
            code: errorCode,
          );
        }
        throw VaultValidationException(errorMessage, code: errorCode);
        
      case 401:
        if (errorCode == 'TOKEN_EXPIRED' || errorCode == 'SESSION_EXPIRED') {
          throw const VaultSessionExpiredException();
        }
        throw VaultAuthException(errorMessage, code: errorCode, statusCode: 401);
        
      case 403:
        if (errorCode == 'MFA_REQUIRED') {
          final methods = (body?['available_methods'] as List<dynamic>?)
              ?.cast<String>() ?? 
              [];
          throw VaultMfaRequiredException(availableMethods: methods);
        }
        throw VaultAuthException(errorMessage, code: errorCode, statusCode: 403);
        
      case 404:
        throw VaultException(
          errorMessage,
          code: errorCode ?? 'NOT_FOUND',
          statusCode: 404,
        );
        
      case 409:
        throw VaultException(
          errorMessage,
          code: errorCode ?? 'CONFLICT',
          statusCode: 409,
        );
        
      case 429:
        final resetTimestamp = int.tryParse(
          response.headers['x-ratelimit-reset'] ?? '',
        );
        throw VaultRateLimitException(
          errorMessage,
          resetTimestamp: resetTimestamp,
          code: errorCode,
        );
        
      default:
        throw VaultException(
          errorMessage,
          code: errorCode ?? 'UNKNOWN_ERROR',
          statusCode: response.statusCode,
          details: details,
        );
    }
  }

  /// Perform GET request
  Future<dynamic> get(
    String path, {
    Map<String, String>? queryParams,
    bool authenticated = true,
  }) async {
    try {
      final headers = {..._defaultHeaders};
      if (authenticated) {
        headers.addAll(await _authHeaders);
      }

      final response = await _client
          .get(
            _buildUri(path, queryParams: queryParams),
            headers: headers,
          )
          .timeout(timeout);

      return _handleResponse(response);
    } on SocketException catch (e) {
      throw VaultNetworkException(
        'Network error: Unable to connect to server',
        originalError: e,
        code: 'NETWORK_ERROR',
      );
    } on TimeoutException catch (e) {
      throw VaultNetworkException(
        'Request timeout',
        originalError: e,
        code: 'TIMEOUT',
      );
    }
  }

  /// Perform POST request
  Future<dynamic> post(
    String path, {
    Map<String, dynamic>? body,
    bool authenticated = true,
  }) async {
    try {
      final headers = {..._defaultHeaders};
      if (authenticated) {
        headers.addAll(await _authHeaders);
      }

      final response = await _client
          .post(
            _buildUri(path),
            headers: headers,
            body: body != null ? jsonEncode(body) : null,
          )
          .timeout(timeout);

      return _handleResponse(response);
    } on SocketException catch (e) {
      throw VaultNetworkException(
        'Network error: Unable to connect to server',
        originalError: e,
        code: 'NETWORK_ERROR',
      );
    } on TimeoutException catch (e) {
      throw VaultNetworkException(
        'Request timeout',
        originalError: e,
        code: 'TIMEOUT',
      );
    }
  }

  /// Perform PATCH request
  Future<dynamic> patch(
    String path, {
    Map<String, dynamic>? body,
    bool authenticated = true,
  }) async {
    try {
      final headers = {..._defaultHeaders};
      if (authenticated) {
        headers.addAll(await _authHeaders);
      }

      final response = await _client
          .patch(
            _buildUri(path),
            headers: headers,
            body: body != null ? jsonEncode(body) : null,
          )
          .timeout(timeout);

      return _handleResponse(response);
    } on SocketException catch (e) {
      throw VaultNetworkException(
        'Network error: Unable to connect to server',
        originalError: e,
        code: 'NETWORK_ERROR',
      );
    } on TimeoutException catch (e) {
      throw VaultNetworkException(
        'Request timeout',
        originalError: e,
        code: 'TIMEOUT',
      );
    }
  }

  /// Perform DELETE request
  Future<dynamic> delete(
    String path, {
    bool authenticated = true,
  }) async {
    try {
      final headers = {..._defaultHeaders};
      if (authenticated) {
        headers.addAll(await _authHeaders);
      }

      final response = await _client
          .delete(
            _buildUri(path),
            headers: headers,
          )
          .timeout(timeout);

      return _handleResponse(response);
    } on SocketException catch (e) {
      throw VaultNetworkException(
        'Network error: Unable to connect to server',
        originalError: e,
        code: 'NETWORK_ERROR',
      );
    } on TimeoutException catch (e) {
      throw VaultNetworkException(
        'Request timeout',
        originalError: e,
        code: 'TIMEOUT',
      );
    }
  }

  /// Dispose the client
  void dispose() {
    _client.close();
    _instance = null;
  }
}

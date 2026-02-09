/**
 * Error classes for Vault Auth SDK
 */

/** Base error for Vault Auth SDK */
export class VaultAuthError extends Error {
  public readonly statusCode?: number;
  public readonly errorCode?: string;
  public readonly details?: Record<string, unknown>;
  public readonly requestId?: string;

  constructor(
    message: string,
    statusCode?: number,
    errorCode?: string,
    details?: Record<string, unknown>,
    requestId?: string
  ) {
    super(message);
    this.name = 'VaultAuthError';
    this.statusCode = statusCode;
    this.errorCode = errorCode;
    this.details = details;
    this.requestId = requestId;
  }

  toString(): string {
    const parts = [this.message];
    if (this.errorCode) {
      parts.push(`(code: ${this.errorCode})`);
    }
    if (this.requestId) {
      parts.push(`[request_id: ${this.requestId}]`);
    }
    return parts.join(' ');
  }
}

/** Raised when authentication fails (401) */
export class AuthenticationError extends VaultAuthError {
  constructor(
    message: string = 'Authentication failed',
    errorCode?: string,
    details?: Record<string, unknown>,
    requestId?: string
  ) {
    super(message, 401, errorCode, details, requestId);
    this.name = 'AuthenticationError';
  }
}

/** Raised when user lacks permission (403) */
export class AuthorizationError extends VaultAuthError {
  constructor(
    message: string = 'Not authorized',
    errorCode?: string,
    details?: Record<string, unknown>,
    requestId?: string
  ) {
    super(message, 403, errorCode, details, requestId);
    this.name = 'AuthorizationError';
  }
}

/** Raised when resource is not found (404) */
export class NotFoundError extends VaultAuthError {
  public readonly resourceType?: string;
  public readonly resourceId?: string;

  constructor(
    message?: string,
    resourceType?: string,
    resourceId?: string,
    errorCode?: string,
    details?: Record<string, unknown>,
    requestId?: string
  ) {
    let finalMessage = message || 'Resource not found';
    if (resourceType && resourceId) {
      finalMessage = `${resourceType} '${resourceId}' not found`;
    }
    super(finalMessage, 404, errorCode, details, requestId);
    this.name = 'NotFoundError';
    this.resourceType = resourceType;
    this.resourceId = resourceId;
  }
}

/** Raised when rate limit is exceeded (429) */
export class RateLimitError extends VaultAuthError {
  public readonly retryAfter?: number;

  constructor(
    message: string = 'Rate limit exceeded',
    retryAfter?: number,
    errorCode?: string,
    details?: Record<string, unknown>,
    requestId?: string
  ) {
    super(message, 429, errorCode, details, requestId);
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
  }
}

/** Raised when server returns 5xx error */
export class ServerError extends VaultAuthError {
  constructor(
    message: string = 'Internal server error',
    statusCode: number = 500,
    errorCode?: string,
    details?: Record<string, unknown>,
    requestId?: string
  ) {
    super(message, statusCode, errorCode, details, requestId);
    this.name = 'ServerError';
  }
}

/** Raised when request validation fails (400) */
export class ValidationError extends VaultAuthError {
  public readonly fieldErrors?: Record<string, string>;

  constructor(
    message: string = 'Validation failed',
    fieldErrors?: Record<string, string>,
    errorCode?: string,
    details?: Record<string, unknown>,
    requestId?: string
  ) {
    super(message, 400, errorCode, details, requestId);
    this.name = 'ValidationError';
    this.fieldErrors = fieldErrors;
  }
}

/** Raised when JWT token is expired */
export class TokenExpiredError extends AuthenticationError {
  constructor(
    message: string = 'Token has expired',
    errorCode?: string,
    details?: Record<string, unknown>,
    requestId?: string
  ) {
    super(message, errorCode, details, requestId);
    this.name = 'TokenExpiredError';
  }
}

/** Raised when JWT token is invalid */
export class InvalidTokenError extends AuthenticationError {
  constructor(
    message: string = 'Invalid token',
    errorCode?: string,
    details?: Record<string, unknown>,
    requestId?: string
  ) {
    super(message, errorCode, details, requestId);
    this.name = 'InvalidTokenError';
  }
}

/** Raised when SDK is misconfigured */
export class ConfigurationError extends VaultAuthError {
  constructor(message: string = 'Configuration error') {
    super(message, undefined, 'configuration_error');
    this.name = 'ConfigurationError';
  }
}

/** Type guard for VaultAuthError */
export function isVaultAuthError(error: unknown): error is VaultAuthError {
  return error instanceof VaultAuthError;
}

export const FantasticauthError = VaultAuthError;
export const isFantasticauthError = isVaultAuthError;

/** Convert HTTP status code to appropriate error class */
export function errorFromResponse(
  statusCode: number,
  message: string,
  errorCode?: string,
  details?: Record<string, unknown>,
  requestId?: string,
  headers?: Record<string, string>
): VaultAuthError {
  switch (statusCode) {
    case 400:
      return new ValidationError(
        message,
        details?.fields as Record<string, string>,
        errorCode,
        details,
        requestId
      );
    case 401:
      return new AuthenticationError(message, errorCode, details, requestId);
    case 403:
      return new AuthorizationError(message, errorCode, details, requestId);
    case 404:
      return new NotFoundError(message, undefined, undefined, errorCode, details, requestId);
    case 429: {
      const retryAfter = headers?.['retry-after']
        ? parseInt(headers['retry-after'], 10)
        : undefined;
      return new RateLimitError(message, retryAfter, errorCode, details, requestId);
    }
    default:
      if (statusCode >= 500) {
        return new ServerError(message, statusCode, errorCode, details, requestId);
      }
      return new VaultAuthError(message, statusCode, errorCode, details, requestId);
  }
}

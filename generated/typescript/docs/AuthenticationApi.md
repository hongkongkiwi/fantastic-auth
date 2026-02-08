# AuthenticationApi

All URIs are relative to *https://api.vault.dev/api/v1*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**forgotPassword**](AuthenticationApi.md#forgotpasswordoperation) | **POST** /auth/forgot-password | Request password reset |
| [**getCurrentUser**](AuthenticationApi.md#getcurrentuser) | **GET** /auth/me | Get current user |
| [**login**](AuthenticationApi.md#loginoperation) | **POST** /auth/login | Login with email and password |
| [**logout**](AuthenticationApi.md#logout) | **POST** /auth/logout | Logout current session |
| [**oauthCallback**](AuthenticationApi.md#oauthcallback) | **GET** /auth/oauth/{provider}/callback | OAuth callback |
| [**oauthRedirect**](AuthenticationApi.md#oauthredirect) | **POST** /auth/oauth/{provider} | Initiate OAuth login |
| [**refreshToken**](AuthenticationApi.md#refreshtoken) | **POST** /auth/refresh | Refresh access token |
| [**register**](AuthenticationApi.md#registeroperation) | **POST** /auth/register | Register new user |
| [**resetPassword**](AuthenticationApi.md#resetpasswordoperation) | **POST** /auth/reset-password | Reset password with token |
| [**sendMagicLink**](AuthenticationApi.md#sendmagiclink) | **POST** /auth/magic-link | Send magic link for passwordless login |
| [**ssoCallback**](AuthenticationApi.md#ssocallbackoperation) | **POST** /auth/sso/callback | SSO callback handler |
| [**ssoMetadata**](AuthenticationApi.md#ssometadata) | **GET** /auth/sso/metadata | Get SSO metadata (SAML) |
| [**ssoRedirect**](AuthenticationApi.md#ssoredirect) | **GET** /auth/sso/redirect | Initiate SSO login |
| [**verifyEmail**](AuthenticationApi.md#verifyemailoperation) | **POST** /auth/verify-email | Verify email address |
| [**verifyMagicLink**](AuthenticationApi.md#verifymagiclinkoperation) | **POST** /auth/magic-link/verify | Verify magic link and create session |



## forgotPassword

> MessageResponse forgotPassword(forgotPasswordRequest)

Request password reset

### Example

```ts
import {
  Configuration,
  AuthenticationApi,
} from '@vault/sdk';
import type { ForgotPasswordOperationRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const api = new AuthenticationApi();

  const body = {
    // ForgotPasswordRequest
    forgotPasswordRequest: ...,
  } satisfies ForgotPasswordOperationRequest;

  try {
    const data = await api.forgotPassword(body);
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters


| Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **forgotPasswordRequest** | [ForgotPasswordRequest](ForgotPasswordRequest.md) |  | |

### Return type

[**MessageResponse**](MessageResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Reset email sent (if email exists) |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## getCurrentUser

> UserResponse getCurrentUser()

Get current user

### Example

```ts
import {
  Configuration,
  AuthenticationApi,
} from '@vault/sdk';
import type { GetCurrentUserRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new AuthenticationApi(config);

  try {
    const data = await api.getCurrentUser();
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters

This endpoint does not need any parameter.

### Return type

[**UserResponse**](UserResponse.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Current user info |  -  |
| **401** | Authentication required |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## login

> AuthResponse login(loginRequest)

Login with email and password

### Example

```ts
import {
  Configuration,
  AuthenticationApi,
} from '@vault/sdk';
import type { LoginOperationRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const api = new AuthenticationApi();

  const body = {
    // LoginRequest
    loginRequest: ...,
  } satisfies LoginOperationRequest;

  try {
    const data = await api.login(body);
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters


| Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **loginRequest** | [LoginRequest](LoginRequest.md) |  | |

### Return type

[**AuthResponse**](AuthResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Login successful |  -  |
| **401** | Authentication required |  -  |
| **403** | Account locked or MFA required |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## logout

> MessageResponse logout()

Logout current session

### Example

```ts
import {
  Configuration,
  AuthenticationApi,
} from '@vault/sdk';
import type { LogoutRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new AuthenticationApi(config);

  try {
    const data = await api.logout();
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters

This endpoint does not need any parameter.

### Return type

[**MessageResponse**](MessageResponse.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Logged out successfully |  -  |
| **401** | Authentication required |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## oauthCallback

> AuthResponse oauthCallback(provider, code, state)

OAuth callback

### Example

```ts
import {
  Configuration,
  AuthenticationApi,
} from '@vault/sdk';
import type { OauthCallbackRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const api = new AuthenticationApi();

  const body = {
    // string
    provider: provider_example,
    // string
    code: code_example,
    // string
    state: state_example,
  } satisfies OauthCallbackRequest;

  try {
    const data = await api.oauthCallback(body);
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters


| Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **provider** | `string` |  | [Defaults to `undefined`] |
| **code** | `string` |  | [Defaults to `undefined`] |
| **state** | `string` |  | [Defaults to `undefined`] |

### Return type

[**AuthResponse**](AuthResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | OAuth login successful |  -  |
| **400** | Invalid request |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## oauthRedirect

> OauthRedirect200Response oauthRedirect(provider, oAuthRequest)

Initiate OAuth login

### Example

```ts
import {
  Configuration,
  AuthenticationApi,
} from '@vault/sdk';
import type { OauthRedirectRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const api = new AuthenticationApi();

  const body = {
    // 'google' | 'github' | 'microsoft' | 'apple' | 'discord' | 'slack'
    provider: provider_example,
    // OAuthRequest (optional)
    oAuthRequest: ...,
  } satisfies OauthRedirectRequest;

  try {
    const data = await api.oauthRedirect(body);
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters


| Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **provider** | `google`, `github`, `microsoft`, `apple`, `discord`, `slack` |  | [Defaults to `undefined`] [Enum: google, github, microsoft, apple, discord, slack] |
| **oAuthRequest** | [OAuthRequest](OAuthRequest.md) |  | [Optional] |

### Return type

[**OauthRedirect200Response**](OauthRedirect200Response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | OAuth URL generated |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## refreshToken

> AuthResponse refreshToken(refreshRequest)

Refresh access token

### Example

```ts
import {
  Configuration,
  AuthenticationApi,
} from '@vault/sdk';
import type { RefreshTokenRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const api = new AuthenticationApi();

  const body = {
    // RefreshRequest
    refreshRequest: ...,
  } satisfies RefreshTokenRequest;

  try {
    const data = await api.refreshToken(body);
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters


| Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **refreshRequest** | [RefreshRequest](RefreshRequest.md) |  | |

### Return type

[**AuthResponse**](AuthResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Token refreshed successfully |  -  |
| **401** | Authentication required |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## register

> AuthResponse register(registerRequest)

Register new user

### Example

```ts
import {
  Configuration,
  AuthenticationApi,
} from '@vault/sdk';
import type { RegisterOperationRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const api = new AuthenticationApi();

  const body = {
    // RegisterRequest
    registerRequest: ...,
  } satisfies RegisterOperationRequest;

  try {
    const data = await api.register(body);
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters


| Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **registerRequest** | [RegisterRequest](RegisterRequest.md) |  | |

### Return type

[**AuthResponse**](AuthResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | User registered successfully |  -  |
| **400** | Invalid request |  -  |
| **409** | Email already exists |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## resetPassword

> MessageResponse resetPassword(resetPasswordRequest)

Reset password with token

### Example

```ts
import {
  Configuration,
  AuthenticationApi,
} from '@vault/sdk';
import type { ResetPasswordOperationRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const api = new AuthenticationApi();

  const body = {
    // ResetPasswordRequest
    resetPasswordRequest: ...,
  } satisfies ResetPasswordOperationRequest;

  try {
    const data = await api.resetPassword(body);
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters


| Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **resetPasswordRequest** | [ResetPasswordRequest](ResetPasswordRequest.md) |  | |

### Return type

[**MessageResponse**](MessageResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Password reset successful |  -  |
| **400** | Invalid request |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## sendMagicLink

> MessageResponse sendMagicLink(magicLinkRequest)

Send magic link for passwordless login

### Example

```ts
import {
  Configuration,
  AuthenticationApi,
} from '@vault/sdk';
import type { SendMagicLinkRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const api = new AuthenticationApi();

  const body = {
    // MagicLinkRequest
    magicLinkRequest: ...,
  } satisfies SendMagicLinkRequest;

  try {
    const data = await api.sendMagicLink(body);
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters


| Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **magicLinkRequest** | [MagicLinkRequest](MagicLinkRequest.md) |  | |

### Return type

[**MessageResponse**](MessageResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Magic link sent (if email exists) |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## ssoCallback

> AuthResponse ssoCallback(ssoCallbackRequest)

SSO callback handler

### Example

```ts
import {
  Configuration,
  AuthenticationApi,
} from '@vault/sdk';
import type { SsoCallbackOperationRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const api = new AuthenticationApi();

  const body = {
    // SsoCallbackRequest
    ssoCallbackRequest: {"connectionId":"sso_123","payload":{"state":"state_abc","code":"code_xyz"}},
  } satisfies SsoCallbackOperationRequest;

  try {
    const data = await api.ssoCallback(body);
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters


| Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **ssoCallbackRequest** | [SsoCallbackRequest](SsoCallbackRequest.md) |  | |

### Return type

[**AuthResponse**](AuthResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | SSO login successful |  -  |
| **400** | Invalid request |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## ssoMetadata

> string ssoMetadata(connectionId)

Get SSO metadata (SAML)

### Example

```ts
import {
  Configuration,
  AuthenticationApi,
} from '@vault/sdk';
import type { SsoMetadataRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const api = new AuthenticationApi();

  const body = {
    // string
    connectionId: connectionId_example,
  } satisfies SsoMetadataRequest;

  try {
    const data = await api.ssoMetadata(body);
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters


| Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **connectionId** | `string` |  | [Defaults to `undefined`] |

### Return type

**string**

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/xml`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | SAML metadata |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## ssoRedirect

> SsoRedirect200Response ssoRedirect(domain, connectionId)

Initiate SSO login

### Example

```ts
import {
  Configuration,
  AuthenticationApi,
} from '@vault/sdk';
import type { SsoRedirectRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const api = new AuthenticationApi();

  const body = {
    // string (optional)
    domain: domain_example,
    // string (optional)
    connectionId: connectionId_example,
  } satisfies SsoRedirectRequest;

  try {
    const data = await api.ssoRedirect(body);
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters


| Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **domain** | `string` |  | [Optional] [Defaults to `undefined`] |
| **connectionId** | `string` |  | [Optional] [Defaults to `undefined`] |

### Return type

[**SsoRedirect200Response**](SsoRedirect200Response.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | SSO redirect URL |  -  |
| **400** | Invalid request |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## verifyEmail

> UserResponse verifyEmail(verifyEmailRequest)

Verify email address

### Example

```ts
import {
  Configuration,
  AuthenticationApi,
} from '@vault/sdk';
import type { VerifyEmailOperationRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const api = new AuthenticationApi();

  const body = {
    // VerifyEmailRequest
    verifyEmailRequest: ...,
  } satisfies VerifyEmailOperationRequest;

  try {
    const data = await api.verifyEmail(body);
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters


| Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **verifyEmailRequest** | [VerifyEmailRequest](VerifyEmailRequest.md) |  | |

### Return type

[**UserResponse**](UserResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Email verified successfully |  -  |
| **400** | Invalid request |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## verifyMagicLink

> AuthResponse verifyMagicLink(verifyMagicLinkRequest)

Verify magic link and create session

### Example

```ts
import {
  Configuration,
  AuthenticationApi,
} from '@vault/sdk';
import type { VerifyMagicLinkOperationRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const api = new AuthenticationApi();

  const body = {
    // VerifyMagicLinkRequest
    verifyMagicLinkRequest: ...,
  } satisfies VerifyMagicLinkOperationRequest;

  try {
    const data = await api.verifyMagicLink(body);
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```

### Parameters


| Name | Type | Description  | Notes |
|------------- | ------------- | ------------- | -------------|
| **verifyMagicLinkRequest** | [VerifyMagicLinkRequest](VerifyMagicLinkRequest.md) |  | |

### Return type

[**AuthResponse**](AuthResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Magic link verified, session created |  -  |
| **401** | Authentication required |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


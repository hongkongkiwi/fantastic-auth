# MFAApi

All URIs are relative to *https://api.vault.dev/api/v1*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**beginWebauthnRegistration**](MFAApi.md#beginwebauthnregistration) | **POST** /users/me/mfa/webauthn/register/begin | Begin WebAuthn registration |
| [**disableMfa**](MFAApi.md#disablemfa) | **DELETE** /users/me/mfa | Disable MFA |
| [**enableMfa**](MFAApi.md#enablemfaoperation) | **POST** /users/me/mfa | Enable MFA |
| [**finishWebauthnRegistration**](MFAApi.md#finishwebauthnregistration) | **POST** /users/me/mfa/webauthn/register/finish | Finish WebAuthn registration |
| [**generateBackupCodes**](MFAApi.md#generatebackupcodes) | **POST** /users/me/mfa/backup-codes | Generate MFA backup codes |
| [**getMfaStatus**](MFAApi.md#getmfastatus) | **GET** /users/me/mfa | Get MFA status |
| [**verifyBackupCode**](MFAApi.md#verifybackupcode) | **POST** /users/me/mfa/backup-codes/verify | Verify backup code |



## beginWebauthnRegistration

> WebauthnBeginResponse beginWebauthnRegistration()

Begin WebAuthn registration

### Example

```ts
import {
  Configuration,
  MFAApi,
} from '@vault/sdk';
import type { BeginWebauthnRegistrationRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new MFAApi(config);

  try {
    const data = await api.beginWebauthnRegistration();
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

[**WebauthnBeginResponse**](WebauthnBeginResponse.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | WebAuthn registration options |  -  |
| **401** | Authentication required |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## disableMfa

> MessageResponse disableMfa(verifyMfaRequest)

Disable MFA

### Example

```ts
import {
  Configuration,
  MFAApi,
} from '@vault/sdk';
import type { DisableMfaRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new MFAApi(config);

  const body = {
    // VerifyMfaRequest
    verifyMfaRequest: ...,
  } satisfies DisableMfaRequest;

  try {
    const data = await api.disableMfa(body);
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
| **verifyMfaRequest** | [VerifyMfaRequest](VerifyMfaRequest.md) |  | |

### Return type

[**MessageResponse**](MessageResponse.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | MFA disabled |  -  |
| **401** | Authentication required |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## enableMfa

> EnableMfa200Response enableMfa(enableMfaRequest)

Enable MFA

### Example

```ts
import {
  Configuration,
  MFAApi,
} from '@vault/sdk';
import type { EnableMfaOperationRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new MFAApi(config);

  const body = {
    // EnableMfaRequest
    enableMfaRequest: ...,
  } satisfies EnableMfaOperationRequest;

  try {
    const data = await api.enableMfa(body);
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
| **enableMfaRequest** | [EnableMfaRequest](EnableMfaRequest.md) |  | |

### Return type

[**EnableMfa200Response**](EnableMfa200Response.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | MFA setup initiated |  -  |
| **400** | Invalid request |  -  |
| **401** | Authentication required |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## finishWebauthnRegistration

> MessageResponse finishWebauthnRegistration(webauthnFinishRequest)

Finish WebAuthn registration

### Example

```ts
import {
  Configuration,
  MFAApi,
} from '@vault/sdk';
import type { FinishWebauthnRegistrationRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new MFAApi(config);

  const body = {
    // WebauthnFinishRequest
    webauthnFinishRequest: {"credential":{"id":"cred_123","type":"public-key"}},
  } satisfies FinishWebauthnRegistrationRequest;

  try {
    const data = await api.finishWebauthnRegistration(body);
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
| **webauthnFinishRequest** | [WebauthnFinishRequest](WebauthnFinishRequest.md) |  | |

### Return type

[**MessageResponse**](MessageResponse.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | WebAuthn device registered |  -  |
| **400** | Invalid request |  -  |
| **401** | Authentication required |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## generateBackupCodes

> BackupCodesResponse generateBackupCodes()

Generate MFA backup codes

### Example

```ts
import {
  Configuration,
  MFAApi,
} from '@vault/sdk';
import type { GenerateBackupCodesRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new MFAApi(config);

  try {
    const data = await api.generateBackupCodes();
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

[**BackupCodesResponse**](BackupCodesResponse.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Backup codes generated |  -  |
| **401** | Authentication required |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## getMfaStatus

> MfaStatusResponse getMfaStatus()

Get MFA status

### Example

```ts
import {
  Configuration,
  MFAApi,
} from '@vault/sdk';
import type { GetMfaStatusRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new MFAApi(config);

  try {
    const data = await api.getMfaStatus();
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

[**MfaStatusResponse**](MfaStatusResponse.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | MFA status |  -  |
| **401** | Authentication required |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## verifyBackupCode

> MessageResponse verifyBackupCode(backupCodeVerifyRequest)

Verify backup code

### Example

```ts
import {
  Configuration,
  MFAApi,
} from '@vault/sdk';
import type { VerifyBackupCodeRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new MFAApi(config);

  const body = {
    // BackupCodeVerifyRequest
    backupCodeVerifyRequest: {"code":"ABCD-EFGH"},
  } satisfies VerifyBackupCodeRequest;

  try {
    const data = await api.verifyBackupCode(body);
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
| **backupCodeVerifyRequest** | [BackupCodeVerifyRequest](BackupCodeVerifyRequest.md) |  | |

### Return type

[**MessageResponse**](MessageResponse.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Backup code verified |  -  |
| **400** | Invalid request |  -  |
| **401** | Authentication required |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


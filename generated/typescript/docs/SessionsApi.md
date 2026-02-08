# SessionsApi

All URIs are relative to *https://api.vault.dev/api/v1*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**listSessions**](SessionsApi.md#listsessions) | **GET** /users/me/sessions | List active sessions |
| [**logoutAllSessions**](SessionsApi.md#logoutallsessions) | **DELETE** /users/me/sessions | Logout all sessions |
| [**revokeSession**](SessionsApi.md#revokesession) | **DELETE** /users/me/sessions/{sessionId} | Revoke specific session |



## listSessions

> Array&lt;SessionResponse&gt; listSessions()

List active sessions

### Example

```ts
import {
  Configuration,
  SessionsApi,
} from '@vault/sdk';
import type { ListSessionsRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new SessionsApi(config);

  try {
    const data = await api.listSessions();
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

[**Array&lt;SessionResponse&gt;**](SessionResponse.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | List of sessions |  -  |
| **401** | Authentication required |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## logoutAllSessions

> MessageResponse logoutAllSessions()

Logout all sessions

### Example

```ts
import {
  Configuration,
  SessionsApi,
} from '@vault/sdk';
import type { LogoutAllSessionsRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new SessionsApi(config);

  try {
    const data = await api.logoutAllSessions();
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
| **200** | All sessions revoked |  -  |
| **401** | Authentication required |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## revokeSession

> MessageResponse revokeSession(sessionId)

Revoke specific session

### Example

```ts
import {
  Configuration,
  SessionsApi,
} from '@vault/sdk';
import type { RevokeSessionRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new SessionsApi(config);

  const body = {
    // string
    sessionId: sessionId_example,
  } satisfies RevokeSessionRequest;

  try {
    const data = await api.revokeSession(body);
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
| **sessionId** | `string` |  | [Defaults to `undefined`] |

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
| **200** | Session revoked |  -  |
| **401** | Authentication required |  -  |
| **404** | Resource not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


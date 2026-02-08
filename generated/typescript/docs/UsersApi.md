# UsersApi

All URIs are relative to *https://api.vault.dev/api/v1*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**changePassword**](UsersApi.md#changepasswordoperation) | **PATCH** /users/me/password | Change password |
| [**deleteMe**](UsersApi.md#deleteme) | **DELETE** /users/me | Delete user account |
| [**getMe**](UsersApi.md#getme) | **GET** /users/me | Get current user profile |
| [**updateMe**](UsersApi.md#updateme) | **PATCH** /users/me | Update user profile |



## changePassword

> MessageResponse changePassword(changePasswordRequest)

Change password

### Example

```ts
import {
  Configuration,
  UsersApi,
} from '@vault/sdk';
import type { ChangePasswordOperationRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new UsersApi(config);

  const body = {
    // ChangePasswordRequest
    changePasswordRequest: ...,
  } satisfies ChangePasswordOperationRequest;

  try {
    const data = await api.changePassword(body);
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
| **changePasswordRequest** | [ChangePasswordRequest](ChangePasswordRequest.md) |  | |

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
| **200** | Password changed |  -  |
| **400** | Invalid request |  -  |
| **401** | Authentication required |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## deleteMe

> MessageResponse deleteMe()

Delete user account

### Example

```ts
import {
  Configuration,
  UsersApi,
} from '@vault/sdk';
import type { DeleteMeRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new UsersApi(config);

  try {
    const data = await api.deleteMe();
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
| **200** | Account deleted |  -  |
| **401** | Authentication required |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## getMe

> UserProfileResponse getMe()

Get current user profile

### Example

```ts
import {
  Configuration,
  UsersApi,
} from '@vault/sdk';
import type { GetMeRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new UsersApi(config);

  try {
    const data = await api.getMe();
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

[**UserProfileResponse**](UserProfileResponse.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | User profile |  -  |
| **401** | Authentication required |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## updateMe

> UserProfileResponse updateMe(updateProfileRequest)

Update user profile

### Example

```ts
import {
  Configuration,
  UsersApi,
} from '@vault/sdk';
import type { UpdateMeRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new UsersApi(config);

  const body = {
    // UpdateProfileRequest
    updateProfileRequest: ...,
  } satisfies UpdateMeRequest;

  try {
    const data = await api.updateMe(body);
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
| **updateProfileRequest** | [UpdateProfileRequest](UpdateProfileRequest.md) |  | |

### Return type

[**UserProfileResponse**](UserProfileResponse.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Profile updated |  -  |
| **400** | Invalid request |  -  |
| **401** | Authentication required |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


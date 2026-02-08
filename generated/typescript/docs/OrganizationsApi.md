# OrganizationsApi

All URIs are relative to *https://api.vault.dev/api/v1*

| Method | HTTP request | Description |
|------------- | ------------- | -------------|
| [**acceptInvitation**](OrganizationsApi.md#acceptinvitation) | **POST** /organizations/invitations/{token}/accept | Accept organization invitation |
| [**createOrganization**](OrganizationsApi.md#createorganization) | **POST** /organizations | Create organization |
| [**deleteOrganization**](OrganizationsApi.md#deleteorganization) | **DELETE** /organizations/{orgId} | Delete organization |
| [**getOrganization**](OrganizationsApi.md#getorganization) | **GET** /organizations/{orgId} | Get organization |
| [**inviteMember**](OrganizationsApi.md#invitememberoperation) | **POST** /organizations/{orgId}/members | Invite member |
| [**listInvitations**](OrganizationsApi.md#listinvitations) | **GET** /organizations/{orgId}/invitations | List pending invitations |
| [**listMembers**](OrganizationsApi.md#listmembers) | **GET** /organizations/{orgId}/members | List organization members |
| [**listOrganizations**](OrganizationsApi.md#listorganizations) | **GET** /organizations | List organizations |
| [**removeMember**](OrganizationsApi.md#removemember) | **DELETE** /organizations/{orgId}/members/{userId} | Remove member |
| [**updateMember**](OrganizationsApi.md#updatememberoperation) | **PATCH** /organizations/{orgId}/members/{userId} | Update member role |
| [**updateOrganization**](OrganizationsApi.md#updateorganization) | **PATCH** /organizations/{orgId} | Update organization |



## acceptInvitation

> OrganizationResponse acceptInvitation(token)

Accept organization invitation

### Example

```ts
import {
  Configuration,
  OrganizationsApi,
} from '@vault/sdk';
import type { AcceptInvitationRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new OrganizationsApi(config);

  const body = {
    // string
    token: token_example,
  } satisfies AcceptInvitationRequest;

  try {
    const data = await api.acceptInvitation(body);
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
| **token** | `string` |  | [Defaults to `undefined`] |

### Return type

[**OrganizationResponse**](OrganizationResponse.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Invitation accepted |  -  |
| **400** | Invalid request |  -  |
| **401** | Authentication required |  -  |
| **404** | Resource not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## createOrganization

> OrganizationResponse createOrganization(createOrgRequest)

Create organization

### Example

```ts
import {
  Configuration,
  OrganizationsApi,
} from '@vault/sdk';
import type { CreateOrganizationRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new OrganizationsApi(config);

  const body = {
    // CreateOrgRequest
    createOrgRequest: ...,
  } satisfies CreateOrganizationRequest;

  try {
    const data = await api.createOrganization(body);
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
| **createOrgRequest** | [CreateOrgRequest](CreateOrgRequest.md) |  | |

### Return type

[**OrganizationResponse**](OrganizationResponse.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **201** | Organization created |  -  |
| **400** | Invalid request |  -  |
| **401** | Authentication required |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## deleteOrganization

> MessageResponse deleteOrganization(orgId)

Delete organization

### Example

```ts
import {
  Configuration,
  OrganizationsApi,
} from '@vault/sdk';
import type { DeleteOrganizationRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new OrganizationsApi(config);

  const body = {
    // string
    orgId: orgId_example,
  } satisfies DeleteOrganizationRequest;

  try {
    const data = await api.deleteOrganization(body);
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
| **orgId** | `string` |  | [Defaults to `undefined`] |

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
| **200** | Organization deleted |  -  |
| **401** | Authentication required |  -  |
| **403** | Permission denied |  -  |
| **404** | Resource not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## getOrganization

> OrganizationResponse getOrganization(orgId)

Get organization

### Example

```ts
import {
  Configuration,
  OrganizationsApi,
} from '@vault/sdk';
import type { GetOrganizationRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new OrganizationsApi(config);

  const body = {
    // string
    orgId: orgId_example,
  } satisfies GetOrganizationRequest;

  try {
    const data = await api.getOrganization(body);
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
| **orgId** | `string` |  | [Defaults to `undefined`] |

### Return type

[**OrganizationResponse**](OrganizationResponse.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Organization details |  -  |
| **401** | Authentication required |  -  |
| **404** | Resource not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## inviteMember

> InvitationResponse inviteMember(orgId, inviteMemberRequest)

Invite member

### Example

```ts
import {
  Configuration,
  OrganizationsApi,
} from '@vault/sdk';
import type { InviteMemberOperationRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new OrganizationsApi(config);

  const body = {
    // string
    orgId: orgId_example,
    // InviteMemberRequest
    inviteMemberRequest: ...,
  } satisfies InviteMemberOperationRequest;

  try {
    const data = await api.inviteMember(body);
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
| **orgId** | `string` |  | [Defaults to `undefined`] |
| **inviteMemberRequest** | [InviteMemberRequest](InviteMemberRequest.md) |  | |

### Return type

[**InvitationResponse**](InvitationResponse.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **201** | Invitation sent |  -  |
| **400** | Invalid request |  -  |
| **401** | Authentication required |  -  |
| **403** | Permission denied |  -  |
| **404** | Resource not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## listInvitations

> Array&lt;InvitationResponse&gt; listInvitations(orgId)

List pending invitations

### Example

```ts
import {
  Configuration,
  OrganizationsApi,
} from '@vault/sdk';
import type { ListInvitationsRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new OrganizationsApi(config);

  const body = {
    // string
    orgId: orgId_example,
  } satisfies ListInvitationsRequest;

  try {
    const data = await api.listInvitations(body);
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
| **orgId** | `string` |  | [Defaults to `undefined`] |

### Return type

[**Array&lt;InvitationResponse&gt;**](InvitationResponse.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | List of invitations |  -  |
| **401** | Authentication required |  -  |
| **404** | Resource not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## listMembers

> Array&lt;OrganizationMemberResponse&gt; listMembers(orgId)

List organization members

### Example

```ts
import {
  Configuration,
  OrganizationsApi,
} from '@vault/sdk';
import type { ListMembersRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new OrganizationsApi(config);

  const body = {
    // string
    orgId: orgId_example,
  } satisfies ListMembersRequest;

  try {
    const data = await api.listMembers(body);
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
| **orgId** | `string` |  | [Defaults to `undefined`] |

### Return type

[**Array&lt;OrganizationMemberResponse&gt;**](OrganizationMemberResponse.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | List of members |  -  |
| **401** | Authentication required |  -  |
| **404** | Resource not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## listOrganizations

> Array&lt;OrganizationResponse&gt; listOrganizations()

List organizations

### Example

```ts
import {
  Configuration,
  OrganizationsApi,
} from '@vault/sdk';
import type { ListOrganizationsRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new OrganizationsApi(config);

  try {
    const data = await api.listOrganizations();
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

[**Array&lt;OrganizationResponse&gt;**](OrganizationResponse.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | List of organizations |  -  |
| **401** | Authentication required |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## removeMember

> MessageResponse removeMember(orgId, userId)

Remove member

### Example

```ts
import {
  Configuration,
  OrganizationsApi,
} from '@vault/sdk';
import type { RemoveMemberRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new OrganizationsApi(config);

  const body = {
    // string
    orgId: orgId_example,
    // string
    userId: userId_example,
  } satisfies RemoveMemberRequest;

  try {
    const data = await api.removeMember(body);
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
| **orgId** | `string` |  | [Defaults to `undefined`] |
| **userId** | `string` |  | [Defaults to `undefined`] |

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
| **200** | Member removed |  -  |
| **401** | Authentication required |  -  |
| **403** | Permission denied |  -  |
| **404** | Resource not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## updateMember

> OrganizationMemberResponse updateMember(orgId, userId, updateMemberRequest)

Update member role

### Example

```ts
import {
  Configuration,
  OrganizationsApi,
} from '@vault/sdk';
import type { UpdateMemberOperationRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new OrganizationsApi(config);

  const body = {
    // string
    orgId: orgId_example,
    // string
    userId: userId_example,
    // UpdateMemberRequest
    updateMemberRequest: ...,
  } satisfies UpdateMemberOperationRequest;

  try {
    const data = await api.updateMember(body);
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
| **orgId** | `string` |  | [Defaults to `undefined`] |
| **userId** | `string` |  | [Defaults to `undefined`] |
| **updateMemberRequest** | [UpdateMemberRequest](UpdateMemberRequest.md) |  | |

### Return type

[**OrganizationMemberResponse**](OrganizationMemberResponse.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Member updated |  -  |
| **401** | Authentication required |  -  |
| **403** | Permission denied |  -  |
| **404** | Resource not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


## updateOrganization

> OrganizationResponse updateOrganization(orgId, updateOrgRequest)

Update organization

### Example

```ts
import {
  Configuration,
  OrganizationsApi,
} from '@vault/sdk';
import type { UpdateOrganizationRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const config = new Configuration({ 
    // Configure HTTP bearer authorization: bearerAuth
    accessToken: "YOUR BEARER TOKEN",
  });
  const api = new OrganizationsApi(config);

  const body = {
    // string
    orgId: orgId_example,
    // UpdateOrgRequest
    updateOrgRequest: ...,
  } satisfies UpdateOrganizationRequest;

  try {
    const data = await api.updateOrganization(body);
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
| **orgId** | `string` |  | [Defaults to `undefined`] |
| **updateOrgRequest** | [UpdateOrgRequest](UpdateOrgRequest.md) |  | |

### Return type

[**OrganizationResponse**](OrganizationResponse.md)

### Authorization

[bearerAuth](../README.md#bearerAuth)

### HTTP request headers

- **Content-Type**: `application/json`
- **Accept**: `application/json`


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
| **200** | Organization updated |  -  |
| **401** | Authentication required |  -  |
| **403** | Permission denied |  -  |
| **404** | Resource not found |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)


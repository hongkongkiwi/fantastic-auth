
# UserProfileResponse


## Properties

Name | Type
------------ | -------------
`id` | string
`email` | string
`emailVerified` | boolean
`name` | string
`givenName` | string
`familyName` | string
`picture` | string
`mfaEnabled` | boolean
`mfaMethods` | Array&lt;string&gt;
`oauthConnections` | [Array&lt;OAuthConnectionResponse&gt;](OAuthConnectionResponse.md)
`createdAt` | Date

## Example

```typescript
import type { UserProfileResponse } from '@vault/sdk'

// TODO: Update the object below with actual values
const example = {
  "id": null,
  "email": null,
  "emailVerified": null,
  "name": null,
  "givenName": null,
  "familyName": null,
  "picture": null,
  "mfaEnabled": null,
  "mfaMethods": null,
  "oauthConnections": null,
  "createdAt": null,
} satisfies UserProfileResponse

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as UserProfileResponse
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)



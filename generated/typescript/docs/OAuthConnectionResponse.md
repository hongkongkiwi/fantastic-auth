
# OAuthConnectionResponse


## Properties

Name | Type
------------ | -------------
`provider` | string
`providerUserId` | string
`providerUsername` | string
`email` | string
`connectedAt` | Date

## Example

```typescript
import type { OAuthConnectionResponse } from '@vault/sdk'

// TODO: Update the object below with actual values
const example = {
  "provider": google,
  "providerUserId": null,
  "providerUsername": null,
  "email": null,
  "connectedAt": null,
} satisfies OAuthConnectionResponse

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as OAuthConnectionResponse
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)



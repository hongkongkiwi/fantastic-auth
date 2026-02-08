
# InvitationResponse


## Properties

Name | Type
------------ | -------------
`id` | string
`email` | string
`role` | string
`invitedBy` | string
`expiresAt` | Date
`createdAt` | Date

## Example

```typescript
import type { InvitationResponse } from '@vault/sdk'

// TODO: Update the object below with actual values
const example = {
  "id": null,
  "email": null,
  "role": null,
  "invitedBy": null,
  "expiresAt": null,
  "createdAt": null,
} satisfies InvitationResponse

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as InvitationResponse
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)



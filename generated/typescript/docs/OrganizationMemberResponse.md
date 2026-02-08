
# OrganizationMemberResponse


## Properties

Name | Type
------------ | -------------
`id` | string
`userId` | string
`email` | string
`name` | string
`role` | string
`status` | string
`joinedAt` | Date

## Example

```typescript
import type { OrganizationMemberResponse } from '@vault/sdk'

// TODO: Update the object below with actual values
const example = {
  "id": null,
  "userId": null,
  "email": null,
  "name": null,
  "role": null,
  "status": null,
  "joinedAt": null,
} satisfies OrganizationMemberResponse

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as OrganizationMemberResponse
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)



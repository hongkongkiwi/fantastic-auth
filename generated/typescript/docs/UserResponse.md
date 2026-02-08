
# UserResponse


## Properties

Name | Type
------------ | -------------
`id` | string
`email` | string
`emailVerified` | boolean
`name` | string
`mfaEnabled` | boolean

## Example

```typescript
import type { UserResponse } from '@vault/sdk'

// TODO: Update the object below with actual values
const example = {
  "id": usr_1234567890,
  "email": null,
  "emailVerified": null,
  "name": null,
  "mfaEnabled": null,
} satisfies UserResponse

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as UserResponse
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)



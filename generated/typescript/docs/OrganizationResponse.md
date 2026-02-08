
# OrganizationResponse


## Properties

Name | Type
------------ | -------------
`id` | string
`name` | string
`slug` | string
`description` | string
`logoUrl` | string
`website` | string
`memberCount` | number
`maxMembers` | number
`ssoRequired` | boolean
`createdAt` | Date
`updatedAt` | Date

## Example

```typescript
import type { OrganizationResponse } from '@vault/sdk'

// TODO: Update the object below with actual values
const example = {
  "id": null,
  "name": null,
  "slug": null,
  "description": null,
  "logoUrl": null,
  "website": null,
  "memberCount": null,
  "maxMembers": null,
  "ssoRequired": null,
  "createdAt": null,
  "updatedAt": null,
} satisfies OrganizationResponse

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as OrganizationResponse
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)



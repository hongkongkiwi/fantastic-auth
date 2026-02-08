
# SessionResponse


## Properties

Name | Type
------------ | -------------
`id` | string
`ipAddress` | string
`userAgent` | string
`deviceInfo` | [DeviceInfoResponse](DeviceInfoResponse.md)
`mfaVerified` | boolean
`createdAt` | Date
`lastActivityAt` | Date
`expiresAt` | Date
`current` | boolean

## Example

```typescript
import type { SessionResponse } from '@vault/sdk'

// TODO: Update the object below with actual values
const example = {
  "id": null,
  "ipAddress": null,
  "userAgent": null,
  "deviceInfo": null,
  "mfaVerified": null,
  "createdAt": null,
  "lastActivityAt": null,
  "expiresAt": null,
  "current": null,
} satisfies SessionResponse

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as SessionResponse
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)



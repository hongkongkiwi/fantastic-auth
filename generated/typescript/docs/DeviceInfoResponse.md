
# DeviceInfoResponse


## Properties

Name | Type
------------ | -------------
`deviceType` | string
`os` | string
`browser` | string
`isMobile` | boolean

## Example

```typescript
import type { DeviceInfoResponse } from '@vault/sdk'

// TODO: Update the object below with actual values
const example = {
  "deviceType": null,
  "os": macOS,
  "browser": Chrome,
  "isMobile": null,
} satisfies DeviceInfoResponse

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as DeviceInfoResponse
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)




# MfaStatusResponse


## Properties

Name | Type
------------ | -------------
`enabled` | boolean
`methods` | [Array&lt;MfaMethodResponse&gt;](MfaMethodResponse.md)

## Example

```typescript
import type { MfaStatusResponse } from '@vault/sdk'

// TODO: Update the object below with actual values
const example = {
  "enabled": null,
  "methods": null,
} satisfies MfaStatusResponse

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as MfaStatusResponse
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)



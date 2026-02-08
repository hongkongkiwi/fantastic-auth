
# SsoCallbackRequest


## Properties

Name | Type
------------ | -------------
`connectionId` | string
`payload` | object

## Example

```typescript
import type { SsoCallbackRequest } from '@vault/sdk'

// TODO: Update the object below with actual values
const example = {
  "connectionId": null,
  "payload": null,
} satisfies SsoCallbackRequest

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as SsoCallbackRequest
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)



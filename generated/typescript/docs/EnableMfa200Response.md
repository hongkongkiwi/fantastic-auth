
# EnableMfa200Response


## Properties

Name | Type
------------ | -------------
`secret` | string
`qrCodeUri` | string
`backupCodes` | Array&lt;string&gt;
`message` | string

## Example

```typescript
import type { EnableMfa200Response } from '@vault/sdk'

// TODO: Update the object below with actual values
const example = {
  "secret": null,
  "qrCodeUri": null,
  "backupCodes": null,
  "message": Operation completed successfully,
} satisfies EnableMfa200Response

console.log(example)

// Convert the instance to a JSON string
const exampleJSON: string = JSON.stringify(example)
console.log(exampleJSON)

// Parse the JSON string back to an object
const exampleParsed = JSON.parse(exampleJSON) as EnableMfa200Response
console.log(exampleParsed)
```

[[Back to top]](#) [[Back to API list]](../README.md#api-endpoints) [[Back to Model list]](../README.md#models) [[Back to README]](../README.md)



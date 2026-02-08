#!/bin/bash
# OpenAPI Client SDK Generator Script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENAPI_SPEC="$SCRIPT_DIR/vault-api.yaml"

echo "=== Vault OpenAPI SDK Generator ==="

# Choose generator command (prefer global binary, fallback to npx)
GEN_CMD="openapi-generator"
if ! command -v openapi-generator &> /dev/null; then
    GEN_CMD="npx @openapitools/openapi-generator-cli"
fi

# Generate TypeScript client
echo ""
echo "Generating TypeScript client SDK..."

mkdir -p "$SCRIPT_DIR/../generated"

$GEN_CMD generate \
    -i "$OPENAPI_SPEC" \
    -g typescript-fetch \
    -o "$SCRIPT_DIR/../generated/typescript" \
    --additional-properties="supportsES6=true,npmName=@vault/sdk,npmVersion=0.1.0,typescriptThreePlus=true,modelPropertyNaming=original,enumPropertyNaming=original"

echo ""
echo "TypeScript SDK generated in: $SCRIPT_DIR/../generated/typescript"

# Generate additional clients (commented out by default)
# echo ""
# echo "Generating Python client SDK..."
# openapi-generator generate \
#     -i "$OPENAPI_SPEC" \
#     -g python \
#     -o "$SCRIPT_DIR/../generated/python" \
#     --additional-properties=packageName=vault_sdk

# echo ""
# echo "Generating Go client SDK..."
# openapi-generator generate \
#     -i "$OPENAPI_SPEC" \
#     -g go \
#     -o "$SCRIPT_DIR/../generated/go" \
#     --additional-properties=packageName=vaultsdk

echo ""
echo "=== Generation Complete ==="

#!/bin/bash
set -e

# Health check for Vault API
curl -sf http://localhost:3000/health || exit 1

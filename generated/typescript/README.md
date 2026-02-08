# @vault/sdk@0.1.0

A TypeScript SDK client for the api.vault.dev API.

## Usage

First, install the SDK from npm.

```bash
npm install @vault/sdk --save
```

Next, try it out.


```ts
import {
  Configuration,
  AuthenticationApi,
} from '@vault/sdk';
import type { ForgotPasswordOperationRequest } from '@vault/sdk';

async function example() {
  console.log("🚀 Testing @vault/sdk SDK...");
  const api = new AuthenticationApi();

  const body = {
    // ForgotPasswordRequest
    forgotPasswordRequest: ...,
  } satisfies ForgotPasswordOperationRequest;

  try {
    const data = await api.forgotPassword(body);
    console.log(data);
  } catch (error) {
    console.error(error);
  }
}

// Run the test
example().catch(console.error);
```


## Documentation

### API Endpoints

All URIs are relative to *https://api.vault.dev/api/v1*

| Class | Method | HTTP request | Description
| ----- | ------ | ------------ | -------------
*AuthenticationApi* | [**forgotPassword**](docs/AuthenticationApi.md#forgotpasswordoperation) | **POST** /auth/forgot-password | Request password reset
*AuthenticationApi* | [**getCurrentUser**](docs/AuthenticationApi.md#getcurrentuser) | **GET** /auth/me | Get current user
*AuthenticationApi* | [**login**](docs/AuthenticationApi.md#loginoperation) | **POST** /auth/login | Login with email and password
*AuthenticationApi* | [**logout**](docs/AuthenticationApi.md#logout) | **POST** /auth/logout | Logout current session
*AuthenticationApi* | [**oauthCallback**](docs/AuthenticationApi.md#oauthcallback) | **GET** /auth/oauth/{provider}/callback | OAuth callback
*AuthenticationApi* | [**oauthRedirect**](docs/AuthenticationApi.md#oauthredirect) | **POST** /auth/oauth/{provider} | Initiate OAuth login
*AuthenticationApi* | [**refreshToken**](docs/AuthenticationApi.md#refreshtoken) | **POST** /auth/refresh | Refresh access token
*AuthenticationApi* | [**register**](docs/AuthenticationApi.md#registeroperation) | **POST** /auth/register | Register new user
*AuthenticationApi* | [**resetPassword**](docs/AuthenticationApi.md#resetpasswordoperation) | **POST** /auth/reset-password | Reset password with token
*AuthenticationApi* | [**sendMagicLink**](docs/AuthenticationApi.md#sendmagiclink) | **POST** /auth/magic-link | Send magic link for passwordless login
*AuthenticationApi* | [**ssoCallback**](docs/AuthenticationApi.md#ssocallbackoperation) | **POST** /auth/sso/callback | SSO callback handler
*AuthenticationApi* | [**ssoMetadata**](docs/AuthenticationApi.md#ssometadata) | **GET** /auth/sso/metadata | Get SSO metadata (SAML)
*AuthenticationApi* | [**ssoRedirect**](docs/AuthenticationApi.md#ssoredirect) | **GET** /auth/sso/redirect | Initiate SSO login
*AuthenticationApi* | [**verifyEmail**](docs/AuthenticationApi.md#verifyemailoperation) | **POST** /auth/verify-email | Verify email address
*AuthenticationApi* | [**verifyMagicLink**](docs/AuthenticationApi.md#verifymagiclinkoperation) | **POST** /auth/magic-link/verify | Verify magic link and create session
*HealthApi* | [**healthCheck**](docs/HealthApi.md#healthcheck) | **GET** /health | Health check
*MFAApi* | [**beginWebauthnRegistration**](docs/MFAApi.md#beginwebauthnregistration) | **POST** /users/me/mfa/webauthn/register/begin | Begin WebAuthn registration
*MFAApi* | [**disableMfa**](docs/MFAApi.md#disablemfa) | **DELETE** /users/me/mfa | Disable MFA
*MFAApi* | [**enableMfa**](docs/MFAApi.md#enablemfaoperation) | **POST** /users/me/mfa | Enable MFA
*MFAApi* | [**finishWebauthnRegistration**](docs/MFAApi.md#finishwebauthnregistration) | **POST** /users/me/mfa/webauthn/register/finish | Finish WebAuthn registration
*MFAApi* | [**generateBackupCodes**](docs/MFAApi.md#generatebackupcodes) | **POST** /users/me/mfa/backup-codes | Generate MFA backup codes
*MFAApi* | [**getMfaStatus**](docs/MFAApi.md#getmfastatus) | **GET** /users/me/mfa | Get MFA status
*MFAApi* | [**verifyBackupCode**](docs/MFAApi.md#verifybackupcode) | **POST** /users/me/mfa/backup-codes/verify | Verify backup code
*OrganizationsApi* | [**acceptInvitation**](docs/OrganizationsApi.md#acceptinvitation) | **POST** /organizations/invitations/{token}/accept | Accept organization invitation
*OrganizationsApi* | [**createOrganization**](docs/OrganizationsApi.md#createorganization) | **POST** /organizations | Create organization
*OrganizationsApi* | [**deleteOrganization**](docs/OrganizationsApi.md#deleteorganization) | **DELETE** /organizations/{orgId} | Delete organization
*OrganizationsApi* | [**getOrganization**](docs/OrganizationsApi.md#getorganization) | **GET** /organizations/{orgId} | Get organization
*OrganizationsApi* | [**inviteMember**](docs/OrganizationsApi.md#invitememberoperation) | **POST** /organizations/{orgId}/members | Invite member
*OrganizationsApi* | [**listInvitations**](docs/OrganizationsApi.md#listinvitations) | **GET** /organizations/{orgId}/invitations | List pending invitations
*OrganizationsApi* | [**listMembers**](docs/OrganizationsApi.md#listmembers) | **GET** /organizations/{orgId}/members | List organization members
*OrganizationsApi* | [**listOrganizations**](docs/OrganizationsApi.md#listorganizations) | **GET** /organizations | List organizations
*OrganizationsApi* | [**removeMember**](docs/OrganizationsApi.md#removemember) | **DELETE** /organizations/{orgId}/members/{userId} | Remove member
*OrganizationsApi* | [**updateMember**](docs/OrganizationsApi.md#updatememberoperation) | **PATCH** /organizations/{orgId}/members/{userId} | Update member role
*OrganizationsApi* | [**updateOrganization**](docs/OrganizationsApi.md#updateorganization) | **PATCH** /organizations/{orgId} | Update organization
*SessionsApi* | [**listSessions**](docs/SessionsApi.md#listsessions) | **GET** /users/me/sessions | List active sessions
*SessionsApi* | [**logoutAllSessions**](docs/SessionsApi.md#logoutallsessions) | **DELETE** /users/me/sessions | Logout all sessions
*SessionsApi* | [**revokeSession**](docs/SessionsApi.md#revokesession) | **DELETE** /users/me/sessions/{sessionId} | Revoke specific session
*UsersApi* | [**changePassword**](docs/UsersApi.md#changepasswordoperation) | **PATCH** /users/me/password | Change password
*UsersApi* | [**deleteMe**](docs/UsersApi.md#deleteme) | **DELETE** /users/me | Delete user account
*UsersApi* | [**getMe**](docs/UsersApi.md#getme) | **GET** /users/me | Get current user profile
*UsersApi* | [**updateMe**](docs/UsersApi.md#updateme) | **PATCH** /users/me | Update user profile


### Models

- [AuthResponse](docs/AuthResponse.md)
- [BackupCodeVerifyRequest](docs/BackupCodeVerifyRequest.md)
- [BackupCodesResponse](docs/BackupCodesResponse.md)
- [ChangePasswordRequest](docs/ChangePasswordRequest.md)
- [CreateOrgRequest](docs/CreateOrgRequest.md)
- [DeviceInfoResponse](docs/DeviceInfoResponse.md)
- [EnableMfa200Response](docs/EnableMfa200Response.md)
- [EnableMfaRequest](docs/EnableMfaRequest.md)
- [ErrorResponse](docs/ErrorResponse.md)
- [ErrorResponseError](docs/ErrorResponseError.md)
- [ForgotPasswordRequest](docs/ForgotPasswordRequest.md)
- [HealthResponse](docs/HealthResponse.md)
- [InvitationResponse](docs/InvitationResponse.md)
- [InviteMemberRequest](docs/InviteMemberRequest.md)
- [LoginRequest](docs/LoginRequest.md)
- [MagicLinkRequest](docs/MagicLinkRequest.md)
- [MessageResponse](docs/MessageResponse.md)
- [MfaMethodResponse](docs/MfaMethodResponse.md)
- [MfaStatusResponse](docs/MfaStatusResponse.md)
- [OAuthConnectionResponse](docs/OAuthConnectionResponse.md)
- [OAuthRequest](docs/OAuthRequest.md)
- [OauthRedirect200Response](docs/OauthRedirect200Response.md)
- [OrganizationMemberResponse](docs/OrganizationMemberResponse.md)
- [OrganizationResponse](docs/OrganizationResponse.md)
- [RefreshRequest](docs/RefreshRequest.md)
- [RegisterRequest](docs/RegisterRequest.md)
- [ResetPasswordRequest](docs/ResetPasswordRequest.md)
- [SessionResponse](docs/SessionResponse.md)
- [SsoCallbackRequest](docs/SsoCallbackRequest.md)
- [SsoRedirect200Response](docs/SsoRedirect200Response.md)
- [TotpSetupResponse](docs/TotpSetupResponse.md)
- [UpdateMemberRequest](docs/UpdateMemberRequest.md)
- [UpdateOrgRequest](docs/UpdateOrgRequest.md)
- [UpdateProfileRequest](docs/UpdateProfileRequest.md)
- [UserProfileResponse](docs/UserProfileResponse.md)
- [UserResponse](docs/UserResponse.md)
- [VerifyEmailRequest](docs/VerifyEmailRequest.md)
- [VerifyMagicLinkRequest](docs/VerifyMagicLinkRequest.md)
- [VerifyMfaRequest](docs/VerifyMfaRequest.md)
- [WebauthnBeginResponse](docs/WebauthnBeginResponse.md)
- [WebauthnFinishRequest](docs/WebauthnFinishRequest.md)

### Authorization


Authentication schemes defined for the API:
<a id="bearerAuth"></a>
#### bearerAuth


- **Type**: HTTP Bearer Token authentication (JWT)

## About

This TypeScript SDK client supports the [Fetch API](https://fetch.spec.whatwg.org/)
and is automatically generated by the
[OpenAPI Generator](https://openapi-generator.tech) project:

- API version: `0.1.0`
- Package version: `0.1.0`
- Generator version: `7.19.0`
- Build package: `org.openapitools.codegen.languages.TypeScriptFetchClientCodegen`

The generated npm module supports the following:

- Environments
  * Node.js
  * Webpack
  * Browserify
- Language levels
  * ES5 - you must have a Promises/A+ library installed
  * ES6
- Module systems
  * CommonJS
  * ES6 module system


## Development

### Building

To build the TypeScript source code, you need to have Node.js and npm installed.
After cloning the repository, navigate to the project directory and run:

```bash
npm install
npm run build
```

### Publishing

Once you've built the package, you can publish it to npm:

```bash
npm publish
```

## License

[MIT OR Apache-2.0]()

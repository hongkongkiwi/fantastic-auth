# English (default) translations for Vault Auth Server

## Common
-brand-name = Vault
-app-name = Vault Auth

## Errors - Authentication
errors-invalid-credentials = Invalid email or password
errors-account-locked = Account locked. Try again in { $minutes } minutes.
errors-account-disabled = Your account has been disabled. Please contact support.
errors-account-pending = Your account is pending verification. Please check your email.
errors-session-expired = Your session has expired. Please sign in again.
errors-invalid-token = Invalid or expired token
errors-token-revoked = This token has been revoked
errors-mfa-required = Multi-factor authentication required
errors-mfa-invalid = Invalid verification code
errors-mfa-setup-required = Please set up multi-factor authentication
errors-password-expired = Your password has expired. Please reset it.
errors-too-many-attempts = Too many attempts. Please try again later.

## Errors - Authorization
errors-unauthorized = Authentication required
errors-forbidden = Access denied
errors-insufficient-permissions = You don't have permission to perform this action
errors-tenant-access-denied = Access denied for this organization

## Errors - Validation
errors-validation-failed = Validation failed
errors-invalid-email = Please enter a valid email address
errors-invalid-password = Password does not meet requirements
errors-password-mismatch = Passwords do not match
errors-invalid-format = Invalid format
errors-field-required = This field is required
errors-invalid-uuid = Invalid identifier format
errors-value-too-short = Value is too short (minimum { $min } characters)
errors-value-too-long = Value is too long (maximum { $max } characters)

## Errors - Resource
errors-not-found = { $resource } not found
errors-user-not-found = User not found
errors-organization-not-found = Organization not found
errors-session-not-found = Session not found
errors-already-exists = { $resource } already exists
errors-email-already-exists = An account with this email already exists

## Errors - Rate Limiting
errors-rate-limited = Too many requests. Please try again in { $seconds } seconds.
errors-session-limit-reached = Maximum concurrent sessions reached ({ $max }). Please log out from another device.

## Errors - Server
errors-internal-error = An internal error occurred. Please try again later.
errors-service-unavailable = Service temporarily unavailable. Please try again later.
errors-database-error = Database error occurred
errors-external-service = External service error ({ $service }): { $message }

## Emails - Verification
emails-verification-subject = Verify your email address
emails-verification-greeting = Hi { $name },
emails-verification-body = Thanks for signing up! Please verify your email address by clicking the button below. This link will expire in { $hours } hours.
emails-verification-button = Verify Email
emails-verification-ignore = If you didn't create an account, you can safely ignore this email.
emails-verification-alternative = Or copy and paste this link into your browser:

## Emails - Password Reset
emails-password-reset-subject = Reset your password
emails-password-reset-greeting = Hi { $name },
emails-password-reset-body = We received a request to reset your password. Click the button below to create a new password. This link will expire in { $hours } hours.
emails-password-reset-button = Reset Password
emails-password-reset-ignore = If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged.

## Emails - Magic Link
emails-magic-link-subject = Your magic link to sign in
emails-magic-link-greeting = Hi { $name },
emails-magic-link-body = Click the button below to sign in to your account. This link will expire in { $minutes } minutes and can only be used once.
emails-magic-link-button = Sign In
emails-magic-link-ignore = If you didn't request this link, you can safely ignore this email.

## Emails - Organization Invitation
emails-invitation-subject = You've been invited to join { $organization }
emails-invitation-greeting = Hi { $name },
emails-invitation-body = { $inviter } has invited you to join { $organization } as a { $role }.
emails-invitation-body-accept = Click the button below to accept the invitation. This link will expire in { $days } days.
emails-invitation-button = Accept Invitation

## Emails - Security Alerts
emails-security-alert-subject = Security alert: { $alert_type }
emails-security-alert-greeting = Hi { $name },
emails-security-alert-new-device = We noticed a sign in to your account from a new device.
emails-security-alert-password-changed = Your password was recently changed.
emails-security-alert-email-changed = Your email address was recently changed.
emails-security-alert-mfa-enabled = Two-factor authentication was enabled on your account.
emails-security-alert-mfa-disabled = Two-factor authentication was disabled on your account.
emails-security-alert-suspicious-login = We detected a suspicious login attempt on your account.
emails-security-alert-account-locked = Your account has been temporarily locked due to multiple failed sign-in attempts.
emails-security-alert-details = Time: { $timestamp }
emails-security-alert-ip = IP Address: { $ip }
emails-security-alert-device = Device: { $device }
emails-security-alert-location = Location: { $location }
emails-security-alert-action = If this was you, you can ignore this email. If you don't recognize this activity, please secure your account immediately.

## Emails - Backup Codes
emails-backup-codes-subject = Your backup codes
emails-backup-codes-greeting = Hi { $name },
emails-backup-codes-body = You've enabled two-factor authentication on your account. Here are your backup codes:
emails-backup-codes-warning = Important: Save these codes in a secure place. Each code can only be used once. If you lose access to your authenticator app, you'll need these codes to sign in.
emails-backup-codes-security = Never share these codes with anyone.

## Emails - Welcome
emails-welcome-subject = Welcome to { $app_name }!
emails-welcome-greeting = Hi { $name },
emails-welcome-body = Welcome! Your account has been created successfully. We're excited to have you on board.
emails-welcome-docs = Need help getting started? Check out our documentation.
emails-welcome-support = If you have any questions, feel free to reach out to our support team.
emails-welcome-button = Go to Dashboard

## Emails - New Device
emails-new-device-subject = New device signed in to your account
emails-new-device-greeting = Hi { $name },
emails-new-device-body = We noticed a new device signed in to your account:
emails-new-device-trust-button = Yes, Trust This Device
emails-new-device-revoke-button = No, Revoke Access
emails-new-device-question = Was this you?

## UI Labels
ui-login = Sign In
ui-register = Sign Up
ui-logout = Sign Out
ui-forgot-password = Forgot password?
ui-reset-password = Reset Password
ui-verify-email = Verify Email
ui-resend-code = Resend code
ui-back = Back
ui-continue = Continue
ui-submit = Submit
ui-cancel = Cancel
ui-save = Save
ui-delete = Delete
ui-edit = Edit
ui-close = Close
ui-loading = Loading...
ui-success = Success
ui-error = Error
ui-warning = Warning
ui-info = Info

## MFA Methods
mfa-totp = Authenticator App
mfa-sms = SMS
mfa-email = Email
mfa-webauthn = Security Key
mfa-backup-codes = Backup Codes

## Webhook Events
webhook-user-created = User account created
webhook-user-updated = User profile updated
webhook-user-deleted = User account deleted
webhook-user-login = User signed in
webhook-user-logout = User signed out
webhook-session-created = New session created
webhook-session-revoked = Session revoked
webhook-mfa-enabled = Multi-factor authentication enabled
webhook-mfa-disabled = Multi-factor authentication disabled
webhook-password-changed = Password changed
webhook-email-changed = Email address changed
webhook-email-verified = Email address verified

## Time
time-just-now = just now
time-minutes-ago = { $minutes } minute ago
time-minutes-ago-plural = { $minutes } minutes ago
time-hours-ago = { $hours } hour ago
time-hours-ago-plural = { $hours } hours ago
time-days-ago = { $days } day ago
time-days-ago-plural = { $days } days ago

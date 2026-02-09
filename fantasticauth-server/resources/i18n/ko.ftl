# Korean translations for Vault Auth Server

## Common
-brand-name = Vault
-app-name = Vault Auth

## Errors - Authentication
errors-invalid-credentials = 이메일 또는 비밀번호가 잘못되었습니다
errors-account-locked = 계정이 잠겼습니다. { $minutes }분 후에 다시 시도하세요.
errors-account-disabled = 계정이 비활성화되었습니다. 지원팀에 문의하세요.
errors-account-pending = 계정이 인증 대기 중입니다. 이메일을 확인하세요.
errors-session-expired = 세션이 만료되었습니다. 다시 로그인하세요.
errors-invalid-token = 토큰이 잘못되었거나 만료되었습니다
errors-token-revoked = 이 토큰은 취소되었습니다
errors-mfa-required = 다중 인증이 필요합니다
errors-mfa-invalid = 인증 코드가 잘못되었습니다
errors-mfa-setup-required = 다중 인증을 설정하세요
errors-password-expired = 비밀번호가 만료되었습니다. 재설정하세요.
errors-too-many-attempts = 시도 횟수가 너무 많습니다. 나중에 다시 시도하세요.

## Errors - Authorization
errors-unauthorized = 인증이 필요합니다
errors-forbidden = 접근이 거부되었습니다
errors-insufficient-permissions = 이 작업을 수행할 권한이 없습니다
errors-tenant-access-denied = 이 조직에 대한 접근이 거부되었습니다

## Errors - Validation
errors-validation-failed = 검증에 실패했습니다
errors-invalid-email = 유효한 이메일 주소를 입력하세요
errors-invalid-password = 비밀번호가 요구사항을 충족하지 않습니다
errors-password-mismatch = 비밀번호가 일치하지 않습니다
errors-invalid-format = 잘못된 형식입니다
errors-field-required = 이 필드는 필수입니다
errors-invalid-uuid = 잘못된 식별자 형식입니다
errors-value-too-short = 값이 너무 짧습니다 (최소 { $min }자)
errors-value-too-long = 값이 너무 깁니다 (최대 { $max }자)

## Errors - Resource
errors-not-found = { $resource }을(를) 찾을 수 없습니다
errors-user-not-found = 사용자를 찾을 수 없습니다
errors-organization-not-found = 조직을 찾을 수 없습니다
errors-session-not-found = 세션을 찾을 수 없습니다
errors-already-exists = { $resource }이(가) 이미 존재합니다
errors-email-already-exists = 이 이메일로 가입된 계정이 이미 있습니다

## Errors - Rate Limiting
errors-rate-limited = 요청이 너무 많습니다. { $seconds }초 후에 다시 시도하세요.
errors-session-limit-reached = 최대 동시 세션 수에 도달했습니다 ({ $max }). 다른 기기에서 로그아웃하세요.

## Errors - Server
errors-internal-error = 내부 오류가 발생했습니다. 나중에 다시 시도하세요.
errors-service-unavailable = 서비스를 일시적으로 사용할 수 없습니다. 나중에 다시 시도하세요.
errors-database-error = 데이터베이스 오류가 발생했습니다
errors-external-service = 외부 서비스 오류 ({ $service }): { $message }

## Emails - Verification
emails-verification-subject = 이메일 주소 인증
emails-verification-greeting = { $name }님 안녕하세요,
emails-verification-body = 가입해 주셔서 감사합니다! 아래 버튼을 클릭하여 이메일 주소를 인증하세요. 이 링크는 { $hours }시간 후에 만료됩니다.
emails-verification-button = 이메일 인증
emails-verification-ignore = 계정을 생성하지 않았다면 이 이메일을 무시하셔도 됩니다.
emails-verification-alternative = 또는 브라우저에 이 링크를 복사하여 붙여넣으세요:

## Emails - Password Reset
emails-password-reset-subject = 비밀번호 재설정
emails-password-reset-greeting = { $name }님 안녕하세요,
emails-password-reset-body = 비밀번호 재설정 요청을 받았습니다. 아래 버튼을 클릭하여 새 비밀번호를 만드세요. 이 링크는 { $hours }시간 후에 만료됩니다.
emails-password-reset-button = 비밀번호 재설정
emails-password-reset-ignore = 재설정을 요청하지 않았다면 이 이메일을 무시하셔도 됩니다. 비밀번호는 변경되지 않습니다.

## Emails - Magic Link
emails-magic-link-subject = 로그인용 매직 링크
emails-magic-link-greeting = { $name }님 안녕하세요,
emails-magic-link-body = 아래 버튼을 클릭하여 계정에 로그인하세요. 이 링크는 { $minutes }분 후에 만료되며 한 번만 사용할 수 있습니다.
emails-magic-link-button = 로그인
emails-magic-link-ignore = 이 링크를 요청하지 않았다면 이 이메일을 무시하셔도 됩니다.

## Emails - Organization Invitation
emails-invitation-subject = { $organization }에 초대되었습니다
emails-invitation-greeting = { $name }님 안녕하세요,
emails-invitation-body = { $inviter }님이 { $organization }에 { $role }(으)로 초대했습니다.
emails-invitation-body-accept = 아래 버튼을 클릭하여 초대를 수락하세요. 이 링크는 { $days }일 후에 만료됩니다.
emails-invitation-button = 초대 수락

## Emails - Security Alerts
emails-security-alert-subject = 보안 알림: { $alert_type }
emails-security-alert-greeting = { $name }님 안녕하세요,
emails-security-alert-new-device = 새로운 기기에서 계정에 로그인한 것을 감지했습니다.
emails-security-alert-password-changed = 비밀번호가 최근에 변경되었습니다.
emails-security-alert-email-changed = 이메일 주소가 최근에 변경되었습니다.
emails-security-alert-mfa-enabled = 계정에서 2단계 인증이 활성화되었습니다.
emails-security-alert-mfa-disabled = 계정에서 2단계 인증이 비활성화되었습니다.
emails-security-alert-suspicious-login = 계정에서 의심스러운 로그인 시도를 감지했습니다.
emails-security-alert-account-locked = 여러 번의 로그인 실패로 인해 계정이 일시적으로 잠겼습니다.
emails-security-alert-details = 시간: { $timestamp }
emails-security-alert-ip = IP 주소: { $ip }
emails-security-alert-device = 기기: { $device }
emails-security-alert-location = 위치: { $location }
emails-security-alert-action = 본인이 한 행동이라면 이 이메일을 무시하셔도 됩니다. 이 활동을 인식하지 못한다면 즉시 계정을 보호하세요.

## Emails - Backup Codes
emails-backup-codes-subject = 백업 코드
emails-backup-codes-greeting = { $name }님 안녕하세요,
emails-backup-codes-body = 계정에서 2단계 인증을 활성화했습니다. 다음은 백업 코드입니다:
emails-backup-codes-warning = 중요: 이 코드들을 안전한 곳에 보관하세요. 각 코드는 한 번만 사용할 수 있습니다. 인증 앱에 접근할 수 없게 되면 이 코드들로 로그인해야 합니다.
emails-backup-codes-security = 이 코드를 절대 다른 사람과 공유하지 마세요.

## Emails - Welcome
emails-welcome-subject = { $app_name }에 오신 것을 환영합니다!
emails-welcome-greeting = { $name }님 안녕하세요,
emails-welcome-body = 환영합니다! 계정이 성공적으로 생성되었습니다. 함께하게 되어 기쁩니다.
emails-welcome-docs = 시작에 도움이 필요하신가요? 문서를 확인해 보세요.
emails-welcome-support = 질문이 있으시면 언제든지 지원팀에 문의하세요.
emails-welcome-button = 대시보드로 가기

## Emails - New Device
emails-new-device-subject = 새로운 기기가 계정에 로그인했습니다
emails-new-device-greeting = { $name }님 안녕하세요,
emails-new-device-body = 새로운 기기가 계정에 로그인한 것을 감지했습니다:
emails-new-device-trust-button = 예, 이 기기 신뢰
emails-new-device-revoke-button = 아니오, 접근 취소
emails-new-device-question = 본인이신가요?

## UI Labels
ui-login = 로그인
ui-register = 가입
ui-logout = 로그아웃
ui-forgot-password = 비밀번호를 잊으셨나요?
ui-reset-password = 비밀번호 재설정
ui-verify-email = 이메일 인증
ui-resend-code = 코드 재전송
ui-back = 뒤로
ui-continue = 계속
ui-submit = 제출
ui-cancel = 취소
ui-save = 저장
ui-delete = 삭제
ui-edit = 편집
ui-close = 닫기
ui-loading = 로딩 중...
ui-success = 성공
ui-error = 오류
ui-warning = 경고
ui-info = 정보

## MFA Methods
mfa-totp = 인증 앱
mfa-sms = 문자 메시지
mfa-email = 이메일
mfa-webauthn = 보안 키
mfa-backup-codes = 백업 코드

## Webhook Events
webhook-user-created = 사용자 계정이 생성되었습니다
webhook-user-updated = 사용자 프로필이 업데이트되었습니다
webhook-user-deleted = 사용자 계정이 삭제되었습니다
webhook-user-login = 사용자가 로그인했습니다
webhook-user-logout = 사용자가 로그아웃했습니다
webhook-session-created = 새 세션이 생성되었습니다
webhook-session-revoked = 세션이 취소되었습니다
webhook-mfa-enabled = 다중 인증이 활성화되었습니다
webhook-mfa-disabled = 다중 인증이 비활성화되었습니다
webhook-password-changed = 비밀번호가 변경되었습니다
webhook-email-changed = 이메일 주소가 변경되었습니다
webhook-email-verified = 이메일 주소가 인증되었습니다

## Time
time-just-now = 방금
time-minutes-ago = { $minutes }분 전
time-minutes-ago-plural = { $minutes }분 전
time-hours-ago = { $hours }시간 전
time-hours-ago-plural = { $hours }시간 전
time-days-ago = { $days }일 전
time-days-ago-plural = { $days }일 전

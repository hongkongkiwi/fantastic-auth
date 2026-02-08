# Chinese (Simplified) translations for Vault Auth Server

## Common
-brand-name = Vault
-app-name = Vault Auth

## Errors - Authentication
errors-invalid-credentials = 邮箱或密码无效
errors-account-locked = 账户已锁定。请在 { $minutes } 分钟后重试。
errors-account-disabled = 您的账户已被禁用。请联系客服。
errors-account-pending = 您的账户正在等待验证。请查看您的邮箱。
errors-session-expired = 您的会话已过期。请重新登录。
errors-invalid-token = 令牌无效或已过期
errors-token-revoked = 此令牌已被撤销
errors-mfa-required = 需要多因素认证
errors-mfa-invalid = 验证码无效
errors-mfa-setup-required = 请设置多因素认证
errors-password-expired = 您的密码已过期。请重置密码。
errors-too-many-attempts = 尝试次数过多。请稍后重试。

## Errors - Authorization
errors-unauthorized = 需要身份验证
errors-forbidden = 拒绝访问
errors-insufficient-permissions = 您没有执行此操作的权限
errors-tenant-access-denied = 拒绝访问该组织

## Errors - Validation
errors-validation-failed = 验证失败
errors-invalid-email = 请输入有效的邮箱地址
errors-invalid-password = 密码不符合要求
errors-password-mismatch = 密码不匹配
errors-invalid-format = 格式无效
errors-field-required = 此字段为必填项
errors-invalid-uuid = 标识符格式无效
errors-value-too-short = 值太短（最少 { $min } 个字符）
errors-value-too-long = 值太长（最多 { $max } 个字符）

## Errors - Resource
errors-not-found = 未找到 { $resource }
errors-user-not-found = 未找到用户
errors-organization-not-found = 未找到组织
errors-session-not-found = 未找到会话
errors-already-exists = { $resource } 已存在
errors-email-already-exists = 已存在使用此邮箱的账户

## Errors - Rate Limiting
errors-rate-limited = 请求过多。请在 { $seconds } 秒后重试。
errors-session-limit-reached = 已达到最大并发会话数（{ $max }）。请从其他设备登出。

## Errors - Server
errors-internal-error = 发生内部错误。请稍后重试。
errors-service-unavailable = 服务暂时不可用。请稍后重试。
errors-database-error = 发生数据库错误
errors-external-service = 外部服务错误（{ $service }）：{ $message }

## Emails - Verification
emails-verification-subject = 验证您的邮箱地址
emails-verification-greeting = 您好 { $name }，
emails-verification-body = 感谢您的注册！请点击下方按钮验证您的邮箱地址。此链接将在 { $hours } 小时后过期。
emails-verification-button = 验证邮箱
emails-verification-ignore = 如果您没有创建账户，可以安全地忽略此邮件。
emails-verification-alternative = 或将此链接复制粘贴到浏览器中：

## Emails - Password Reset
emails-password-reset-subject = 重置您的密码
emails-password-reset-greeting = 您好 { $name }，
emails-password-reset-body = 我们收到了重置您密码的请求。点击下方按钮创建新密码。此链接将在 { $hours } 小时后过期。
emails-password-reset-button = 重置密码
emails-password-reset-ignore = 如果您没有请求重置密码，可以安全地忽略此邮件。您的密码将保持不变。

## Emails - Magic Link
emails-magic-link-subject = 您的登录魔法链接
emails-magic-link-greeting = 您好 { $name }，
emails-magic-link-body = 点击下方按钮登录您的账户。此链接将在 { $minutes } 分钟后过期，且只能使用一次。
emails-magic-link-button = 登录
emails-magic-link-ignore = 如果您没有请求此链接，可以安全地忽略此邮件。

## Emails - Organization Invitation
emails-invitation-subject = 您被邀请加入 { $organization }
emails-invitation-greeting = 您好 { $name }，
emails-invitation-body = { $inviter } 邀请您以 { $role } 身份加入 { $organization }。
emails-invitation-body-accept = 点击下方按钮接受邀请。此链接将在 { $days } 天后过期。
emails-invitation-button = 接受邀请

## Emails - Security Alerts
emails-security-alert-subject = 安全警报：{ $alert_type }
emails-security-alert-greeting = 您好 { $name }，
emails-security-alert-new-device = 我们发现您的账户从新设备登录。
emails-security-alert-password-changed = 您的密码最近被更改。
emails-security-alert-email-changed = 您的邮箱地址最近被更改。
emails-security-alert-mfa-enabled = 您的账户已启用双因素认证。
emails-security-alert-mfa-disabled = 您的账户已禁用双因素认证。
emails-security-alert-suspicious-login = 我们检测到您的账户有可疑登录尝试。
emails-security-alert-account-locked = 由于多次登录失败，您的账户已被暂时锁定。
emails-security-alert-details = 时间：{ $timestamp }
emails-security-alert-ip = IP 地址：{ $ip }
emails-security-alert-device = 设备：{ $device }
emails-security-alert-location = 位置：{ $location }
emails-security-alert-action = 如果是您本人操作，可以忽略此邮件。如果您不认识此活动，请立即保护您的账户。

## Emails - Backup Codes
emails-backup-codes-subject = 您的备用码
emails-backup-codes-greeting = 您好 { $name }，
emails-backup-codes-body = 您已在账户上启用双因素认证。以下是您的备用码：
emails-backup-codes-warning = 重要：请将这些代码保存在安全的地方。每个代码只能使用一次。如果您失去对认证应用的访问权限，将需要这些代码来登录。
emails-backup-codes-security = 切勿与任何人分享这些代码。

## Emails - Welcome
emails-welcome-subject = 欢迎使用 { $app_name }！
emails-welcome-greeting = 您好 { $name }，
emails-welcome-body = 欢迎！您的账户已成功创建。很高兴您能加入我们。
emails-welcome-docs = 需要帮助入门吗？请查看我们的文档。
emails-welcome-support = 如有任何问题，请随时联系我们的客服团队。
emails-welcome-button = 前往仪表板

## Emails - New Device
emails-new-device-subject = 新设备登录了您的账户
emails-new-device-greeting = 您好 { $name }，
emails-new-device-body = 我们发现新设备登录了您的账户：
emails-new-device-trust-button = 是，信任此设备
emails-new-device-revoke-button = 否，撤销访问
emails-new-device-question = 是您本人吗？

## UI Labels
ui-login = 登录
ui-register = 注册
ui-logout = 登出
ui-forgot-password = 忘记密码？
ui-reset-password = 重置密码
ui-verify-email = 验证邮箱
ui-resend-code = 重新发送验证码
ui-back = 返回
ui-continue = 继续
ui-submit = 提交
ui-cancel = 取消
ui-save = 保存
ui-delete = 删除
ui-edit = 编辑
ui-close = 关闭
ui-loading = 加载中...
ui-success = 成功
ui-error = 错误
ui-warning = 警告
ui-info = 信息

## MFA Methods
mfa-totp = 认证应用
mfa-sms = 短信
mfa-email = 邮件
mfa-webauthn = 安全密钥
mfa-backup-codes = 备用码

## Webhook Events
webhook-user-created = 用户账户已创建
webhook-user-updated = 用户资料已更新
webhook-user-deleted = 用户账户已删除
webhook-user-login = 用户已登录
webhook-user-logout = 用户已登出
webhook-session-created = 新会话已创建
webhook-session-revoked = 会话已撤销
webhook-mfa-enabled = 多因素认证已启用
webhook-mfa-disabled = 多因素认证已禁用
webhook-password-changed = 密码已更改
webhook-email-changed = 邮箱地址已更改
webhook-email-verified = 邮箱地址已验证

## Time
time-just-now = 刚刚
time-minutes-ago = { $minutes } 分钟前
time-minutes-ago-plural = { $minutes } 分钟前
time-hours-ago = { $hours } 小时前
time-hours-ago-plural = { $hours } 小时前
time-days-ago = { $days } 天前
time-days-ago-plural = { $days } 天前

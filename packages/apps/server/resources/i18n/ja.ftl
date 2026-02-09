# Japanese translations for Vault Auth Server

## Common
-brand-name = Vault
-app-name = Vault Auth

## Errors - Authentication
errors-invalid-credentials = メールアドレスまたはパスワードが無効です
errors-account-locked = アカウントがロックされています。{ $minutes }分後に再試行してください。
errors-account-disabled = アカウントが無効化されました。サポートにお問い合わせください。
errors-account-pending = アカウントの確認が保留中です。メールをご確認ください。
errors-session-expired = セッションの有効期限が切れました。再度ログインしてください。
errors-invalid-token = 無効または期限切れのトークンです
errors-token-revoked = このトークンは取り消されました
errors-mfa-required = 多要素認証が必要です
errors-mfa-invalid = 確認コードが無効です
errors-mfa-setup-required = 多要素認証を設定してください
errors-password-expired = パスワードの有効期限が切れました。リセットしてください。
errors-too-many-attempts = 試行回数が多すぎます。後でもう一度お試しください。

## Errors - Authorization
errors-unauthorized = 認証が必要です
errors-forbidden = アクセスが拒否されました
errors-insufficient-permissions = この操作を実行する権限がありません
errors-tenant-access-denied = この組織へのアクセスが拒否されました

## Errors - Validation
errors-validation-failed = 検証に失敗しました
errors-invalid-email = 有効なメールアドレスを入力してください
errors-invalid-password = パスワードが要件を満たしていません
errors-password-mismatch = パスワードが一致しません
errors-invalid-format = 無効な形式です
errors-field-required = この項目は必須です
errors-invalid-uuid = 無効な識別子形式です
errors-value-too-short = 値が短すぎます（最小{ $min }文字）
errors-value-too-long = 値が長すぎます（最大{ $max }文字）

## Errors - Resource
errors-not-found = { $resource }が見つかりません
errors-user-not-found = ユーザーが見つかりません
errors-organization-not-found = 組織が見つかりません
errors-session-not-found = セッションが見つかりません
errors-already-exists = { $resource }は既に存在します
errors-email-already-exists = このメールアドレスのアカウントは既に存在します

## Errors - Rate Limiting
errors-rate-limited = リクエストが多すぎます。{ $seconds }秒後に再試行してください。
errors-session-limit-reached = 最大同時セッション数に達しました（{ $max }）。別のデバイスからログアウトしてください。

## Errors - Server
errors-internal-error = 内部エラーが発生しました。後でもう一度お試しください。
errors-service-unavailable = サービスが一時的に利用できません。後でもう一度お試しください。
errors-database-error = データベースエラーが発生しました
errors-external-service = 外部サービスエラー（{ $service }）：{ $message }

## Emails - Verification
emails-verification-subject = メールアドレスの確認
emails-verification-greeting = { $name }様、
emails-verification-body = ご登録ありがとうございます！以下のボタンをクリックしてメールアドレスを確認してください。このリンクは{ $hours }時間後に期限切れとなります。
emails-verification-button = メールを確認
emails-verification-ignore = アカウントを作成していない場合は、このメールを無視していただいて構いません。
emails-verification-alternative = または、以下のリンクをブラウザにコピー＆ペーストしてください：

## Emails - Password Reset
emails-password-reset-subject = パスワードのリセット
emails-password-reset-greeting = { $name }様、
emails-password-reset-body = パスワードのリセットリクエストを受け取りました。以下のボタンをクリックして新しいパスワードを作成してください。このリンクは{ $hours }時間後に期限切れとなります。
emails-password-reset-button = パスワードをリセット
emails-password-reset-ignore = リセットをリクエストしていない場合は、このメールを無視していただいて構いません。パスワードは変更されません。

## Emails - Magic Link
emails-magic-link-subject = ログイン用マジックリンク
emails-magic-link-greeting = { $name }様、
emails-magic-link-body = 以下のボタンをクリックしてアカウントにログインしてください。このリンクは{ $minutes }分後に期限切れとなり、一度のみ使用できます。
emails-magic-link-button = ログイン
emails-magic-link-ignore = このリンクをリクエストしていない場合は、このメールを無視していただいて構いません。

## Emails - Organization Invitation
emails-invitation-subject = { $organization }への招待
emails-invitation-greeting = { $name }様、
emails-invitation-body = { $inviter }様があなたを{ $organization }に{ $role }として招待しました。
emails-invitation-body-accept = 以下のボタンをクリックして招待を承諾してください。このリンクは{ $days }日後に期限切れとなります。
emails-invitation-button = 招待を承諾

## Emails - Security Alerts
emails-security-alert-subject = セキュリティアラート：{ $alert_type }
emails-security-alert-greeting = { $name }様、
emails-security-alert-new-device = 新しいデバイスからのアカウントへのログインを検知しました。
emails-security-alert-password-changed = パスワードが最近変更されました。
emails-security-alert-email-changed = メールアドレスが最近変更されました。
emails-security-alert-mfa-enabled = アカウントで二要素認証が有効化されました。
emails-security-alert-mfa-disabled = アカウントで二要素認証が無効化されました。
emails-security-alert-suspicious-login = アカウントへの不審なログイン試行を検知しました。
emails-security-alert-account-locked = 複数回のログイン失敗により、アカウントが一時的にロックされました。
emails-security-alert-details = 日時：{ $timestamp }
emails-security-alert-ip = IPアドレス：{ $ip }
emails-security-alert-device = デバイス：{ $device }
emails-security-alert-location = 場所：{ $location }
emails-security-alert-action = ご自身の操作の場合は、このメールを無視していただいて構いません。心当たりがない場合は、直ちにアカウントを保護してください。

## Emails - Backup Codes
emails-backup-codes-subject = バックアップコード
emails-backup-codes-greeting = { $name }様、
emails-backup-codes-body = アカウントで二要素認証が有効化されました。以下がバックアップコードです：
emails-backup-codes-warning = 重要：これらのコードは安全な場所に保存してください。各コードは一度のみ使用できます。認証アプリへのアクセスを失った場合、これらのコードが必要になります。
emails-backup-codes-security = これらのコードを決して他人と共有しないでください。

## Emails - Welcome
emails-welcome-subject = { $app_name }へようこそ！
emails-welcome-greeting = { $name }様、
emails-welcome-body = ようこそ！アカウントが正常に作成されました。ご利用いただきありがとうございます。
emails-welcome-docs = 開始に関するヘルプが必要ですか？ドキュメントをご覧ください。
emails-welcome-support = ご質問がございましたら、サポートチームまでお気軽にお問い合わせください。
emails-welcome-button = ダッシュボードへ

## Emails - New Device
emails-new-device-subject = 新しいデバイスがアカウントにログインしました
emails-new-device-greeting = { $name }様、
emails-new-device-body = 新しいデバイスがアカウントにログインしたことを検知しました：
emails-new-device-trust-button = はい、このデバイスを信頼する
emails-new-device-revoke-button = いいえ、アクセスを取り消す
emails-new-device-question = ご自身の操作ですか？

## UI Labels
ui-login = ログイン
ui-register = 登録
ui-logout = ログアウト
ui-forgot-password = パスワードをお忘れですか？
ui-reset-password = パスワードをリセット
ui-verify-email = メールを確認
ui-resend-code = コードを再送信
ui-back = 戻る
ui-continue = 続ける
ui-submit = 送信
ui-cancel = キャンセル
ui-save = 保存
ui-delete = 削除
ui-edit = 編集
ui-close = 閉じる
ui-loading = 読み込み中...
ui-success = 成功
ui-error = エラー
ui-warning = 警告
ui-info = 情報

## MFA Methods
mfa-totp = 認証アプリ
mfa-sms = SMS
mfa-email = メール
mfa-webauthn = セキュリティキー
mfa-backup-codes = バックアップコード

## Webhook Events
webhook-user-created = ユーザーアカウントが作成されました
webhook-user-updated = ユーザープロフィールが更新されました
webhook-user-deleted = ユーザーアカウントが削除されました
webhook-user-login = ユーザーがログインしました
webhook-user-logout = ユーザーがログアウトしました
webhook-session-created = 新しいセッションが作成されました
webhook-session-revoked = セッションが取り消されました
webhook-mfa-enabled = 多要素認証が有効化されました
webhook-mfa-disabled = 多要素認証が無効化されました
webhook-password-changed = パスワードが変更されました
webhook-email-changed = メールアドレスが変更されました
webhook-email-verified = メールアドレスが確認されました

## Time
time-just-now = たった今
time-minutes-ago = { $minutes }分前
time-minutes-ago-plural = { $minutes }分前
time-hours-ago = { $hours }時間前
time-hours-ago-plural = { $hours }時間前
time-days-ago = { $days }日前
time-days-ago-plural = { $days }日前

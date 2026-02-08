# Russian translations for Vault Auth Server

## Common
-brand-name = Vault
-app-name = Vault Auth

## Errors - Authentication
errors-invalid-credentials = Неверный email или пароль
errors-account-locked = Аккаунт заблокирован. Попробуйте снова через { $minutes } минут.
errors-account-disabled = Ваш аккаунт отключен. Пожалуйста, свяжитесь с поддержкой.
errors-account-pending = Ваш аккаунт ожидает подтверждения. Пожалуйста, проверьте свою почту.
errors-session-expired = Сеанс истек. Пожалуйста, войдите снова.
errors-invalid-token = Недействительный или истекший токен
errors-token-revoked = Этот токен был отозван
errors-mfa-required = Требуется многофакторная аутентификация
errors-mfa-invalid = Неверный код подтверждения
errors-mfa-setup-required = Пожалуйста, настройте многофакторную аутентификацию
errors-password-expired = Срок действия пароля истек. Пожалуйста, сбросьте его.
errors-too-many-attempts = Слишком много попыток. Пожалуйста, попробуйте позже.

## Errors - Authorization
errors-unauthorized = Требуется аутентификация
errors-forbidden = Доступ запрещен
errors-insufficient-permissions = У вас нет разрешения на выполнение этого действия
errors-tenant-access-denied = Доступ к этой организации запрещен

## Errors - Validation
errors-validation-failed = Ошибка проверки
errors-invalid-email = Пожалуйста, введите действительный email
errors-invalid-password = Пароль не соответствует требованиям
errors-password-mismatch = Пароли не совпадают
errors-invalid-format = Неверный формат
errors-field-required = Это поле обязательно для заполнения
errors-invalid-uuid = Неверный формат идентификатора
errors-value-too-short = Значение слишком короткое (минимум { $min } символов)
errors-value-too-long = Значение слишком длинное (максимум { $max } символов)

## Errors - Resource
errors-not-found = { $resource } не найден
errors-user-not-found = Пользователь не найден
errors-organization-not-found = Организация не найдена
errors-session-not-found = Сеанс не найден
errors-already-exists = { $resource } уже существует
errors-email-already-exists = Аккаунт с таким email уже существует

## Errors - Rate Limiting
errors-rate-limited = Слишком много запросов. Пожалуйста, попробуйте снова через { $seconds } секунд.
errors-session-limit-reached = Достигнуто максимальное количество одновременных сеансов ({ $max }). Пожалуйста, выйдите с другого устройства.

## Errors - Server
errors-internal-error = Произошла внутренняя ошибка. Пожалуйста, попробуйте позже.
errors-service-unavailable = Сервис временно недоступен. Пожалуйста, попробуйте позже.
errors-database-error = Ошибка базы данных
errors-external-service = Ошибка внешнего сервиса ({ $service }): { $message }

## Emails - Verification
emails-verification-subject = Подтвердите свой email
emails-verification-greeting = Здравствуйте, { $name },
emails-verification-body = Спасибо за регистрацию! Пожалуйста, подтвердите свой email, нажав кнопку ниже. Ссылка истекает через { $hours } часов.
emails-verification-button = Подтвердить email
emails-verification-ignore = Если вы не создавали аккаунт, вы можете безопасно проигнорировать это письмо.
emails-verification-alternative = Или скопируйте и вставьте эту ссылку в браузер:

## Emails - Password Reset
emails-password-reset-subject = Сброс пароля
emails-password-reset-greeting = Здравствуйте, { $name },
emails-password-reset-body = Мы получили запрос на сброс пароля. Нажмите кнопку ниже, чтобы создать новый пароль. Ссылка истекает через { $hours } часов.
emails-password-reset-button = Сбросить пароль
emails-password-reset-ignore = Если вы не запрашивали сброс, вы можете безопасно проигнорировать это письмо. Ваш пароль останется без изменений.

## Emails - Magic Link
emails-magic-link-subject = Ваша магическая ссылка для входа
emails-magic-link-greeting = Здравствуйте, { $name },
emails-magic-link-body = Нажмите кнопку ниже, чтобы войти в аккаунт. Ссылка истекает через { $minutes } минут и может быть использована только один раз.
emails-magic-link-button = Войти
emails-magic-link-ignore = Если вы не запрашивали эту ссылку, вы можете безопасно проигнорировать это письмо.

## Emails - Organization Invitation
emails-invitation-subject = Вас пригласили присоединиться к { $organization }
emails-invitation-greeting = Здравствуйте, { $name },
emails-invitation-body = { $inviter } пригласил вас присоединиться к { $organization } в качестве { $role }.
emails-invitation-body-accept = Нажмите кнопку ниже, чтобы принять приглашение. Ссылка истекает через { $days } дней.
emails-invitation-button = Принять приглашение

## Emails - Security Alerts
emails-security-alert-subject = Предупреждение безопасности: { $alert_type }
emails-security-alert-greeting = Здравствуйте, { $name },
emails-security-alert-new-device = Мы заметили вход в ваш аккаунт с нового устройства.
emails-security-alert-password-changed = Ваш пароль был недавно изменен.
emails-security-alert-email-changed = Ваш email был недавно изменен.
emails-security-alert-mfa-enabled = Двухфакторная аутентификация включена на вашем аккаунте.
emails-security-alert-mfa-disabled = Двухфакторная аутентификация отключена на вашем аккаунте.
emails-security-alert-suspicious-login = Мы обнаружили подозрительную попытку входа в ваш аккаунт.
emails-security-alert-account-locked = Ваш аккаунт временно заблокирован из-за нескольких неудачных попыток входа.
emails-security-alert-details = Время: { $timestamp }
emails-security-alert-ip = IP-адрес: { $ip }
emails-security-alert-device = Устройство: { $device }
emails-security-alert-location = Местоположение: { $location }
emails-security-alert-action = Если это были вы, можете проигнорировать это письмо. Если вы не узнаете эту активность, пожалуйста, немедленно защитите свой аккаунт.

## Emails - Backup Codes
emails-backup-codes-subject = Ваши резервные коды
emails-backup-codes-greeting = Здравствуйте, { $name },
emails-backup-codes-body = Вы включили двухфакторную аутентификацию на своем аккаунте. Вот ваши резервные коды:
emails-backup-codes-warning = Важно: Сохраните эти коды в безопасном месте. Каждый код может быть использован только один раз. Если вы потеряете доступ к приложению аутентификации, вам понадобятся эти коды для входа.
emails-backup-codes-security = Никогда не делитесь этими кодами ни с кем.

## Emails - Welcome
emails-welcome-subject = Добро пожаловать в { $app_name }!
emails-welcome-greeting = Здравствуйте, { $name },
emails-welcome-body = Добро пожаловать! Ваш аккаунт успешно создан. Мы рады видеть вас.
emails-welcome-docs = Нужна помощь с началом работы? Ознакомьтесь с нашей документацией.
emails-welcome-support = Если у вас есть вопросы, обращайтесь в нашу службу поддержки.
emails-welcome-button = Перейти в панель управления

## Emails - New Device
emails-new-device-subject = Новое устройство вошло в ваш аккаунт
emails-new-device-greeting = Здравствуйте, { $name },
emails-new-device-body = Мы заметили вход нового устройства в ваш аккаунт:
emails-new-device-trust-button = Да, доверять этому устройству
emails-new-device-revoke-button = Нет, отозвать доступ
emails-new-device-question = Это были вы?

## UI Labels
ui-login = Войти
ui-register = Зарегистрироваться
ui-logout = Выйти
ui-forgot-password = Забыли пароль?
ui-reset-password = Сбросить пароль
ui-verify-email = Подтвердить email
ui-resend-code = Отправить код повторно
ui-back = Назад
ui-continue = Продолжить
ui-submit = Отправить
ui-cancel = Отмена
ui-save = Сохранить
ui-delete = Удалить
ui-edit = Редактировать
ui-close = Закрыть
ui-loading = Загрузка...
ui-success = Успех
ui-error = Ошибка
ui-warning = Предупреждение
ui-info = Информация

## MFA Methods
mfa-totp = Приложение аутентификации
mfa-sms = SMS
mfa-email = Email
mfa-webauthn = Ключ безопасности
mfa-backup-codes = Резервные коды

## Webhook Events
webhook-user-created = Аккаунт пользователя создан
webhook-user-updated = Профиль пользователя обновлен
webhook-user-deleted = Аккаунт пользователя удален
webhook-user-login = Пользователь вошел
webhook-user-logout = Пользователь вышел
webhook-session-created = Создан новый сеанс
webhook-session-revoked = Сеанс отозван
webhook-mfa-enabled = Многофакторная аутентификация включена
webhook-mfa-disabled = Многофакторная аутентификация отключена
webhook-password-changed = Пароль изменен
webhook-email-changed = Email изменен
webhook-email-verified = Email подтвержден

## Time
time-just-now = только что
time-minutes-ago = { $minutes } минуту назад
time-minutes-ago-plural = { $minutes } минут назад
time-hours-ago = { $hours } час назад
time-hours-ago-plural = { $hours } часов назад
time-days-ago = { $days } день назад
time-days-ago-plural = { $days } дней назад

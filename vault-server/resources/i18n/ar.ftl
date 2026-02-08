# Arabic translations for Vault Auth Server (RTL)

## Common
-brand-name = Vault
-app-name = Vault Auth

## Errors - Authentication
errors-invalid-credentials = البريد الإلكتروني أو كلمة المرور غير صحيحة
errors-account-locked = الحساب مقفل. حاول مرة أخرى بعد { $minutes } دقيقة.
errors-account-disabled = تم تعطيل حسابك. يرجى التواصل مع الدعم.
errors-account-pending = حسابك بانتظار التحقق. يرجى التحقق من بريدك الإلكتروني.
errors-session-expired = انتهت صلاحية جلستك. يرجى تسجيل الدخول مرة أخرى.
errors-invalid-token = الرمز غير صالح أو منتهي الصلاحية
errors-token-revoked = تم إلغاء هذا الرمز
errors-mfa-required = المصادقة متعددة العوامل مطلوبة
errors-mfa-invalid = رمز التحقق غير صالح
errors-mfa-setup-required = يرجى إعداد المصادقة متعددة العوامل
errors-password-expired = انتهت صلاحية كلمة المرور. يرجى إعادة تعيينها.
errors-too-many-attempts = محاولات كثيرة جداً. يرجى المحاولة لاحقاً.

## Errors - Authorization
errors-unauthorized = المصادقة مطلوبة
errors-forbidden = الوصول مرفوض
errors-insufficient-permissions = ليس لديك إذن لتنفيذ هذا الإجراء
errors-tenant-access-denied = الوصول مرفوض لهذه المؤسسة

## Errors - Validation
errors-validation-failed = فشل التحقق
errors-invalid-email = يرجى إدخال عنوان بريد إلكتروني صالح
errors-invalid-password = كلمة المرور لا تلبي المتطلبات
errors-password-mismatch = كلمات المرور غير متطابقة
errors-invalid-format = تنسيق غير صالح
errors-field-required = هذا الحقل مطلوب
errors-invalid-uuid = تنسيق المعرف غير صالح
errors-value-too-short = القيمة قصيرة جداً (الحد الأدنى { $min } حرف)
errors-value-too-long = القيمة طويلة جداً (الحد الأقصى { $max } حرف)

## Errors - Resource
errors-not-found = { $resource } غير موجود
errors-user-not-found = المستخدم غير موجود
errors-organization-not-found = المؤسسة غير موجودة
errors-session-not-found = الجلسة غير موجودة
errors-already-exists = { $resource } موجود بالفعل
errors-email-already-exists = حساب بهذا البريد الإلكتروني موجود بالفعل

## Errors - Rate Limiting
errors-rate-limited = طلبات كثيرة جداً. يرجى المحاولة مرة أخرى بعد { $seconds } ثانية.
errors-session-limit-reached = تم الوصول إلى الحد الأقصى للجلسات المتزامنة ({ $max }). يرجى تسجيل الخروج من جهاز آخر.

## Errors - Server
errors-internal-error = حدث خطأ داخلي. يرجى المحاولة لاحقاً.
errors-service-unavailable = الخدمة غير متاحة مؤقتاً. يرجى المحاولة لاحقاً.
errors-database-error = حدث خطأ في قاعدة البيانات
errors-external-service = خطأ في الخدمة الخارجية ({ $service }): { $message }

## Emails - Verification
emails-verification-subject = تحقق من عنوان بريدك الإلكتروني
emails-verification-greeting = مرحباً { $name }،
emails-verification-body = شكراً للتسجيل! يرجى التحقق من عنوان بريدك الإلكتروني بالنقر على الزر أدناه. سينتهي هذا الرابط خلال { $hours } ساعة.
emails-verification-button = تحقق من البريد
emails-verification-ignore = إذا لم تقم بإنشاء حساب، يمكنك تجاهل هذا البريد بأمان.
emails-verification-alternative = أو انسخ والصق هذا الرابط في متصفحك:

## Emails - Password Reset
emails-password-reset-subject = إعادة تعيين كلمة المرور
emails-password-reset-greeting = مرحباً { $name }،
emails-password-reset-body = تلقينا طلباً لإعادة تعيين كلمة المرور. انقر على الزر أدناه لإنشاء كلمة مرور جديدة. سينتهي هذا الرابط خلال { $hours } ساعة.
emails-password-reset-button = إعادة تعيين كلمة المرور
emails-password-reset-ignore = إذا لم تطلب إعادة التعيين، يمكنك تجاهل هذا البريد بأمان. ستظل كلمة المرور الخاصة بك unchanged.

## Emails - Magic Link
emails-magic-link-subject = رابطك السحري لتسجيل الدخول
emails-magic-link-greeting = مرحباً { $name }،
emails-magic-link-body = انقر على الزر أدناه لتسجيل الدخول إلى حسابك. سينتهي هذا الرابط خلال { $minutes } دقيقة ويمكن استخدامه مرة واحدة فقط.
emails-magic-link-button = تسجيل الدخول
emails-magic-link-ignore = إذا لم تطلب هذا الرابط، يمكنك تجاهل هذا البريد بأمان.

## Emails - Organization Invitation
emails-invitation-subject = تمت دعوتك للانضمام إلى { $organization }
emails-invitation-greeting = مرحباً { $name }،
emails-invitation-body = { $inviter } قام بدعوتك للانضمام إلى { $organization } كـ { $role }.
emails-invitation-body-accept = انقر على الزر أدناه لقبول الدعوة. سينتهي هذا الرابط خلال { $days } يوم.
emails-invitation-button = قبول الدعوة

## Emails - Security Alerts
emails-security-alert-subject = تنبيه أمان: { $alert_type }
emails-security-alert-greeting = مرحباً { $name }،
emails-security-alert-new-device = لاحظنا تسجيل دخول إلى حسابك من جهاز جديد.
emails-security-alert-password-changed = تم تغيير كلمة المرور مؤخراً.
emails-security-alert-email-changed = تم تغيير عنوان البريد الإلكتروني مؤخراً.
emails-security-alert-mfa-enabled = تم تمكين المصادقة الثنائية على حسابك.
emails-security-alert-mfa-disabled = تم تعطيل المصادقة الثنائية على حسابك.
emails-security-alert-suspicious-login = اكتشفنا محاولة تسجيل دخول مشبوهة على حسابك.
emails-security-alert-account-locked = تم قفل حسابك مؤقتاً بسبب محاولات تسجيل دخول فاشلة متعددة.
emails-security-alert-details = الوقت: { $timestamp }
emails-security-alert-ip = عنوان IP: { $ip }
emails-security-alert-device = الجهاز: { $device }
emails-security-alert-location = الموقع: { $location }
emails-security-alert-action = إذا كنت أنت، يمكنك تجاهل هذا البريد. إذا لم تتعرف على هذا النشاط، يرجى تأمين حسابك فوراً.

## Emails - Backup Codes
emails-backup-codes-subject = رموزك الاحتياطية
emails-backup-codes-greeting = مرحباً { $name }،
emails-backup-codes-body = لقد قمت بتمكين المصادقة الثنائية على حسابك. فيما يلي رموزك الاحتياطية:
emails-backup-codes-warning = مهم: احفظ هذه الرموز في مكان آمن. يمكن استخدام كل رمز مرة واحدة فقط. إذا فقدت الوصول إلى تطبيق المصادقة، ستحتاج هذه الرموز لتسجيل الدخول.
emails-backup-codes-security = لا تشارك هذه الرموز مع أي شخص أبداً.

## Emails - Welcome
emails-welcome-subject = مرحباً بك في { $app_name }!
emails-welcome-greeting = مرحباً { $name }،
emails-welcome-body = أهلاً وسهلاً! تم إنشاء حسابك بنجاح. نحن سعداء بوجودك معنا.
emails-welcome-docs = هل تحتاج مساعدة للبدء؟ راجع документацию.
emails-welcome-support = إذا كان لديك أي أسئلة، لا تتردد في التواصل مع فريق الدعم.
emails-welcome-button = الذهاب إلى لوحة التحكم

## Emails - New Device
emails-new-device-subject = جهاز جديد سجل الدخول إلى حسابك
emails-new-device-greeting = مرحباً { $name }،
emails-new-device-body = لاحظنا تسجيل دخول جهاز جديد إلى حسابك:
emails-new-device-trust-button = نعم، ثق بهذا الجهاز
emails-new-device-revoke-button = لا، إلغاء الوصول
emails-new-device-question = هل أنت؟

## UI Labels
ui-login = تسجيل الدخول
ui-register = التسجيل
ui-logout = تسجيل الخروج
ui-forgot-password = نسيت كلمة المرور؟
ui-reset-password = إعادة تعيين كلمة المرور
ui-verify-email = تحقق من البريد
ui-resend-code = إعادة إرسال الرمز
ui-back = رجوع
ui-continue = متابعة
ui-submit = إرسال
ui-cancel = إلغاء
ui-save = حفظ
ui-delete = حذف
ui-edit = تعديل
ui-close = إغلاق
ui-loading = جاري التحميل...
ui-success = نجاح
ui-error = خطأ
ui-warning = تحذير
ui-info = معلومات

## MFA Methods
mfa-totp = تطبيق المصادقة
mfa-sms = رسالة نصية
mfa-email = بريد إلكتروني
mfa-webauthn = مفتاح الأمان
mfa-backup-codes = رموز احتياطية

## Webhook Events
webhook-user-created = تم إنشاء حساب المستخدم
webhook-user-updated = تم تحديث ملف المستخدم
webhook-user-deleted = تم حذف حساب المستخدم
webhook-user-login = قام المستخدم بتسجيل الدخول
webhook-user-logout = قام المستخدم بتسجيل الخروج
webhook-session-created = تم إنشاء جلسة جديدة
webhook-session-revoked = تم إلغاء الجلسة
webhook-mfa-enabled = تم تمكين المصادقة متعددة العوامل
webhook-mfa-disabled = تم تعطيل المصادقة متعددة العوامل
webhook-password-changed = تم تغيير كلمة المرور
webhook-email-changed = تم تغيير عنوان البريد
webhook-email-verified = تم التحقق من عنوان البريد

## Time
time-just-now = للتو
time-minutes-ago = منذ { $minutes } دقيقة
time-minutes-ago-plural = منذ { $minutes } دقائق
time-hours-ago = منذ { $hours } ساعة
time-hours-ago-plural = منذ { $hours } ساعات
time-days-ago = منذ { $days } يوم
time-days-ago-plural = منذ { $days } أيام

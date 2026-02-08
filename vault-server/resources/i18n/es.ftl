# Spanish translations for Vault Auth Server

## Common
-brand-name = Vault
-app-name = Vault Auth

## Errors - Authentication
errors-invalid-credentials = Correo electrónico o contraseña inválidos
errors-account-locked = Cuenta bloqueada. Inténtalo de nuevo en { $minutes } minutos.
errors-account-disabled = Tu cuenta ha sido desactivada. Por favor contacta con soporte.
errors-account-pending = Tu cuenta está pendiente de verificación. Por favor revisa tu correo.
errors-session-expired = Tu sesión ha expirado. Por favor inicia sesión de nuevo.
errors-invalid-token = Token inválido o expirado
errors-token-revoked = Este token ha sido revocado
errors-mfa-required = Se requiere autenticación multifactor
errors-mfa-invalid = Código de verificación inválido
errors-mfa-setup-required = Por favor configura la autenticación multifactor
errors-password-expired = Tu contraseña ha expirado. Por favor restablécela.
errors-too-many-attempts = Demasiados intentos. Por favor inténtalo más tarde.

## Errors - Authorization
errors-unauthorized = Se requiere autenticación
errors-forbidden = Acceso denegado
errors-insufficient-permissions = No tienes permiso para realizar esta acción
errors-tenant-access-denied = Acceso denegado para esta organización

## Errors - Validation
errors-validation-failed = Validación fallida
errors-invalid-email = Por favor introduce una dirección de correo válida
errors-invalid-password = La contraseña no cumple con los requisitos
errors-password-mismatch = Las contraseñas no coinciden
errors-invalid-format = Formato inválido
errors-field-required = Este campo es obligatorio
errors-invalid-uuid = Formato de identificador inválido
errors-value-too-short = El valor es demasiado corto (mínimo { $min } caracteres)
errors-value-too-long = El valor es demasiado largo (máximo { $max } caracteres)

## Errors - Resource
errors-not-found = { $resource } no encontrado
errors-user-not-found = Usuario no encontrado
errors-organization-not-found = Organización no encontrada
errors-session-not-found = Sesión no encontrada
errors-already-exists = { $resource } ya existe
errors-email-already-exists = Ya existe una cuenta con este correo electrónico

## Errors - Rate Limiting
errors-rate-limited = Demasiadas solicitudes. Por favor inténtalo de nuevo en { $seconds } segundos.
errors-session-limit-reached = Máximo de sesiones concurrentes alcanzado ({ $max }). Por favor cierra sesión en otro dispositivo.

## Errors - Server
errors-internal-error = Ocurrió un error interno. Por favor inténtalo más tarde.
errors-service-unavailable = Servicio temporalmente no disponible. Por favor inténtalo más tarde.
errors-database-error = Ocurrió un error de base de datos
errors-external-service = Error de servicio externo ({ $service }): { $message }

## Emails - Verification
emails-verification-subject = Verifica tu dirección de correo
emails-verification-greeting = Hola { $name },
emails-verification-body = ¡Gracias por registrarte! Por favor verifica tu dirección de correo haciendo clic en el botón de abajo. Este enlace expirará en { $hours } horas.
emails-verification-button = Verificar Correo
emails-verification-ignore = Si no creaste una cuenta, puedes ignorar este correo de forma segura.
emails-verification-alternative = O copia y pega este enlace en tu navegador:

## Emails - Password Reset
emails-password-reset-subject = Restablece tu contraseña
emails-password-reset-greeting = Hola { $name },
emails-password-reset-body = Recibimos una solicitud para restablecer tu contraseña. Haz clic en el botón de abajo para crear una nueva contraseña. Este enlace expirará en { $hours } horas.
emails-password-reset-button = Restablecer Contraseña
emails-password-reset-ignore = Si no solicitaste un restablecimiento de contraseña, puedes ignorar este correo de forma segura. Tu contraseña permanecerá sin cambios.

## Emails - Magic Link
emails-magic-link-subject = Tu enlace mágico para iniciar sesión
emails-magic-link-greeting = Hola { $name },
emails-magic-link-body = Haz clic en el botón de abajo para iniciar sesión en tu cuenta. Este enlace expirará en { $minutes } minutos y solo puede usarse una vez.
emails-magic-link-button = Iniciar Sesión
emails-magic-link-ignore = Si no solicitaste este enlace, puedes ignorar este correo de forma segura.

## Emails - Organization Invitation
emails-invitation-subject = Has sido invitado a unirte a { $organization }
emails-invitation-greeting = Hola { $name },
emails-invitation-body = { $inviter } te ha invitado a unirte a { $organization } como { $role }.
emails-invitation-body-accept = Haz clic en el botón de abajo para aceptar la invitación. Este enlace expirará en { $days } días.
emails-invitation-button = Aceptar Invitación

## Emails - Security Alerts
emails-security-alert-subject = Alerta de seguridad: { $alert_type }
emails-security-alert-greeting = Hola { $name },
emails-security-alert-new-device = Notamos un inicio de sesión en tu cuenta desde un nuevo dispositivo.
emails-security-alert-password-changed = Tu contraseña fue cambiada recientemente.
emails-security-alert-email-changed = Tu dirección de correo fue cambiada recientemente.
emails-security-alert-mfa-enabled = La autenticación de dos factores fue habilitada en tu cuenta.
emails-security-alert-mfa-disabled = La autenticación de dos factores fue deshabilitada en tu cuenta.
emails-security-alert-suspicious-login = Detectamos un intento de inicio de sesión sospechoso en tu cuenta.
emails-security-alert-account-locked = Tu cuenta ha sido bloqueada temporalmente debido a múltiples intentos fallidos de inicio de sesión.
emails-security-alert-details = Hora: { $timestamp }
emails-security-alert-ip = Dirección IP: { $ip }
emails-security-alert-device = Dispositivo: { $device }
emails-security-alert-location = Ubicación: { $location }
emails-security-alert-action = Si fuiste tú, puedes ignorar este correo. Si no reconoces esta actividad, por favor asegura tu cuenta inmediatamente.

## Emails - Backup Codes
emails-backup-codes-subject = Tus códigos de respaldo
emails-backup-codes-greeting = Hola { $name },
emails-backup-codes-body = Has habilitado la autenticación de dos factores en tu cuenta. Aquí están tus códigos de respaldo:
emails-backup-codes-warning = Importante: Guarda estos códigos en un lugar seguro. Cada código solo puede usarse una vez. Si pierdes acceso a tu aplicación de autenticación, necesitarás estos códigos para iniciar sesión.
emails-backup-codes-security = Nunca compartas estos códigos con nadie.

## Emails - Welcome
emails-welcome-subject = ¡Bienvenido a { $app_name }!
emails-welcome-greeting = Hola { $name },
emails-welcome-body = ¡Bienvenido! Tu cuenta ha sido creada exitosamente. Estamos emocionados de tenerte con nosotros.
emails-welcome-docs = ¿Necesitas ayuda para empezar? Consulta nuestra documentación.
emails-welcome-support = Si tienes alguna pregunta, no dudes en contactar a nuestro equipo de soporte.
emails-welcome-button = Ir al Panel

## Emails - New Device
emails-new-device-subject = Nuevo dispositivo inició sesión en tu cuenta
emails-new-device-greeting = Hola { $name },
emails-new-device-body = Notamos un nuevo dispositivo que inició sesión en tu cuenta:
emails-new-device-trust-button = Sí, Confiar en Este Dispositivo
emails-new-device-revoke-button = No, Revocar Acceso
emails-new-device-question = ¿Fuiste tú?

## UI Labels
ui-login = Iniciar Sesión
ui-register = Registrarse
ui-logout = Cerrar Sesión
ui-forgot-password = ¿Olvidaste tu contraseña?
ui-reset-password = Restablecer Contraseña
ui-verify-email = Verificar Correo
ui-resend-code = Reenviar código
ui-back = Atrás
ui-continue = Continuar
ui-submit = Enviar
ui-cancel = Cancelar
ui-save = Guardar
ui-delete = Eliminar
ui-edit = Editar
ui-close = Cerrar
ui-loading = Cargando...
ui-success = Éxito
ui-error = Error
ui-warning = Advertencia
ui-info = Información

## MFA Methods
mfa-totp = App de Autenticación
mfa-sms = SMS
mfa-email = Correo
mfa-webauthn = Llave de Seguridad
mfa-backup-codes = Códigos de Respaldo

## Webhook Events
webhook-user-created = Cuenta de usuario creada
webhook-user-updated = Perfil de usuario actualizado
webhook-user-deleted = Cuenta de usuario eliminada
webhook-user-login = Usuario inició sesión
webhook-user-logout = Usuario cerró sesión
webhook-session-created = Nueva sesión creada
webhook-session-revoked = Sesión revocada
webhook-mfa-enabled = Autenticación multifactor habilitada
webhook-mfa-disabled = Autenticación multifactor deshabilitada
webhook-password-changed = Contraseña cambiada
webhook-email-changed = Dirección de correo cambiada
webhook-email-verified = Dirección de correo verificada

## Time
time-just-now = justo ahora
time-minutes-ago = hace { $minutes } minuto
time-minutes-ago-plural = hace { $minutes } minutos
time-hours-ago = hace { $hours } hora
time-hours-ago-plural = hace { $hours } horas
time-days-ago = hace { $days } día
time-days-ago-plural = hace { $days } días

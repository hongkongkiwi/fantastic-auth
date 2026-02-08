# German translations for Vault Auth Server

## Common
-brand-name = Vault
-app-name = Vault Auth

## Errors - Authentication
errors-invalid-credentials = Ungültige E-Mail oder Passwort
errors-account-locked = Konto gesperrt. Versuchen Sie es in { $minutes } Minuten erneut.
errors-account-disabled = Ihr Konto wurde deaktiviert. Bitte kontaktieren Sie den Support.
errors-account-pending = Ihr Konto wartet auf Bestätigung. Bitte überprüfen Sie Ihre E-Mails.
errors-session-expired = Ihre Sitzung ist abgelaufen. Bitte melden Sie sich erneut an.
errors-invalid-token = Ungültiger oder abgelaufener Token
errors-token-revoked = Dieser Token wurde widerrufen
errors-mfa-required = Multi-Faktor-Authentifizierung erforderlich
errors-mfa-invalid = Ungültiger Bestätigungscode
errors-mfa-setup-required = Bitte richten Sie die Multi-Faktor-Authentifizierung ein
errors-password-expired = Ihr Passwort ist abgelaufen. Bitte setzen Sie es zurück.
errors-too-many-attempts = Zu viele Versuche. Bitte versuchen Sie es später erneut.

## Errors - Authorization
errors-unauthorized = Authentifizierung erforderlich
errors-forbidden = Zugriff verweigert
errors-insufficient-permissions = Sie haben keine Berechtigung für diese Aktion
errors-tenant-access-denied = Zugriff für diese Organisation verweigert

## Errors - Validation
errors-validation-failed = Validierung fehlgeschlagen
errors-invalid-email = Bitte geben Sie eine gültige E-Mail-Adresse ein
errors-invalid-password = Passwort erfüllt nicht die Anforderungen
errors-password-mismatch = Passwörter stimmen nicht überein
errors-invalid-format = Ungültiges Format
errors-field-required = Dieses Feld ist erforderlich
errors-invalid-uuid = Ungültiges Identifikator-Format
errors-value-too-short = Wert zu kurz (Minimum { $min } Zeichen)
errors-value-too-long = Wert zu lang (Maximum { $max } Zeichen)

## Errors - Resource
errors-not-found = { $resource } nicht gefunden
errors-user-not-found = Benutzer nicht gefunden
errors-organization-not-found = Organisation nicht gefunden
errors-session-not-found = Sitzung nicht gefunden
errors-already-exists = { $resource } existiert bereits
errors-email-already-exists = Ein Konto mit dieser E-Mail existiert bereits

## Errors - Rate Limiting
errors-rate-limited = Zu viele Anfragen. Bitte versuchen Sie es in { $seconds } Sekunden erneut.
errors-session-limit-reached = Maximale gleichzeitige Sitzungen erreicht ({ $max }). Bitte melden Sie sich von einem anderen Gerät ab.

## Errors - Server
errors-internal-error = Ein interner Fehler ist aufgetreten. Bitte versuchen Sie es später erneut.
errors-service-unavailable = Service vorübergehend nicht verfügbar. Bitte versuchen Sie es später erneut.
errors-database-error = Datenbankfehler aufgetreten
errors-external-service = Externer Service-Fehler ({ $service }): { $message }

## Emails - Verification
emails-verification-subject = Bestätigen Sie Ihre E-Mail-Adresse
emails-verification-greeting = Hallo { $name },
emails-verification-body = Vielen Dank für Ihre Registrierung! Bitte bestätigen Sie Ihre E-Mail-Adresse, indem Sie auf die Schaltfläche unten klicken. Dieser Link läuft in { $hours } Stunden ab.
emails-verification-button = E-Mail Bestätigen
emails-verification-ignore = Wenn Sie kein Konto erstellt haben, können Sie diese E-Mail ignorieren.
emails-verification-alternative = Oder kopieren Sie diesen Link in Ihren Browser:

## Emails - Password Reset
emails-password-reset-subject = Setzen Sie Ihr Passwort zurück
emails-password-reset-greeting = Hallo { $name },
emails-password-reset-body = Wir haben eine Anfrage zum Zurücksetzen Ihres Passworts erhalten. Klicken Sie auf die Schaltfläche unten, um ein neues Passwort zu erstellen. Dieser Link läuft in { $hours } Stunden ab.
emails-password-reset-button = Passwort Zurücksetzen
emails-password-reset-ignore = Wenn Sie kein Zurücksetzen angefordert haben, können Sie diese E-Mail ignorieren. Ihr Passwort bleibt unverändert.

## Emails - Magic Link
emails-magic-link-subject = Ihr Magischer Link zur Anmeldung
emails-magic-link-greeting = Hallo { $name },
emails-magic-link-body = Klicken Sie auf die Schaltfläche unten, um sich bei Ihrem Konto anzumelden. Dieser Link läuft in { $minutes } Minuten ab und kann nur einmal verwendet werden.
emails-magic-link-button = Anmelden
emails-magic-link-ignore = Wenn Sie diesen Link nicht angefordert haben, können Sie diese E-Mail ignorieren.

## Emails - Organization Invitation
emails-invitation-subject = Sie wurden eingeladen, { $organization } beizutreten
emails-invitation-greeting = Hallo { $name },
emails-invitation-body = { $inviter } hat Sie eingeladen, { $organization } als { $role } beizutreten.
emails-invitation-body-accept = Klicken Sie auf die Schaltfläche unten, um die Einladung anzunehmen. Dieser Link läuft in { $days } Tagen ab.
emails-invitation-button = Einladung Annehmen

## Emails - Security Alerts
emails-security-alert-subject = Sicherheitswarnung: { $alert_type }
emails-security-alert-greeting = Hallo { $name },
emails-security-alert-new-device = Wir haben eine Anmeldung von einem neuen Gerät an Ihrem Konto festgestellt.
emails-security-alert-password-changed = Ihr Passwort wurde kürzlich geändert.
emails-security-alert-email-changed = Ihre E-Mail-Adresse wurde kürzlich geändert.
emails-security-alert-mfa-enabled = Die Zwei-Faktor-Authentifizierung wurde für Ihr Konto aktiviert.
emails-security-alert-mfa-disabled = Die Zwei-Faktor-Authentifizierung wurde für Ihr Konto deaktiviert.
emails-security-alert-suspicious-login = Wir haben einen verdächtigen Anmeldeversuch an Ihrem Konto festgestellt.
emails-security-alert-account-locked = Ihr Konto wurde aufgrund mehrerer fehlgeschlagener Anmeldeversuche vorübergehend gesperrt.
emails-security-alert-details = Zeit: { $timestamp }
emails-security-alert-ip = IP-Adresse: { $ip }
emails-security-alert-device = Gerät: { $device }
emails-security-alert-location = Standort: { $location }
emails-security-alert-action = Waren Sie das? Dann können Sie diese E-Mail ignorieren. Erkennen Sie diese Aktivität nicht? Bitte sichern Sie Ihr Konto sofort.

## Emails - Backup Codes
emails-backup-codes-subject = Ihre Backup-Codes
emails-backup-codes-greeting = Hallo { $name },
emails-backup-codes-body = Sie haben die Zwei-Faktor-Authentifizierung für Ihr Konto aktiviert. Hier sind Ihre Backup-Codes:
emails-backup-codes-warning = Wichtig: Bewahren Sie diese Codes an einem sicheren Ort auf. Jeder Code kann nur einmal verwendet werden. Wenn Sie den Zugriff auf Ihre Authentifizierungs-App verlieren, benötigen Sie diese Codes zur Anmeldung.
emails-backup-codes-security = Geben Sie diese Codes niemals an andere weiter.

## Emails - Welcome
emails-welcome-subject = Willkommen bei { $app_name }!
emails-welcome-greeting = Hallo { $name },
emails-welcome-body = Willkommen! Ihr Konto wurde erfolgreich erstellt. Wir freuen uns, Sie bei uns zu haben.
emails-welcome-docs = Benötigen Sie Hilfe beim Einstieg? Sehen Sie sich unsere Dokumentation an.
emails-welcome-support = Bei Fragen wenden Sie sich bitte an unser Support-Team.
emails-welcome-button = Zum Dashboard

## Emails - New Device
emails-new-device-subject = Neues Gerät bei Ihrem Konto angemeldet
emails-new-device-greeting = Hallo { $name },
emails-new-device-body = Wir haben festgestellt, dass sich ein neues Gerät bei Ihrem Konto angemeldet hat:
emails-new-device-trust-button = Ja, Diesem Gerät Vertrauen
emails-new-device-revoke-button = Nein, Zugriff Widerrufen
emails-new-device-question = Waren Sie das?

## UI Labels
ui-login = Anmelden
ui-register = Registrieren
ui-logout = Abmelden
ui-forgot-password = Passwort vergessen?
ui-reset-password = Passwort Zurücksetzen
ui-verify-email = E-Mail Bestätigen
ui-resend-code = Code Erneut Senden
ui-back = Zurück
ui-continue = Weiter
ui-submit = Absenden
ui-cancel = Abbrechen
ui-save = Speichern
ui-delete = Löschen
ui-edit = Bearbeiten
ui-close = Schließen
ui-loading = Laden...
ui-success = Erfolg
ui-error = Fehler
ui-warning = Warnung
ui-info = Info

## MFA Methods
mfa-totp = Authentifizierungs-App
mfa-sms = SMS
mfa-email = E-Mail
mfa-webauthn = Sicherheitsschlüssel
mfa-backup-codes = Backup-Codes

## Webhook Events
webhook-user-created = Benutzerkonto erstellt
webhook-user-updated = Benutzerprofil aktualisiert
webhook-user-deleted = Benutzerkonto gelöscht
webhook-user-login = Benutzer angemeldet
webhook-user-logout = Benutzer abgemeldet
webhook-session-created = Neue Sitzung erstellt
webhook-session-revoked = Sitzung widerrufen
webhook-mfa-enabled = Multi-Faktor-Authentifizierung aktiviert
webhook-mfa-disabled = Multi-Faktor-Authentifizierung deaktiviert
webhook-password-changed = Passwort geändert
webhook-email-changed = E-Mail-Adresse geändert
webhook-email-verified = E-Mail-Adresse bestätigt

## Time
time-just-now = gerade eben
time-minutes-ago = vor { $minutes } Minute
time-minutes-ago-plural = vor { $minutes } Minuten
time-hours-ago = vor { $hours } Stunde
time-hours-ago-plural = vor { $hours } Stunden
time-days-ago = vor { $days } Tag
time-days-ago-plural = vor { $days } Tagen

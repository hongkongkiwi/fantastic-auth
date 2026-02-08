# Italian translations for Vault Auth Server

## Common
-brand-name = Vault
-app-name = Vault Auth

## Errors - Authentication
errors-invalid-credentials = Email o password non validi
errors-account-locked = Account bloccato. Riprova tra { $minutes } minuti.
errors-account-disabled = Il tuo account è stato disabilitato. Contatta il supporto.
errors-account-pending = Il tuo account è in attesa di verifica. Controlla la tua email.
errors-session-expired = La tua sessione è scaduta. Accedi di nuovo.
errors-invalid-token = Token non valido o scaduto
errors-token-revoked = Questo token è stato revocato
errors-mfa-required = Autenticazione multi-fattore richiesta
errors-mfa-invalid = Codice di verifica non valido
errors-mfa-setup-required = Configura l'autenticazione multi-fattore
errors-password-expired = La tua password è scaduta. Reimpostala.
errors-too-many-attempts = Troppi tentativi. Riprova più tardi.

## Errors - Authorization
errors-unauthorized = Autenticazione richiesta
errors-forbidden = Accesso negato
errors-insufficient-permissions = Non hai il permesso di eseguire questa azione
errors-tenant-access-denied = Accesso negato per questa organizzazione

## Errors - Validation
errors-validation-failed = Validazione fallita
errors-invalid-email = Inserisci un indirizzo email valido
errors-invalid-password = La password non soddisfa i requisiti
errors-password-mismatch = Le password non corrispondono
errors-invalid-format = Formato non valido
errors-field-required = Questo campo è obbligatorio
errors-invalid-uuid = Formato identificatore non valido
errors-value-too-short = Valore troppo corto (minimo { $min } caratteri)
errors-value-too-long = Valore troppo lungo (massimo { $max } caratteri)

## Errors - Resource
errors-not-found = { $resource } non trovato
errors-user-not-found = Utente non trovato
errors-organization-not-found = Organizzazione non trovata
errors-session-not-found = Sessione non trovata
errors-already-exists = { $resource } esiste già
errors-email-already-exists = Esiste già un account con questa email

## Errors - Rate Limiting
errors-rate-limited = Troppe richieste. Riprova tra { $seconds } secondi.
errors-session-limit-reached = Raggiunto il numero massimo di sessioni contemporanee ({ $max }). Esci da un altro dispositivo.

## Errors - Server
errors-internal-error = Si è verificato un errore interno. Riprova più tardi.
errors-service-unavailable = Servizio temporaneamente non disponibile. Riprova più tardi.
errors-database-error = Errore del database
errors-external-service = Errore servizio esterno ({ $service }): { $message }

## Emails - Verification
emails-verification-subject = Verifica il tuo indirizzo email
emails-verification-greeting = Ciao { $name },
emails-verification-body = Grazie per esserti registrato! Verifica il tuo indirizzo email cliccando il pulsante qui sotto. Il link scade tra { $hours } ore.
emails-verification-button = Verifica Email
emails-verification-ignore = Se non hai creato un account, puoi ignorare questa email.
emails-verification-alternative = Oppure copia e incolla questo link nel tuo browser:

## Emails - Password Reset
emails-password-reset-subject = Reimposta la tua password
emails-password-reset-greeting = Ciao { $name },
emails-password-reset-body = Abbiamo ricevuto una richiesta di reimpostazione della password. Clicca il pulsante qui sotto per creare una nuova password. Il link scade tra { $hours } ore.
emails-password-reset-button = Reimposta Password
emails-password-reset-ignore = Se non hai richiesto la reimpostazione, puoi ignorare questa email. La tua password rimarrà invariata.

## Emails - Magic Link
emails-magic-link-subject = Il tuo link magico per l'accesso
emails-magic-link-greeting = Ciao { $name },
emails-magic-link-body = Clicca il pulsante qui sotto per accedere al tuo account. Il link scade tra { $minutes } minuti e può essere usato solo una volta.
emails-magic-link-button = Accedi
emails-magic-link-ignore = Se non hai richiesto questo link, puoi ignorare questa email.

## Emails - Organization Invitation
emails-invitation-subject = Sei stato invitato a unirti a { $organization }
emails-invitation-greeting = Ciao { $name },
emails-invitation-body = { $inviter } ti ha invitato a unirti a { $organization } come { $role }.
emails-invitation-body-accept = Clicca il pulsante qui sotto per accettare l'invito. Il link scade tra { $days } giorni.
emails-invitation-button = Accetta Invito

## Emails - Security Alerts
emails-security-alert-subject = Avviso di sicurezza: { $alert_type }
emails-security-alert-greeting = Ciao { $name },
emails-security-alert-new-device = Abbiamo notato un accesso al tuo account da un nuovo dispositivo.
emails-security-alert-password-changed = La tua password è stata cambiata recentemente.
emails-security-alert-email-changed = Il tuo indirizzo email è stato cambiato recentemente.
emails-security-alert-mfa-enabled = L'autenticazione a due fattori è stata abilitata sul tuo account.
emails-security-alert-mfa-disabled = L'autenticazione a due fattori è stata disabilitata sul tuo account.
emails-security-alert-suspicious-login = Abbiamo rilevato un tentativo di accesso sospetto sul tuo account.
emails-security-alert-account-locked = Il tuo account è stato temporaneamente bloccato a causa di più tentativi di accesso falliti.
emails-security-alert-details = Ora: { $timestamp }
emails-security-alert-ip = Indirizzo IP: { $ip }
emails-security-alert-device = Dispositivo: { $device }
emails-security-alert-location = Posizione: { $location }
emails-security-alert-action = Se eri tu, puoi ignorare questa email. Se non riconosci questa attività, proteggi immediatamente il tuo account.

## Emails - Backup Codes
emails-backup-codes-subject = I tuoi codici di backup
emails-backup-codes-greeting = Ciao { $name },
emails-backup-codes-body = Hai abilitato l'autenticazione a due fattori sul tuo account. Ecco i tuoi codici di backup:
emails-backup-codes-warning = Importante: Salva questi codici in un posto sicuro. Ogni codice può essere usato solo una volta. Se perdi l'accesso alla tua app di autenticazione, avrai bisogno di questi codici per accedere.
emails-backup-codes-security = Non condividere mai questi codici con nessuno.

## Emails - Welcome
emails-welcome-subject = Benvenuto in { $app_name }!
emails-welcome-greeting = Ciao { $name },
emails-welcome-body = Benvenuto! Il tuo account è stato creato con successo. Siamo felici di averti con noi.
emails-welcome-docs = Hai bisogno di aiuto per iniziare? Consulta la nostra documentazione.
emails-welcome-support = Se hai domande, contatta il nostro team di supporto.
emails-welcome-button = Vai alla Dashboard

## Emails - New Device
emails-new-device-subject = Nuovo dispositivo ha effettuato l'accesso al tuo account
emails-new-device-greeting = Ciao { $name },
emails-new-device-body = Abbiamo notato che un nuovo dispositivo ha effettuato l'accesso al tuo account:
emails-new-device-trust-button = Sì, Fidati di Questo Dispositivo
emails-new-device-revoke-button = No, Revoca Accesso
emails-new-device-question = Eri tu?

## UI Labels
ui-login = Accedi
ui-register = Registrati
ui-logout = Esci
ui-forgot-password = Password dimenticata?
ui-reset-password = Reimposta Password
ui-verify-email = Verifica Email
ui-resend-code = Rinvia codice
ui-back = Indietro
ui-continue = Continua
ui-submit = Invia
ui-cancel = Annulla
ui-save = Salva
ui-delete = Elimina
ui-edit = Modifica
ui-close = Chiudi
ui-loading = Caricamento...
ui-success = Successo
ui-error = Errore
ui-warning = Avviso
ui-info = Info

## MFA Methods
mfa-totp = App di Autenticazione
mfa-sms = SMS
mfa-email = Email
mfa-webauthn = Chiave di Sicurezza
mfa-backup-codes = Codici di Backup

## Webhook Events
webhook-user-created = Account utente creato
webhook-user-updated = Profilo utente aggiornato
webhook-user-deleted = Account utente eliminato
webhook-user-login = Utente ha effettuato l'accesso
webhook-user-logout = Utente ha effettuato la disconnessione
webhook-session-created = Nuova sessione creata
webhook-session-revoked = Sessione revocata
webhook-mfa-enabled = Autenticazione multi-fattore abilitata
webhook-mfa-disabled = Autenticazione multi-fattore disabilitata
webhook-password-changed = Password cambiata
webhook-email-changed = Indirizzo email cambiato
webhook-email-verified = Indirizzo email verificato

## Time
time-just-now = proprio ora
time-minutes-ago = { $minutes } minuto fa
time-minutes-ago-plural = { $minutes } minuti fa
time-hours-ago = { $hours } ora fa
time-hours-ago-plural = { $hours } ore fa
time-days-ago = { $days } giorno fa
time-days-ago-plural = { $days } giorni fa

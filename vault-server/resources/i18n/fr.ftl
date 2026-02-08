# French translations for Vault Auth Server

## Common
-brand-name = Vault
-app-name = Vault Auth

## Errors - Authentication
errors-invalid-credentials = Email ou mot de passe invalide
errors-account-locked = Compte verrouillé. Réessayez dans { $minutes } minutes.
errors-account-disabled = Votre compte a été désactivé. Veuillez contacter le support.
errors-account-pending = Votre compte est en attente de vérification. Veuillez vérifier vos emails.
errors-session-expired = Votre session a expiré. Veuillez vous reconnecter.
errors-invalid-token = Token invalide ou expiré
errors-token-revoked = Ce token a été révoqué
errors-mfa-required = Authentification multi-facteur requise
errors-mfa-invalid = Code de vérification invalide
errors-mfa-setup-required = Veuillez configurer l'authentification multi-facteur
errors-password-expired = Votre mot de passe a expiré. Veuillez le réinitialiser.
errors-too-many-attempts = Trop de tentatives. Veuillez réessayer plus tard.

## Errors - Authorization
errors-unauthorized = Authentification requise
errors-forbidden = Accès refusé
errors-insufficient-permissions = Vous n'avez pas la permission d'effectuer cette action
errors-tenant-access-denied = Accès refusé pour cette organisation

## Errors - Validation
errors-validation-failed = Validation échouée
errors-invalid-email = Veuillez entrer une adresse email valide
errors-invalid-password = Le mot de passe ne répond pas aux exigences
errors-password-mismatch = Les mots de passe ne correspondent pas
errors-invalid-format = Format invalide
errors-field-required = Ce champ est requis
errors-invalid-uuid = Format d'identifiant invalide
errors-value-too-short = Valeur trop courte (minimum { $min } caractères)
errors-value-too-long = Valeur trop longue (maximum { $max } caractères)

## Errors - Resource
errors-not-found = { $resource } non trouvé
errors-user-not-found = Utilisateur non trouvé
errors-organization-not-found = Organisation non trouvée
errors-session-not-found = Session non trouvée
errors-already-exists = { $resource } existe déjà
errors-email-already-exists = Un compte avec cet email existe déjà

## Errors - Rate Limiting
errors-rate-limited = Trop de requêtes. Veuillez réessayer dans { $seconds } secondes.
errors-session-limit-reached = Nombre maximum de sessions simultanées atteint ({ $max }). Veuillez vous déconnecter d'un autre appareil.

## Errors - Server
errors-internal-error = Une erreur interne s'est produite. Veuillez réessayer plus tard.
errors-service-unavailable = Service temporairement indisponible. Veuillez réessayer plus tard.
errors-database-error = Erreur de base de données
errors-external-service = Erreur de service externe ({ $service }): { $message }

## Emails - Verification
emails-verification-subject = Vérifiez votre adresse email
emails-verification-greeting = Bonjour { $name },
emails-verification-body = Merci de vous être inscrit ! Veuillez vérifier votre adresse email en cliquant sur le bouton ci-dessous. Ce lien expirera dans { $hours } heures.
emails-verification-button = Vérifier l'Email
emails-verification-ignore = Si vous n'avez pas créé de compte, vous pouvez ignorer cet email en toute sécurité.
emails-verification-alternative = Ou copiez et collez ce lien dans votre navigateur :

## Emails - Password Reset
emails-password-reset-subject = Réinitialisez votre mot de passe
emails-password-reset-greeting = Bonjour { $name },
emails-password-reset-body = Nous avons reçu une demande de réinitialisation de votre mot de passe. Cliquez sur le bouton ci-dessous pour créer un nouveau mot de passe. Ce lien expirera dans { $hours } heures.
emails-password-reset-button = Réinitialiser le Mot de Passe
emails-password-reset-ignore = Si vous n'avez pas demandé de réinitialisation, vous pouvez ignorer cet email en toute sécurité. Votre mot de passe restera inchangé.

## Emails - Magic Link
emails-magic-link-subject = Votre lien magique pour vous connecter
emails-magic-link-greeting = Bonjour { $name },
emails-magic-link-body = Cliquez sur le bouton ci-dessous pour vous connecter à votre compte. Ce lien expirera dans { $minutes } minutes et ne peut être utilisé qu'une seule fois.
emails-magic-link-button = Se Connecter
emails-magic-link-ignore = Si vous n'avez pas demandé ce lien, vous pouvez ignorer cet email en toute sécurité.

## Emails - Organization Invitation
emails-invitation-subject = Vous êtes invité à rejoindre { $organization }
emails-invitation-greeting = Bonjour { $name },
emails-invitation-body = { $inviter } vous a invité à rejoindre { $organization } en tant que { $role }.
emails-invitation-body-accept = Cliquez sur le bouton ci-dessous pour accepter l'invitation. Ce lien expirera dans { $days } jours.
emails-invitation-button = Accepter l'Invitation

## Emails - Security Alerts
emails-security-alert-subject = Alerte de sécurité : { $alert_type }
emails-security-alert-greeting = Bonjour { $name },
emails-security-alert-new-device = Nous avons remarqué une connexion à votre compte depuis un nouvel appareil.
emails-security-alert-password-changed = Votre mot de passe a été récemment modifié.
emails-security-alert-email-changed = Votre adresse email a été récemment modifiée.
emails-security-alert-mfa-enabled = L'authentification à deux facteurs a été activée sur votre compte.
emails-security-alert-mfa-disabled = L'authentification à deux facteurs a été désactivée sur votre compte.
emails-security-alert-suspicious-login = Nous avons détecté une tentative de connexion suspecte sur votre compte.
emails-security-alert-account-locked = Votre compte a été temporairement verrouillé en raison de plusieurs tentatives de connexion échouées.
emails-security-alert-details = Heure : { $timestamp }
emails-security-alert-ip = Adresse IP : { $ip }
emails-security-alert-device = Appareil : { $device }
emails-security-alert-location = Localisation : { $location }
emails-security-alert-action = Si c'était vous, vous pouvez ignorer cet email. Si vous ne reconnaissez pas cette activité, veuillez sécuriser votre compte immédiatement.

## Emails - Backup Codes
emails-backup-codes-subject = Vos codes de secours
emails-backup-codes-greeting = Bonjour { $name },
emails-backup-codes-body = Vous avez activé l'authentification à deux facteurs sur votre compte. Voici vos codes de secours :
emails-backup-codes-warning = Important : Conservez ces codes dans un endroit sûr. Chaque code ne peut être utilisé qu'une seule fois. Si vous perdez l'accès à votre application d'authentification, vous aurez besoin de ces codes pour vous connecter.
emails-backup-codes-security = Ne partagez jamais ces codes avec personne.

## Emails - Welcome
emails-welcome-subject = Bienvenue sur { $app_name } !
emails-welcome-greeting = Bonjour { $name },
emails-welcome-body = Bienvenue ! Votre compte a été créé avec succès. Nous sommes ravis de vous compter parmi nous.
emails-welcome-docs = Besoin d'aide pour démarrer ? Consultez notre documentation.
emails-welcome-support = Si vous avez des questions, n'hésitez pas à contacter notre équipe de support.
emails-welcome-button = Aller au Tableau de Bord

## Emails - New Device
emails-new-device-subject = Nouvel appareil connecté à votre compte
emails-new-device-greeting = Bonjour { $name },
emails-new-device-body = Nous avons remarqué qu'un nouvel appareil s'est connecté à votre compte :
emails-new-device-trust-button = Oui, Faire Confiance à cet Appareil
emails-new-device-revoke-button = Non, Révoquer l'Accès
emails-new-device-question = Était-ce vous ?

## UI Labels
ui-login = Se Connecter
ui-register = S'inscrire
ui-logout = Se Déconnecter
ui-forgot-password = Mot de passe oublié ?
ui-reset-password = Réinitialiser le Mot de Passe
ui-verify-email = Vérifier l'Email
ui-resend-code = Renvoyer le code
ui-back = Retour
ui-continue = Continuer
ui-submit = Soumettre
ui-cancel = Annuler
ui-save = Enregistrer
ui-delete = Supprimer
ui-edit = Modifier
ui-close = Fermer
ui-loading = Chargement...
ui-success = Succès
ui-error = Erreur
ui-warning = Avertissement
ui-info = Info

## MFA Methods
mfa-totp = Application d'Authentification
mfa-sms = SMS
mfa-email = Email
mfa-webauthn = Clé de Sécurité
mfa-backup-codes = Codes de Secours

## Webhook Events
webhook-user-created = Compte utilisateur créé
webhook-user-updated = Profil utilisateur mis à jour
webhook-user-deleted = Compte utilisateur supprimé
webhook-user-login = Utilisateur connecté
webhook-user-logout = Utilisateur déconnecté
webhook-session-created = Nouvelle session créée
webhook-session-revoked = Session révoquée
webhook-mfa-enabled = Authentification multi-facteur activée
webhook-mfa-disabled = Authentification multi-facteur désactivée
webhook-password-changed = Mot de passe changé
webhook-email-changed = Adresse email changée
webhook-email-verified = Adresse email vérifiée

## Time
time-just-now = à l'instant
time-minutes-ago = il y a { $minutes } minute
time-minutes-ago-plural = il y a { $minutes } minutes
time-hours-ago = il y a { $hours } heure
time-hours-ago-plural = il y a { $hours } heures
time-days-ago = il y a { $days } jour
time-days-ago-plural = il y a { $days } jours

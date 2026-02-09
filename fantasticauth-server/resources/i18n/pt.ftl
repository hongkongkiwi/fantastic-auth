# Portuguese translations for Vault Auth Server

## Common
-brand-name = Vault
-app-name = Vault Auth

## Errors - Authentication
errors-invalid-credentials = Email ou senha inválidos
errors-account-locked = Conta bloqueada. Tente novamente em { $minutes } minutos.
errors-account-disabled = Sua conta foi desativada. Entre em contato com o suporte.
errors-account-pending = Sua conta está aguardando verificação. Verifique seu email.
errors-session-expired = Sua sessão expirou. Faça login novamente.
errors-invalid-token = Token inválido ou expirado
errors-token-revoked = Este token foi revogado
errors-mfa-required = Autenticação multi-fator necessária
errors-mfa-invalid = Código de verificação inválido
errors-mfa-setup-required = Configure a autenticação multi-fator
errors-password-expired = Sua senha expirou. Redefina-a.
errors-too-many-attempts = Muitas tentativas. Tente novamente mais tarde.

## Errors - Authorization
errors-unauthorized = Autenticação necessária
errors-forbidden = Acesso negado
errors-insufficient-permissions = Você não tem permissão para executar esta ação
errors-tenant-access-denied = Acesso negado para esta organização

## Errors - Validation
errors-validation-failed = Validação falhou
errors-invalid-email = Por favor, insira um endereço de email válido
errors-invalid-password = A senha não atende aos requisitos
errors-password-mismatch = As senhas não coincidem
errors-invalid-format = Formato inválido
errors-field-required = Este campo é obrigatório
errors-invalid-uuid = Formato de identificador inválido
errors-value-too-short = Valor muito curto (mínimo { $min } caracteres)
errors-value-too-long = Valor muito longo (máximo { $max } caracteres)

## Errors - Resource
errors-not-found = { $resource } não encontrado
errors-user-not-found = Usuário não encontrado
errors-organization-not-found = Organização não encontrada
errors-session-not-found = Sessão não encontrada
errors-already-exists = { $resource } já existe
errors-email-already-exists = Já existe uma conta com este email

## Errors - Rate Limiting
errors-rate-limited = Muitas solicitações. Tente novamente em { $seconds } segundos.
errors-session-limit-reached = Limite máximo de sessões simultâneas atingido ({ $max }). Saia de outro dispositivo.

## Errors - Server
errors-internal-error = Ocorreu um erro interno. Tente novamente mais tarde.
errors-service-unavailable = Serviço temporariamente indisponível. Tente novamente mais tarde.
errors-database-error = Erro de banco de dados
errors-external-service = Erro de serviço externo ({ $service }): { $message }

## Emails - Verification
emails-verification-subject = Verifique seu endereço de email
emails-verification-greeting = Olá { $name },
emails-verification-body = Obrigado por se registrar! Verifique seu endereço de email clicando no botão abaixo. Este link expira em { $hours } horas.
emails-verification-button = Verificar Email
emails-verification-ignore = Se você não criou uma conta, pode ignorar este email com segurança.
emails-verification-alternative = Ou copie e cole este link no seu navegador:

## Emails - Password Reset
emails-password-reset-subject = Redefina sua senha
emails-password-reset-greeting = Olá { $name },
emails-password-reset-body = Recebemos uma solicitação para redefinir sua senha. Clique no botão abaixo para criar uma nova senha. Este link expira em { $hours } horas.
emails-password-reset-button = Redefinir Senha
emails-password-reset-ignore = Se você não solicitou a redefinição, pode ignorar este email com segurança. Sua senha permanecerá inalterada.

## Emails - Magic Link
emails-magic-link-subject = Seu link mágico para entrar
emails-magic-link-greeting = Olá { $name },
emails-magic-link-body = Clique no botão abaixo para entrar na sua conta. Este link expira em { $minutes } minutos e só pode ser usado uma vez.
emails-magic-link-button = Entrar
emails-magic-link-ignore = Se você não solicitou este link, pode ignorar este email com segurança.

## Emails - Organization Invitation
emails-invitation-subject = Você foi convidado para se juntar a { $organization }
emails-invitation-greeting = Olá { $name },
emails-invitation-body = { $inviter } convidou você para se juntar a { $organization } como { $role }.
emails-invitation-body-accept = Clique no botão abaixo para aceitar o convite. Este link expira em { $days } dias.
emails-invitation-button = Aceitar Convite

## Emails - Security Alerts
emails-security-alert-subject = Alerta de segurança: { $alert_type }
emails-security-alert-greeting = Olá { $name },
emails-security-alert-new-device = Notamos um login na sua conta a partir de um novo dispositivo.
emails-security-alert-password-changed = Sua senha foi alterada recentemente.
emails-security-alert-email-changed = Seu endereço de email foi alterado recentemente.
emails-security-alert-mfa-enabled = A autenticação de dois fatores foi habilitada na sua conta.
emails-security-alert-mfa-disabled = A autenticação de dois fatores foi desabilitada na sua conta.
emails-security-alert-suspicious-login = Detectamos uma tentativa de login suspeita na sua conta.
emails-security-alert-account-locked = Sua conta foi temporariamente bloqueada devido a várias tentativas de login falhas.
emails-security-alert-details = Horário: { $timestamp }
emails-security-alert-ip = Endereço IP: { $ip }
emails-security-alert-device = Dispositivo: { $device }
emails-security-alert-location = Localização: { $location }
emails-security-alert-action = Se foi você, pode ignorar este email. Se não reconhecer esta atividade, proteja sua conta imediatamente.

## Emails - Backup Codes
emails-backup-codes-subject = Seus códigos de backup
emails-backup-codes-greeting = Olá { $name },
emails-backup-codes-body = Você habilitou a autenticação de dois fatores na sua conta. Aqui estão seus códigos de backup:
emails-backup-codes-warning = Importante: Guarde estes códigos em um lugar seguro. Cada código só pode ser usado uma vez. Se perder o acesso ao seu aplicativo de autenticação, precisará destes códigos para entrar.
emails-backup-codes-security = Nunca compartilhe estes códigos com ninguém.

## Emails - Welcome
emails-welcome-subject = Bem-vindo ao { $app_name }!
emails-welcome-greeting = Olá { $name },
emails-welcome-body = Bem-vindo! Sua conta foi criada com sucesso. Estamos felizes em tê-lo conosco.
emails-welcome-docs = Precisa de ajuda para começar? Consulte nossa documentação.
emails-welcome-support = Se tiver alguma dúvida, entre em contato com nossa equipe de suporte.
emails-welcome-button = Ir para o Painel

## Emails - New Device
emails-new-device-subject = Novo dispositivo fez login na sua conta
emails-new-device-greeting = Olá { $name },
emails-new-device-body = Notamos que um novo dispositivo fez login na sua conta:
emails-new-device-trust-button = Sim, Confiar neste Dispositivo
emails-new-device-revoke-button = Não, Revogar Acesso
emails-new-device-question = Foi você?

## UI Labels
ui-login = Entrar
ui-register = Cadastrar
ui-logout = Sair
ui-forgot-password = Esqueceu a senha?
ui-reset-password = Redefinir Senha
ui-verify-email = Verificar Email
ui-resend-code = Reenviar código
ui-back = Voltar
ui-continue = Continuar
ui-submit = Enviar
ui-cancel = Cancelar
ui-save = Salvar
ui-delete = Excluir
ui-edit = Editar
ui-close = Fechar
ui-loading = Carregando...
ui-success = Sucesso
ui-error = Erro
ui-warning = Aviso
ui-info = Informação

## MFA Methods
mfa-totp = App de Autenticação
mfa-sms = SMS
mfa-email = Email
mfa-webauthn = Chave de Segurança
mfa-backup-codes = Códigos de Backup

## Webhook Events
webhook-user-created = Conta de usuário criada
webhook-user-updated = Perfil de usuário atualizado
webhook-user-deleted = Conta de usuário excluída
webhook-user-login = Usuário fez login
webhook-user-logout = Usuário fez logout
webhook-session-created = Nova sessão criada
webhook-session-revoked = Sessão revogada
webhook-mfa-enabled = Autenticação multi-fator habilitada
webhook-mfa-disabled = Autenticação multi-fator desabilitada
webhook-password-changed = Senha alterada
webhook-email-changed = Endereço de email alterado
webhook-email-verified = Endereço de email verificado

## Time
time-just-now = agora mesmo
time-minutes-ago = { $minutes } minuto atrás
time-minutes-ago-plural = { $minutes } minutos atrás
time-hours-ago = { $hours } hora atrás
time-hours-ago-plural = { $hours } horas atrás
time-days-ago = { $days } dia atrás
time-days-ago-plural = { $days } dias atrás

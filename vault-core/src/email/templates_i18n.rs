//! i18n-enabled email templates for authentication and user management
//!
//! These templates support multiple languages and RTL (Right-to-Left) text direction.

use super::{EmailError, TemplateEngine};
use serde::Serialize;

/// Supported languages for email templates
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EmailLanguage {
    #[default]
    English,
    Spanish,
    French,
    German,
    Italian,
    Portuguese,
    Chinese,
    Japanese,
    Korean,
    Arabic,
    Russian,
}

impl EmailLanguage {
    /// Get language code
    pub fn code(&self) -> &'static str {
        match self {
            EmailLanguage::English => "en",
            EmailLanguage::Spanish => "es",
            EmailLanguage::French => "fr",
            EmailLanguage::German => "de",
            EmailLanguage::Italian => "it",
            EmailLanguage::Portuguese => "pt",
            EmailLanguage::Chinese => "zh",
            EmailLanguage::Japanese => "ja",
            EmailLanguage::Korean => "ko",
            EmailLanguage::Arabic => "ar",
            EmailLanguage::Russian => "ru",
        }
    }

    /// Parse from language code
    pub fn from_code(code: &str) -> Option<Self> {
        match code.to_lowercase().as_str() {
            "en" | "en-us" | "en-gb" => Some(EmailLanguage::English),
            "es" | "es-es" | "es-mx" => Some(EmailLanguage::Spanish),
            "fr" | "fr-fr" | "fr-ca" => Some(EmailLanguage::French),
            "de" | "de-de" => Some(EmailLanguage::German),
            "it" | "it-it" => Some(EmailLanguage::Italian),
            "pt" | "pt-br" | "pt-pt" => Some(EmailLanguage::Portuguese),
            "zh" | "zh-cn" | "zh-hans" => Some(EmailLanguage::Chinese),
            "ja" | "ja-jp" => Some(EmailLanguage::Japanese),
            "ko" | "ko-kr" => Some(EmailLanguage::Korean),
            "ar" | "ar-sa" => Some(EmailLanguage::Arabic),
            "ru" | "ru-ru" => Some(EmailLanguage::Russian),
            _ => None,
        }
    }

    /// Check if language is RTL
    pub fn is_rtl(&self) -> bool {
        matches!(self, EmailLanguage::Arabic)
    }

    /// Get text direction
    pub fn direction(&self) -> &'static str {
        if self.is_rtl() {
            "rtl"
        } else {
            "ltr"
        }
    }
}

/// Trait for i18n-enabled email templates
pub trait I18nEmailTemplate: Serialize {
    /// Get the email subject for the given language
    fn subject(&self, lang: EmailLanguage) -> String;

    /// Render HTML version for the given language
    fn render_html(&self, engine: &TemplateEngine, lang: EmailLanguage) -> Result<String, EmailError>;

    /// Render plain text version for the given language
    fn render_text(&self, engine: &TemplateEngine, lang: EmailLanguage) -> Result<String, EmailError>;
}

/// Email template context with language
#[derive(Debug, Clone)]
pub struct EmailContext {
    pub language: EmailLanguage,
    pub base_url: String,
    pub app_name: String,
}

impl EmailContext {
    pub fn new(language: EmailLanguage, base_url: String, app_name: String) -> Self {
        Self { language, base_url, app_name }
    }

    pub fn with_language(lang_code: &str, base_url: String, app_name: String) -> Self {
        let language = EmailLanguage::from_code(lang_code).unwrap_or_default();
        Self { language, base_url, app_name }
    }
}

/// i18n-enabled email verification template
#[derive(Serialize)]
pub struct I18nVerificationEmail {
    pub name: String,
    pub verification_url: String,
    pub expires_in_hours: i32,
}

impl I18nEmailTemplate for I18nVerificationEmail {
    fn subject(&self, lang: EmailLanguage) -> String {
        match lang {
            EmailLanguage::English => "Verify your email address".to_string(),
            EmailLanguage::Spanish => "Verifica tu dirección de correo".to_string(),
            EmailLanguage::French => "Vérifiez votre adresse email".to_string(),
            EmailLanguage::German => "Bestätigen Sie Ihre E-Mail-Adresse".to_string(),
            EmailLanguage::Italian => "Verifica il tuo indirizzo email".to_string(),
            EmailLanguage::Portuguese => "Verifique seu endereço de email".to_string(),
            EmailLanguage::Chinese => "验证您的邮箱地址".to_string(),
            EmailLanguage::Japanese => "メールアドレスの確認".to_string(),
            EmailLanguage::Korean => "이메일 주소 인증".to_string(),
            EmailLanguage::Arabic => "تحقق من عنوان بريدك الإلكتروني".to_string(),
            EmailLanguage::Russian => "Подтвердите свой email".to_string(),
        }
    }

    fn render_html(&self, _engine: &TemplateEngine, lang: EmailLanguage) -> Result<String, EmailError> {
        let (greeting, body, button, ignore, expires_text) = self.get_translations(lang);
        let rtl_attr = if lang.is_rtl() { "dir=\"rtl\"" } else { "" };
        let align = if lang.is_rtl() { "right" } else { "left" };

        Ok(format!(
            r##"<!DOCTYPE html>
<html lang="{}" {}>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{}</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; background-color: #f5f5f5; direction: {};">
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #f5f5f5;">
        <tr>
            <td align="center" style="padding: 40px 20px;">
                <table width="600" cellpadding="0" cellspacing="0" border="0" style="background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                    <tr>
                        <td style="padding: 40px; text-align: {};">
                            <h1 style="color: #1a1a1a; font-size: 24px; margin: 0 0 16px 0; font-weight: 600;">{}</h1>
                            <p style="color: #4a4a4a; font-size: 16px; line-height: 1.6; margin: 0 0 16px 0;">{}</p>
                            <p style="color: #4a4a4a; font-size: 16px; line-height: 1.6; margin: 0 0 24px 0;">{}</p>
                            <p style="margin: 32px 0;">
                                <a href="{}" style="background-color: #0066cc; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: 600;">{}</a>
                            </p>
                            <p style="color: #888888; font-size: 14px; margin-top: 24px;">{}</p>
                            <p style="color: #888888; font-size: 12px; word-break: break-all;">{}</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>"##,
            lang.code(), rtl_attr, self.subject(lang), lang.direction(), align,
            greeting, body, expires_text, self.verification_url, button, ignore, self.verification_url
        ))
    }

    fn render_text(&self, _engine: &TemplateEngine, lang: EmailLanguage) -> Result<String, EmailError> {
        let (greeting, body, button, ignore, expires_text) = self.get_translations(lang);
        
        Ok(format!(
            r#"{}

{}

{}

{}: {}

{}

{}"#,
            greeting, body, expires_text, button, self.verification_url, ignore, self.verification_url
        ))
    }
}

impl I18nVerificationEmail {
    fn get_translations(&self, lang: EmailLanguage) -> (String, String, String, String, String) {
        match lang {
            EmailLanguage::English => (
                format!("Hi {},", self.name),
                "Thanks for signing up! Please verify your email address by clicking the button below.".to_string(),
                "Verify Email".to_string(),
                "If you didn't create an account, you can safely ignore this email.".to_string(),
                format!("This link will expire in {} hours.", self.expires_in_hours),
            ),
            EmailLanguage::Spanish => (
                format!("Hola {},", self.name),
                "¡Gracias por registrarte! Por favor verifica tu dirección de correo haciendo clic en el botón de abajo.".to_string(),
                "Verificar Correo".to_string(),
                "Si no creaste una cuenta, puedes ignorar este correo de forma segura.".to_string(),
                format!("Este enlace expirará en {} horas.", self.expires_in_hours),
            ),
            EmailLanguage::French => (
                format!("Bonjour {},", self.name),
                "Merci pour votre inscription ! Veuillez vérifier votre adresse email en cliquant sur le bouton ci-dessous.".to_string(),
                "Vérifier l'Email".to_string(),
                "Si vous n'avez pas créé de compte, vous pouvez ignorer cet email en toute sécurité.".to_string(),
                format!("Ce lien expirera dans {} heures.", self.expires_in_hours),
            ),
            EmailLanguage::German => (
                format!("Hallo {},", self.name),
                "Vielen Dank für Ihre Registrierung! Bitte bestätigen Sie Ihre E-Mail-Adresse, indem Sie auf die Schaltfläche unten klicken.".to_string(),
                "E-Mail Bestätigen".to_string(),
                "Wenn Sie kein Konto erstellt haben, können Sie diese E-Mail ignorieren.".to_string(),
                format!("Dieser Link läuft in {} Stunden ab.", self.expires_in_hours),
            ),
            EmailLanguage::Italian => (
                format!("Ciao {},", self.name),
                "Grazie per esserti registrato! Verifica il tuo indirizzo email cliccando il pulsante qui sotto.".to_string(),
                "Verifica Email".to_string(),
                "Se non hai creato un account, puoi ignorare questa email.".to_string(),
                format!("Il link scade tra {} ore.", self.expires_in_hours),
            ),
            EmailLanguage::Portuguese => (
                format!("Olá {},", self.name),
                "Obrigado por se registrar! Verifique seu endereço de email clicando no botão abaixo.".to_string(),
                "Verificar Email".to_string(),
                "Se você não criou uma conta, pode ignorar este email com segurança.".to_string(),
                format!("Este link expira em {} horas.", self.expires_in_hours),
            ),
            EmailLanguage::Chinese => (
                format!("您好 {},", self.name),
                "感谢您的注册！请点击下方按钮验证您的邮箱地址。".to_string(),
                "验证邮箱".to_string(),
                "如果您没有创建账户，可以安全地忽略此邮件。".to_string(),
                format!("此链接将在 {} 小时后过期。", self.expires_in_hours),
            ),
            EmailLanguage::Japanese => (
                format!("{}様、", self.name),
                "ご登録ありがとうございます！以下のボタンをクリックしてメールアドレスを確認してください。".to_string(),
                "メールを確認".to_string(),
                "アカウントを作成していない場合は、このメールを無視していただいて構いません。".to_string(),
                format!("このリンクは{}時間後に期限切れとなります。", self.expires_in_hours),
            ),
            EmailLanguage::Korean => (
                format!("{}님 안녕하세요,", self.name),
                "가입해 주셔서 감사합니다! 아래 버튼을 클릭하여 이메일 주소를 인증하세요.".to_string(),
                "이메일 인증".to_string(),
                "계정을 생성하지 않았다면 이 이메일을 무시하셔도 됩니다.".to_string(),
                format!("이 링크는 {}시간 후에 만료됩니다.", self.expires_in_hours),
            ),
            EmailLanguage::Arabic => (
                format!("مرحباً {},", self.name),
                "شكراً للتسجيل! يرجى التحقق من عنوان بريدك الإلكتروني بالنقر على الزر أدناه.".to_string(),
                "تحقق من البريد".to_string(),
                "إذا لم تقم بإنشاء حساب، يمكنك تجاهل هذا البريد بأمان.".to_string(),
                format!("سينتهي هذا الرابط خلال {} ساعة.", self.expires_in_hours),
            ),
            EmailLanguage::Russian => (
                format!("Здравствуйте, {},", self.name),
                "Спасибо за регистрацию! Пожалуйста, подтвердите свой email, нажав кнопку ниже.".to_string(),
                "Подтвердить email".to_string(),
                "Если вы не создавали аккаунт, можете проигнорировать это письмо.".to_string(),
                format!("Ссылка истекает через {} часов.", self.expires_in_hours),
            ),
        }
    }
}

/// i18n-enabled password reset template
#[derive(Serialize)]
pub struct I18nPasswordResetEmail {
    pub name: String,
    pub reset_url: String,
    pub expires_in_hours: i32,
}

impl I18nEmailTemplate for I18nPasswordResetEmail {
    fn subject(&self, lang: EmailLanguage) -> String {
        match lang {
            EmailLanguage::English => "Reset your password".to_string(),
            EmailLanguage::Spanish => "Restablece tu contraseña".to_string(),
            EmailLanguage::French => "Réinitialisez votre mot de passe".to_string(),
            EmailLanguage::German => "Setzen Sie Ihr Passwort zurück".to_string(),
            EmailLanguage::Italian => "Reimposta la tua password".to_string(),
            EmailLanguage::Portuguese => "Redefina sua senha".to_string(),
            EmailLanguage::Chinese => "重置您的密码".to_string(),
            EmailLanguage::Japanese => "パスワードのリセット".to_string(),
            EmailLanguage::Korean => "비밀번호 재설정".to_string(),
            EmailLanguage::Arabic => "إعادة تعيين كلمة المرور".to_string(),
            EmailLanguage::Russian => "Сброс пароля".to_string(),
        }
    }

    fn render_html(&self, _engine: &TemplateEngine, lang: EmailLanguage) -> Result<String, EmailError> {
        let (greeting, body, button, ignore, expires_text) = self.get_translations(lang);
        let rtl_attr = if lang.is_rtl() { "dir=\"rtl\"" } else { "" };
        let align = if lang.is_rtl() { "right" } else { "left" };

        Ok(format!(
            r##"<!DOCTYPE html>
<html lang="{}" {}>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{}</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; background-color: #f5f5f5; direction: {};">
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #f5f5f5;">
        <tr>
            <td align="center" style="padding: 40px 20px;">
                <table width="600" cellpadding="0" cellspacing="0" border="0" style="background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                    <tr>
                        <td style="padding: 40px; text-align: {};">
                            <h1 style="color: #1a1a1a; font-size: 24px; margin: 0 0 16px 0; font-weight: 600;">{}</h1>
                            <p style="color: #4a4a4a; font-size: 16px; line-height: 1.6; margin: 0 0 16px 0;">{}</p>
                            <p style="color: #4a4a4a; font-size: 16px; line-height: 1.6; margin: 0 0 24px 0;">{}</p>
                            <p style="margin: 32px 0;">
                                <a href="{}" style="background-color: #0066cc; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: 600;">{}</a>
                            </p>
                            <p style="color: #888888; font-size: 14px; margin-top: 24px;">{}</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>"##,
            lang.code(), rtl_attr, self.subject(lang), lang.direction(), align,
            greeting, body, expires_text, self.reset_url, button, ignore
        ))
    }

    fn render_text(&self, _engine: &TemplateEngine, lang: EmailLanguage) -> Result<String, EmailError> {
        let (greeting, body, button, ignore, expires_text) = self.get_translations(lang);
        
        Ok(format!(
            r#"{}

{}

{}

{}: {}

{}"#,
            greeting, body, expires_text, button, self.reset_url, ignore
        ))
    }
}

impl I18nPasswordResetEmail {
    fn get_translations(&self, lang: EmailLanguage) -> (String, String, String, String, String) {
        match lang {
            EmailLanguage::English => (
                format!("Hi {},", self.name),
                "We received a request to reset your password. Click the button below to create a new password.".to_string(),
                "Reset Password".to_string(),
                "If you didn't request a password reset, you can safely ignore this email.".to_string(),
                format!("This link will expire in {} hours.", self.expires_in_hours),
            ),
            EmailLanguage::Spanish => (
                format!("Hola {},", self.name),
                "Recibimos una solicitud para restablecer tu contraseña. Haz clic en el botón de abajo para crear una nueva contraseña.".to_string(),
                "Restablecer Contraseña".to_string(),
                "Si no solicitaste un restablecimiento de contraseña, puedes ignorar este correo de forma segura.".to_string(),
                format!("Este enlace expirará en {} horas.", self.expires_in_hours),
            ),
            EmailLanguage::French => (
                format!("Bonjour {},", self.name),
                "Nous avons reçu une demande de réinitialisation de votre mot de passe. Cliquez sur le bouton ci-dessous pour créer un nouveau mot de passe.".to_string(),
                "Réinitialiser le Mot de Passe".to_string(),
                "Si vous n'avez pas demandé de réinitialisation, vous pouvez ignorer cet email en toute sécurité.".to_string(),
                format!("Ce lien expirera dans {} heures.", self.expires_in_hours),
            ),
            EmailLanguage::German => (
                format!("Hallo {},", self.name),
                "Wir haben eine Anfrage zum Zurücksetzen Ihres Passworts erhalten. Klicken Sie auf die Schaltfläche unten, um ein neues Passwort zu erstellen.".to_string(),
                "Passwort Zurücksetzen".to_string(),
                "Wenn Sie kein Zurücksetzen angefordert haben, können Sie diese E-Mail ignorieren.".to_string(),
                format!("Dieser Link läuft in {} Stunden ab.", self.expires_in_hours),
            ),
            EmailLanguage::Italian => (
                format!("Ciao {},", self.name),
                "Abbiamo ricevuto una richiesta di reimpostazione della password. Clicca il pulsante qui sotto per creare una nuova password.".to_string(),
                "Reimposta Password".to_string(),
                "Se non hai richiesto la reimpostazione, puoi ignorare questa email.".to_string(),
                format!("Il link scade tra {} ore.", self.expires_in_hours),
            ),
            EmailLanguage::Portuguese => (
                format!("Olá {},", self.name),
                "Recebemos uma solicitação para redefinir sua senha. Clique no botão abaixo para criar uma nova senha.".to_string(),
                "Redefinir Senha".to_string(),
                "Se você não solicitou a redefinição, pode ignorar este email com segurança.".to_string(),
                format!("Este link expira em {} horas.", self.expires_in_hours),
            ),
            EmailLanguage::Chinese => (
                format!("您好 {},", self.name),
                "我们收到了重置您密码的请求。点击下方按钮创建新密码。".to_string(),
                "重置密码".to_string(),
                "如果您没有请求重置密码，可以安全地忽略此邮件。".to_string(),
                format!("此链接将在 {} 小时后过期。", self.expires_in_hours),
            ),
            EmailLanguage::Japanese => (
                format!("{}様、", self.name),
                "パスワードのリセットリクエストを受け取りました。以下のボタンをクリックして新しいパスワードを作成してください。".to_string(),
                "パスワードをリセット".to_string(),
                "リセットをリクエストしていない場合は、このメールを無視していただいて構います。".to_string(),
                format!("このリンクは{}時間後に期限切れとなります。", self.expires_in_hours),
            ),
            EmailLanguage::Korean => (
                format!("{}님 안녕하세요,", self.name),
                "비밀번호 재설정 요청을 받았습니다. 아래 버튼을 클릭하여 새 비밀번호를 만드세요.".to_string(),
                "비밀번호 재설정".to_string(),
                "재설정을 요청하지 않았다면 이 이메일을 무시하셔도 됩니다.".to_string(),
                format!("이 링크는 {}시간 후에 만료됩니다.", self.expires_in_hours),
            ),
            EmailLanguage::Arabic => (
                format!("مرحباً {},", self.name),
                "تلقينا طلباً لإعادة تعيين كلمة المرور. انقر على الزر أدناه لإنشاء كلمة مرور جديدة.".to_string(),
                "إعادة تعيين كلمة المرور".to_string(),
                "إذا لم تطلب إعادة التعيين، يمكنك تجاهل هذا البريد بأمان.".to_string(),
                format!("سينتهي هذا الرابط خلال {} ساعة.", self.expires_in_hours),
            ),
            EmailLanguage::Russian => (
                format!("Здравствуйте, {},", self.name),
                "Мы получили запрос на сброс пароля. Нажмите кнопку ниже, чтобы создать новый пароль.".to_string(),
                "Сбросить пароль".to_string(),
                "Если вы не запрашивали сброс, можете проигнорировать это письмо.".to_string(),
                format!("Ссылка истекает через {} часов.", self.expires_in_hours),
            ),
        }
    }
}

/// Helper to extend TemplateEngine with i18n support
pub trait I18nTemplateEngine {
    /// Render an i18n-enabled template
    fn render_i18n<T: I18nEmailTemplate>(
        &self,
        template: &T,
        lang: EmailLanguage,
    ) -> Result<super::RenderedEmail, EmailError>;
}

impl I18nTemplateEngine for TemplateEngine {
    fn render_i18n<T: I18nEmailTemplate>(
        &self,
        template: &T,
        lang: EmailLanguage,
    ) -> Result<super::RenderedEmail, EmailError> {
        let html = template.render_html(self, lang)?;
        let text = template.render_text(self, lang)?;
        let subject = template.subject(lang);

        Ok(super::RenderedEmail {
            subject,
            html_body: html,
            text_body: text,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_language_parsing() {
        assert_eq!(EmailLanguage::from_code("en"), Some(EmailLanguage::English));
        assert_eq!(EmailLanguage::from_code("es-MX"), Some(EmailLanguage::Spanish));
        assert_eq!(EmailLanguage::from_code("ar"), Some(EmailLanguage::Arabic));
        assert_eq!(EmailLanguage::from_code("invalid"), None);
    }

    #[test]
    fn test_rtl_detection() {
        assert!(!EmailLanguage::English.is_rtl());
        assert!(EmailLanguage::Arabic.is_rtl());
        assert_eq!(EmailLanguage::Arabic.direction(), "rtl");
        assert_eq!(EmailLanguage::English.direction(), "ltr");
    }

    #[test]
    fn test_verification_email_subject() {
        let email = I18nVerificationEmail {
            name: "Test".to_string(),
            verification_url: "https://example.com".to_string(),
            expires_in_hours: 24,
        };

        assert_eq!(email.subject(EmailLanguage::English), "Verify your email address");
        assert_eq!(email.subject(EmailLanguage::Spanish), "Verifica tu dirección de correo");
        assert_eq!(email.subject(EmailLanguage::Arabic), "تحقق من عنوان بريدك الإلكتروني");
    }
}

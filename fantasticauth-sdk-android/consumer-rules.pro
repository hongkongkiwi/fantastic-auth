# Consumer ProGuard rules for Vault SDK
# These are automatically included when consumers use the library

# Keep all public API classes and methods
-keep public class dev.vault.sdk.Vault {
    public static void configure(android.content.Context, java.lang.String, java.lang.String);
    public static void configure(android.content.Context, java.lang.String, java.lang.String, long, boolean);
    public static void reset();
    public static boolean isInitialized();
    public static dev.vault.sdk.VaultConfig getConfig();
    public static android.content.Context getContext();
    public static java.lang.String getVERSION();
    public static dev.vault.sdk.auth.VaultAuth auth();
    public static dev.vault.sdk.session.VaultSession session();
    public static dev.vault.sdk.biometric.VaultBiometric biometric(android.content.Context);
    public static dev.vault.sdk.organizations.VaultOrganizations organizations();
}

# Keep exceptions
-keep public class dev.vault.sdk.network.VaultException {
    public java.lang.String getCode();
    public java.lang.Integer getStatusCode();
    public boolean isAuthError();
    public boolean isNetworkError();
    public boolean isRateLimitError();
    public boolean isNotFoundError();
    public boolean isValidationError();
    public java.lang.String toUserMessage();
}

# Keep data models used by consumers
-keep public class dev.vault.sdk.user.User {
    public *;
}

-keep public class dev.vault.sdk.user.Profile {
    public *;
}

-keep public class dev.vault.sdk.session.VaultSession$SessionData {
    public *;
}

-keep public class dev.vault.sdk.organizations.Organization {
    public *;
}

-keep public class dev.vault.sdk.organizations.OrganizationMember {
    public *;
}

-keep public class dev.vault.sdk.organizations.Invitation {
    public *;
}

-keep public class dev.vault.sdk.organizations.OrganizationRole {
    public *;
}

-keep public class dev.vault.sdk.organizations.InvitationStatus {
    public *;
}

-keep public class dev.vault.sdk.biometric.BiometricResult {
    public *;
}

-keep public class dev.vault.sdk.biometric.BiometricStatus {
    public *;
}

-keep public class dev.vault.sdk.biometric.BiometricException {
    public *;
}

-keep public class dev.vault.sdk.auth.OAuthProvider {
    public *;
}

-keep public class dev.vault.sdk.auth.OAuthCallbackResult {
    public *;
}

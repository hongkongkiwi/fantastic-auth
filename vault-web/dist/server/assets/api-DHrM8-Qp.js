import { c as createServerRpc } from "./createServerRpc-Bd3B-Ah9.js";
import { c as createSession, g as getSessionCookieName, a as getSessionTtlSeconds, e as env } from "./server-DL57AnWM.js";
import { c as createServerFn } from "../server.js";
import "@t3-oss/env-core";
import "zod";
import "@tanstack/history";
import "@tanstack/router-core/ssr/client";
import "@tanstack/router-core";
import "node:async_hooks";
import "@tanstack/router-core/ssr/server";
import "h3-v2";
import "tiny-invariant";
import "seroval";
import "react/jsx-runtime";
import "@tanstack/react-router/ssr/server";
import "@tanstack/react-router";
const DEFAULT_BASE_URL = "http://localhost:8080/api/v1";
const getBaseUrl = () => env.INTERNAL_API_BASE_URL || DEFAULT_BASE_URL;
const getHostedConfig_createServerFn_handler = createServerRpc({
  id: "b92e70e16f392b15ad8c13d909d159d9277a8cea40153a7d152372a6e6cb34ef",
  name: "getHostedConfig",
  filename: "src/hosted/api.ts"
}, (opts) => getHostedConfig.__executeServer(opts));
const getHostedConfig = createServerFn({
  method: "GET"
}).inputValidator((input) => input).handler(getHostedConfig_createServerFn_handler, async ({
  data
}) => {
  const baseUrl = getBaseUrl();
  const response = await fetch(`${baseUrl}/hosted/config?tenant_id=${data.tenantId}`);
  if (response.ok) {
    return response.json();
  }
  return {
    tenantId: data.tenantId,
    companyName: "Vault",
    signInTitle: "Sign in to your account",
    signUpTitle: "Create your account",
    oauthProviders: ["google", "github"],
    showMagicLink: true,
    showWebAuthn: true,
    requireEmailVerification: true,
    allowSignUp: true,
    afterSignInUrl: "/dashboard",
    afterSignUpUrl: "/welcome",
    afterSignOutUrl: "/hosted/sign-in",
    allowedRedirectUrls: ["http://localhost:3000", "http://localhost:8080"],
    termsUrl: "/terms",
    privacyUrl: "/privacy"
  };
});
const hostedSignIn_createServerFn_handler = createServerRpc({
  id: "4c4c6efb431cb3e467a6afa9464ba1af0373f18bc7d8f2ade3f6c4ca87cf460a",
  name: "hostedSignIn",
  filename: "src/hosted/api.ts"
}, (opts) => hostedSignIn.__executeServer(opts));
const hostedSignIn = createServerFn({
  method: "POST"
}).inputValidator((input) => input).handler(hostedSignIn_createServerFn_handler, async ({
  data
}) => {
  const baseUrl = getBaseUrl();
  const response = await fetch(`${baseUrl}/auth/signin`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      email: data.email,
      password: data.password,
      tenant_id: data.tenantId
    })
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({
      message: "Sign in failed"
    }));
    throw new Error(error.message || "Invalid credentials");
  }
  const result = await response.json();
  const session = createSession();
  [`${getSessionCookieName()}_hosted=${encodeURIComponent(session.token)}`, `Max-Age=${getSessionTtlSeconds()}`, "Path=/", "SameSite=Lax", "HttpOnly"];
  return {
    sessionToken: session.token,
    user: result.user,
    redirectUrl: data.redirectUrl || "/dashboard",
    requiresMfa: result.requiresMfa,
    mfaToken: result.mfaToken
  };
});
const hostedSignUp_createServerFn_handler = createServerRpc({
  id: "b5af2b0f5b3bfef7350538f597333f57e07504f99fcbe1b508ce57d168cbea67",
  name: "hostedSignUp",
  filename: "src/hosted/api.ts"
}, (opts) => hostedSignUp.__executeServer(opts));
const hostedSignUp = createServerFn({
  method: "POST"
}).inputValidator((input) => input).handler(hostedSignUp_createServerFn_handler, async ({
  data
}) => {
  const baseUrl = getBaseUrl();
  const response = await fetch(`${baseUrl}/auth/signup`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      email: data.email,
      password: data.password,
      name: data.name,
      tenant_id: data.tenantId
    })
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({
      message: "Sign up failed"
    }));
    throw new Error(error.message || "Could not create account");
  }
  const result = await response.json();
  return {
    sessionToken: result.sessionToken || "",
    user: result.user,
    redirectUrl: data.redirectUrl || "/welcome"
  };
});
const hostedOAuthStart_createServerFn_handler = createServerRpc({
  id: "622b84adf3123c35c2afd21c2c10615a5d4b9aa6a92ce81bccb916f5063294fb",
  name: "hostedOAuthStart",
  filename: "src/hosted/api.ts"
}, (opts) => hostedOAuthStart.__executeServer(opts));
const hostedOAuthStart = createServerFn({
  method: "POST"
}).inputValidator((input) => input).handler(hostedOAuthStart_createServerFn_handler, async ({
  data
}) => {
  const baseUrl = getBaseUrl();
  const response = await fetch(`${baseUrl}/auth/oauth/${data.provider}/start`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      tenant_id: data.tenantId,
      redirect_uri: `${baseUrl}/hosted/oauth-callback`,
      state: data.state
    })
  });
  if (!response.ok) {
    throw new Error("Failed to start OAuth flow");
  }
  return response.json();
});
const hostedOAuthCallback_createServerFn_handler = createServerRpc({
  id: "d4155fbcbe598960305caaa0460634889bef4ebf55939027f3c8729a9d0d4a74",
  name: "hostedOAuthCallback",
  filename: "src/hosted/api.ts"
}, (opts) => hostedOAuthCallback.__executeServer(opts));
const hostedOAuthCallback = createServerFn({
  method: "POST"
}).inputValidator((input) => input).handler(hostedOAuthCallback_createServerFn_handler, async ({
  data
}) => {
  const baseUrl = getBaseUrl();
  const response = await fetch(`${baseUrl}/auth/oauth/callback`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      code: data.code,
      state: data.state,
      tenant_id: data.tenantId
    })
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({
      message: "OAuth failed"
    }));
    throw new Error(error.message || "OAuth authentication failed");
  }
  const result = await response.json();
  return {
    sessionToken: result.sessionToken,
    user: result.user,
    redirectUrl: data.redirectUrl || "/dashboard"
  };
});
const hostedSendMagicLink_createServerFn_handler = createServerRpc({
  id: "188843d40400af4d3cb0176f40ac9e09380c3c2ff8b3b2a63e04559317674d7c",
  name: "hostedSendMagicLink",
  filename: "src/hosted/api.ts"
}, (opts) => hostedSendMagicLink.__executeServer(opts));
const hostedSendMagicLink = createServerFn({
  method: "POST"
}).inputValidator((input) => input).handler(hostedSendMagicLink_createServerFn_handler, async ({
  data
}) => {
  const baseUrl = getBaseUrl();
  const response = await fetch(`${baseUrl}/auth/magic-link`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      email: data.email,
      tenant_id: data.tenantId,
      redirect_url: data.redirectUrl
    })
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({
      message: "Failed to send magic link"
    }));
    throw new Error(error.message);
  }
  return {
    success: true
  };
});
const hostedRequestPasswordReset_createServerFn_handler = createServerRpc({
  id: "1ca42db0c2d7c66f24cfff9cb30ebd7016860272f0cdd353442eeca73c52638f",
  name: "hostedRequestPasswordReset",
  filename: "src/hosted/api.ts"
}, (opts) => hostedRequestPasswordReset.__executeServer(opts));
const hostedRequestPasswordReset = createServerFn({
  method: "POST"
}).inputValidator((input) => input).handler(hostedRequestPasswordReset_createServerFn_handler, async ({
  data
}) => {
  const baseUrl = getBaseUrl();
  const response = await fetch(`${baseUrl}/auth/password-reset-request`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      email: data.email,
      tenant_id: data.tenantId
    })
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({
      message: "Failed to send reset email"
    }));
    throw new Error(error.message);
  }
  return {
    success: true
  };
});
const hostedVerifyEmail_createServerFn_handler = createServerRpc({
  id: "bd9cff8d3b9ce4f4e6e3cfb824b074e8b83564e739d2a433cd2f837974ae3e65",
  name: "hostedVerifyEmail",
  filename: "src/hosted/api.ts"
}, (opts) => hostedVerifyEmail.__executeServer(opts));
const hostedVerifyEmail = createServerFn({
  method: "POST"
}).inputValidator((input) => input).handler(hostedVerifyEmail_createServerFn_handler, async ({
  data
}) => {
  const baseUrl = getBaseUrl();
  const response = await fetch(`${baseUrl}/auth/verify-email`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      token: data.token,
      tenant_id: data.tenantId
    })
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({
      message: "Invalid or expired token"
    }));
    throw new Error(error.message);
  }
  return {
    success: true,
    redirectUrl: "/hosted/sign-in"
  };
});
const hostedVerifyMfa_createServerFn_handler = createServerRpc({
  id: "eba5296fd712cc1e557da6d47dae2405baaa57df15aaf6c6a8d1953200ec95ca",
  name: "hostedVerifyMfa",
  filename: "src/hosted/api.ts"
}, (opts) => hostedVerifyMfa.__executeServer(opts));
const hostedVerifyMfa = createServerFn({
  method: "POST"
}).inputValidator((input) => input).handler(hostedVerifyMfa_createServerFn_handler, async ({
  data
}) => {
  const baseUrl = getBaseUrl();
  const response = await fetch(`${baseUrl}/auth/mfa/verify`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      code: data.code,
      method: data.method,
      mfa_token: data.mfaToken,
      tenant_id: data.tenantId
    })
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({
      message: "Invalid MFA code"
    }));
    throw new Error(error.message);
  }
  const result = await response.json();
  return {
    sessionToken: result.sessionToken,
    user: result.user,
    redirectUrl: data.redirectUrl || "/dashboard"
  };
});
const hostedListOrganizations_createServerFn_handler = createServerRpc({
  id: "e88a814d5a618e7e6649b95cd90ac8cada5115df1d3fdefefd210a9fc9369e17",
  name: "hostedListOrganizations",
  filename: "src/hosted/api.ts"
}, (opts) => hostedListOrganizations.__executeServer(opts));
const hostedListOrganizations = createServerFn({
  method: "GET"
}).inputValidator((input) => input).handler(hostedListOrganizations_createServerFn_handler, async ({
  data
}) => {
  const baseUrl = getBaseUrl();
  const response = await fetch(`${baseUrl}/organizations`, {
    headers: {
      "Authorization": `Bearer ${data.sessionToken}`,
      "X-Tenant-ID": data.tenantId
    }
  });
  if (!response.ok) {
    throw new Error("Failed to fetch organizations");
  }
  return response.json();
});
const hostedSwitchOrganization_createServerFn_handler = createServerRpc({
  id: "00caa7e83ac2160de123c0d3a6fc13e26979131b0e5342bfa9e5f1f9ee4edd43",
  name: "hostedSwitchOrganization",
  filename: "src/hosted/api.ts"
}, (opts) => hostedSwitchOrganization.__executeServer(opts));
const hostedSwitchOrganization = createServerFn({
  method: "POST"
}).inputValidator((input) => input).handler(hostedSwitchOrganization_createServerFn_handler, async ({
  data
}) => {
  const baseUrl = getBaseUrl();
  const response = await fetch(`${baseUrl}/organizations/switch`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${data.sessionToken}`,
      "X-Tenant-ID": data.tenantId
    },
    body: JSON.stringify({
      organization_id: data.organizationId
    })
  });
  if (!response.ok) {
    throw new Error("Failed to switch organization");
  }
  return {
    success: true,
    redirectUrl: "/dashboard"
  };
});
const hostedCreateOrganization_createServerFn_handler = createServerRpc({
  id: "74b76322f432f923b54acfb6d8cdc556b05cbc5adeb8065dff2a0bf954828322",
  name: "hostedCreateOrganization",
  filename: "src/hosted/api.ts"
}, (opts) => hostedCreateOrganization.__executeServer(opts));
const hostedCreateOrganization = createServerFn({
  method: "POST"
}).inputValidator((input) => input).handler(hostedCreateOrganization_createServerFn_handler, async ({
  data
}) => {
  const baseUrl = getBaseUrl();
  const response = await fetch(`${baseUrl}/organizations`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${data.sessionToken}`,
      "X-Tenant-ID": data.tenantId
    },
    body: JSON.stringify({
      name: data.name,
      slug: data.slug
    })
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({
      message: "Failed to create organization"
    }));
    throw new Error(error.message);
  }
  return response.json();
});
const hostedWebAuthnChallenge_createServerFn_handler = createServerRpc({
  id: "bffb1b1898bf60e6171ff14d1b3a016bba0489e0e74026e9ac02d0bf7c7f45ad",
  name: "hostedWebAuthnChallenge",
  filename: "src/hosted/api.ts"
}, (opts) => hostedWebAuthnChallenge.__executeServer(opts));
const hostedWebAuthnChallenge = createServerFn({
  method: "POST"
}).inputValidator((input) => input).handler(hostedWebAuthnChallenge_createServerFn_handler, async ({
  data
}) => {
  const baseUrl = getBaseUrl();
  const response = await fetch(`${baseUrl}/auth/webauthn/challenge`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      tenant_id: data.tenantId
    })
  });
  if (!response.ok) {
    throw new Error("Failed to generate WebAuthn challenge");
  }
  return response.json();
});
export {
  getHostedConfig_createServerFn_handler,
  hostedCreateOrganization_createServerFn_handler,
  hostedListOrganizations_createServerFn_handler,
  hostedOAuthCallback_createServerFn_handler,
  hostedOAuthStart_createServerFn_handler,
  hostedRequestPasswordReset_createServerFn_handler,
  hostedSendMagicLink_createServerFn_handler,
  hostedSignIn_createServerFn_handler,
  hostedSignUp_createServerFn_handler,
  hostedSwitchOrganization_createServerFn_handler,
  hostedVerifyEmail_createServerFn_handler,
  hostedVerifyMfa_createServerFn_handler,
  hostedWebAuthnChallenge_createServerFn_handler
};

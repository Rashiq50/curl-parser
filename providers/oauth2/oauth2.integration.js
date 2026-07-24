// Generic OAuth2 integration — OUTDATED fixture
// Uses the Implicit grant (response_type=token), deprecated by OAuth 2.1.
// Recommended replacement: Authorization Code flow with PKCE.

const AUTH_BASE = "https://provider.example.com";

// DEPRECATED: implicit flow returns the access token in the URL fragment.
export function buildAuthorizeUrl(state) {
  const params = new URLSearchParams({
    client_id: process.env.OAUTH_CLIENT_ID,
    redirect_uri: "https://app.example.com/callback",
    response_type: "token", // implicit grant — insecure, no refresh tokens
    scope: "profile email",
    state,
  });
  return `${AUTH_BASE}/authorize?${params.toString()}`;
}

// DEPRECATED: client secret shipped alongside implicit flow.
export async function exchangeSecret(code) {
  const res = await fetch(`${AUTH_BASE}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: process.env.OAUTH_CLIENT_ID,
      client_secret: process.env.OAUTH_CLIENT_SECRET, // no PKCE
    }),
  });
  return res.json();
}

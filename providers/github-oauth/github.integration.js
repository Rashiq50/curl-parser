// GitHub OAuth integration — CURRENT fixture
// Standard Authorization Code flow with server-side token exchange and CSRF state.

const AUTHORIZE_URL = "https://github.com/login/oauth/authorize";
const TOKEN_URL = "https://github.com/login/oauth/access_token";

export function buildAuthorizeUrl(state) {
  const params = new URLSearchParams({
    client_id: process.env.GITHUB_CLIENT_ID,
    redirect_uri: "https://app.example.com/auth/github/callback",
    response_type: "code", // authorization code flow
    scope: "read:user user:email",
    state, // CSRF protection
  });
  return `${AUTHORIZE_URL}?${params.toString()}`;
}

// Secret exchange happens server-side only.
export async function exchangeCode(code) {
  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: process.env.GITHUB_CLIENT_ID,
      client_secret: process.env.GITHUB_CLIENT_SECRET,
      code,
    }),
  });
  return res.json();
}

// Auth0 integration — OUTDATED fixture
// Pinned to auth0@2.42.0 (EOL). Uses the old callback-style ManagementClient.

import { ManagementClient, AuthenticationClient } from "auth0";

// DEPRECATED: v2 constructor signature + callback API.
const management = new ManagementClient({
  domain: process.env.AUTH0_DOMAIN,
  clientId: process.env.AUTH0_CLIENT_ID,
  clientSecret: process.env.AUTH0_CLIENT_SECRET,
  scope: "read:users update:users",
});

const auth = new AuthenticationClient({
  domain: process.env.AUTH0_DOMAIN,
  clientId: process.env.AUTH0_CLIENT_ID,
});

// v2 callback style — removed in v4 (now returns promises).
export function getUser(userId, cb) {
  management.getUser({ id: userId }, cb);
}

export function passwordGrant(username, password, cb) {
  auth.passwordGrant(
    { username, password, realm: "Username-Password-Authentication" },
    cb
  );
}

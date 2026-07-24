// Twilio integration — OUTDATED fixture
// Pinned to twilio@3.84.1 (EOL major). API version 2010-04-01 is current/stable.

import twilio from "twilio";

const client = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

// Works, but SDK v3 is unsupported. v5 is the current major.
export async function sendSms(to, body) {
  return client.messages.create({
    to,
    from: "+15005550006",
    body,
  });
}

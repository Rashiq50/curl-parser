// SendGrid integration — CURRENT fixture
// Latest @sendgrid/mail@8.1.3 against the current v3 Mail Send API.

import sgMail from "@sendgrid/mail";

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

export async function sendEmail(to, subject, html) {
  return sgMail.send({
    to,
    from: "no-reply@example.com",
    subject,
    html,
  });
}

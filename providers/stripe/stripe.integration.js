// Stripe integration
// Pinned to stripe@8.222.0 — SDK major upgrade tracked separately.
// API version bumped to 2025-06-30; Charges API replaced with PaymentIntents.

import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
  apiVersion: "2025-06-30",
});

// SCA-compliant payment flow using the PaymentIntents API.
// `paymentMethodId` is a `pm_…` ID created on the client with Stripe.js /
// the mobile SDKs — never a raw card token.
export async function chargeCard(paymentMethodId, amountCents) {
  return stripe.paymentIntents.create({
    amount: amountCents,
    currency: "usd",
    payment_method: paymentMethodId,
    confirm: true,
    description: "Payment",
    automatic_payment_methods: {
      enabled: true,
      allow_redirects: "never",
    },
  });
}

export async function createCustomer(email, paymentMethodId) {
  return stripe.customers.create({
    email,
    payment_method: paymentMethodId,
  });
}

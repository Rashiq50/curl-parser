// Stripe integration — OUTDATED fixture
// Pinned to stripe@8.222.0 and API version 2020-08-27.
// Uses the legacy Charges API (deprecated in favor of PaymentIntents).

import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
  apiVersion: "2020-08-27", // stale: latest is 2025-06-30
});

// DEPRECATED PATTERN: direct charge creation.
// Modern Stripe requires PaymentIntents to support SCA / 3D Secure.
export async function chargeCard(token, amountCents) {
  return stripe.charges.create({
    amount: amountCents,
    currency: "usd",
    source: token, // deprecated: raw card tokens
    description: "Legacy charge",
  });
}

export async function createCustomer(email, token) {
  return stripe.customers.create({
    email,
    source: token,
  });
}

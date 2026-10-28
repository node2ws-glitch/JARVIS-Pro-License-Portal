# JARVIS Pro License Portal

A static GitHub Pages site for checking Pro keys and an authenticated Supabase Edge Function for issuing them. The browser contains only a Supabase **publishable** key. The service-role key stays in Supabase Edge Functions.

## Contents

- `index.html` — license checker + allowlisted admin sign-in / issuance panel.
- `supabase/functions/verify-paid-license/` — hashes and checks a license; optional device activation.
- `supabase/functions/issue-paid-license/` — creates a random key only for a confirmed, allowlisted admin; stores the digest, returns the raw key once.
- `supabase/schema.sql` — licensing tables and verification RPC for a new Supabase project.
- `.github/workflows/pages.yml` — deploys the site from the `main` branch to GitHub Pages.

## 1. Put this repository on GitHub

Create a repository and upload these files to its root. In **Settings → Pages**, choose **GitHub Actions**. The included workflow publishes `index.html` after you push to `main`.

## 2. Configure Supabase

This source is preconfigured for project `wjfjyqbizqzwiivggzah` (`AG JARVIS PAID`). In `index.html`, the Supabase URL, publishable key, and admin email are public client-side configuration. A publishable key is expected to be visible in a website; never put a service-role key or database password there.

For the existing JARVIS Pro project, the licensing schema and admin allowlist are already provisioned. If you deploy to a new project, run `supabase/schema.sql` in its SQL Editor first, update the project URL/key/admin email in `index.html`, then set up the backend below.

Install Supabase CLI, sign in, and from this repository run:

```sh
supabase link --project-ref wjfjyqbizqzwiivggzah
supabase secrets set LICENSE_ADMIN_EMAILS=aryanghorpade001@gmail.com
supabase functions deploy verify-paid-license --no-verify-jwt
supabase functions deploy issue-paid-license
```

Supabase provides `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` to deployed functions. Do **not** add those values to GitHub, `index.html`, or desktop code. Keep the allowlist secret server-side.

In **Supabase → Authentication → URL Configuration**, add the actual GitHub Pages URL to the redirect allow-list. For a repository named `jarvis-pro-portal`, it will look like:

```text
https://YOUR-GITHUB-USERNAME.github.io/jarvis-pro-portal/**
```

The admin panel uses a one-time email sign-in link—there is no website password. Email authentication and sign-up must be enabled for the first admin sign-in. Configure custom SMTP before relying on email delivery in production.

## 3. Use the website

1. Open the published GitHub Pages URL.
2. Expand **License Admin** and send the sign-in link to the allowlisted admin inbox.
3. Open the link in the same browser, return to the portal, choose expiry and device limit, and create a key.
4. Copy and deliver the raw key privately. It is displayed once; only its SHA-256 digest is stored.
5. Customers can use the public validator to check a key. A web check does not consume a device activation; the desktop app activates the device separately.

## Security notes

- Key creation is checked server-side against `LICENSE_ADMIN_EMAILS` and a confirmed Supabase Auth user.
- Raw license keys are never stored in the database.
- The site does not process payments or host the Windows installer.
- Invalid/revoked desktop licenses lock Pro features; they do not silently uninstall the app or delete user data.
- Review Edge Function and RLS settings before changing projects or deploying changes.

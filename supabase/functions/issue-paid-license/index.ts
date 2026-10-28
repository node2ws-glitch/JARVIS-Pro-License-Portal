const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Content-Type': 'application/json',
};

const json = (body: Record<string, unknown>, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: corsHeaders });

function createLicenseKey() {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  const suffix = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('').toUpperCase();
  return `JARVIS-PRO-${suffix}`;
}

async function sha256(value: string) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

Deno.serve(async (request: Request) => {
  if (request.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  if (request.method !== 'POST') return json({ error: 'Method not allowed.' }, 405);

  const supabaseUrl = Deno.env.get('SUPABASE_URL');
  const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
  const allowedAdmins = (Deno.env.get('LICENSE_ADMIN_EMAILS') || '')
    .split(',').map((email) => email.trim().toLowerCase()).filter(Boolean);
  if (!supabaseUrl || !serviceRoleKey || allowedAdmins.length === 0) {
    return json({ error: 'License issuance is not configured.' }, 503);
  }

  const authorization = request.headers.get('authorization') || '';
  const token = authorization.match(/^Bearer\s+(.+)$/i)?.[1];
  if (!token) return json({ error: 'Sign in with the authorized license-admin email first.' }, 401);

  let user: { email?: string; email_confirmed_at?: string | null };
  try {
    const userResponse = await fetch(`${supabaseUrl}/auth/v1/user`, {
      headers: { apikey: serviceRoleKey, Authorization: `Bearer ${token}` },
    });
    if (!userResponse.ok) return json({ error: 'Admin session is invalid or expired. Sign in again.' }, 401);
    user = await userResponse.json();
  } catch {
    return json({ error: 'Could not verify the admin session.' }, 503);
  }

  const adminEmail = String(user.email || '').trim().toLowerCase();
  if (!adminEmail || !allowedAdmins.includes(adminEmail) || !user.email_confirmed_at) {
    return json({ error: 'This confirmed email is not authorized to issue licenses.' }, 403);
  }

  let body: { customer_email?: unknown; expires_in_days?: unknown; max_devices?: unknown };
  try { body = await request.json(); } catch { return json({ error: 'Invalid JSON request.' }, 400); }

  const customerEmail = String(body.customer_email || '').trim().toLowerCase();
  if (customerEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(customerEmail)) {
    return json({ error: 'Enter a valid customer email, or leave it blank.' }, 400);
  }

  const expiresInDays = Number(body.expires_in_days ?? 365);
  const maxDevices = Number(body.max_devices ?? 3);
  if (!Number.isInteger(expiresInDays) || expiresInDays < 0 || expiresInDays > 3650) {
    return json({ error: 'Expiry must be 0 (no expiry) or between 1 and 3650 days.' }, 400);
  }
  if (!Number.isInteger(maxDevices) || maxDevices < 1 || maxDevices > 10) {
    return json({ error: 'Device limit must be between 1 and 10.' }, 400);
  }

  const licenseKey = createLicenseKey();
  const licenseHash = await sha256(licenseKey);
  const expiresAt = expiresInDays === 0 ? null : new Date(Date.now() + expiresInDays * 86400000).toISOString();
  const licenseRow = {
    license_key_hash: licenseHash,
    email: customerEmail || null,
    tier: 'PRO',
    status: 'active',
    max_devices: maxDevices,
    expires_at: expiresAt,
    features: {
      automations: true,
      webhooks: true,
      connectors: false,
      encrypted_vault: true,
      network_radar: true,
    },
  };

  try {
    const insertResponse = await fetch(`${supabaseUrl}/rest/v1/paid_licenses`, {
      method: 'POST',
      headers: {
        apikey: serviceRoleKey,
        Authorization: `Bearer ${serviceRoleKey}`,
        'Content-Type': 'application/json',
        Prefer: 'return=representation',
      },
      body: JSON.stringify(licenseRow),
    });
    if (!insertResponse.ok) {
      // Do not log or return the raw key or database credentials.
      const details = await insertResponse.text();
      console.error('License insert rejected:', insertResponse.status, details.slice(0, 400));
      return json({ error: 'The license could not be saved. Check the database and retry.' }, 500);
    }
    const [saved] = await insertResponse.json();
    return json({
      issued: true,
      license_key: licenseKey,
      customer_email: customerEmail || null,
      license_id: saved?.id,
      expires_at: expiresAt,
      max_devices: maxDevices,
      features: licenseRow.features,
      message: 'Copy this key now. The database stores only its SHA-256 digest; it cannot be shown again.',
    }, 201);
  } catch {
    return json({ error: 'The license service could not save the new key.' }, 503);
  }
});

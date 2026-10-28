const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

Deno.serve(async (request: Request) => {
  if (request.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  if (request.method !== 'POST') return Response.json({ valid: false, code: 'method_not_allowed', message: 'Use POST.' }, { status: 405, headers: corsHeaders });

  try {
    const { license_key, device_id, activate = false } = await request.json();
    const key = String(license_key || '').trim().toUpperCase();
    const device = String(device_id || '').trim();
    if (key.length < 12 || key.length > 128 || (activate && (device.length < 8 || device.length > 200))) {
      return Response.json({ valid: false, code: 'bad_request', message: 'Enter a valid license key and device identifier.' }, { status: 200, headers: corsHeaders });
    }

    const supabaseUrl = Deno.env.get('SUPABASE_URL');
    const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
    if (!supabaseUrl || !serviceKey) throw new Error('License service is not configured.');

    const keyHash = await sha256(key);
    const deviceHash = activate ? await sha256(device) : null;
    const rpcResponse = await fetch(`${supabaseUrl}/rest/v1/rpc/verify_paid_license`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', apikey: serviceKey, Authorization: `Bearer ${serviceKey}` },
      body: JSON.stringify({ p_key_hash: keyHash, p_device_hash: deviceHash }),
    });
    if (!rpcResponse.ok) {
      const detail = await rpcResponse.text();
      console.error('license RPC returned', rpcResponse.status, detail);
      throw new Error('License database request failed.');
    }
    const data = await rpcResponse.json();
    return Response.json({ ...data, activated: Boolean(activate && data?.valid) }, { status: 200, headers: corsHeaders });
  } catch (error) {
    console.error('verify-paid-license failed:', error?.message || error);
    return Response.json({ valid: false, code: 'service_error', message: 'License verification is temporarily unavailable. Try again shortly.' }, { status: 200, headers: corsHeaders });
  }
});

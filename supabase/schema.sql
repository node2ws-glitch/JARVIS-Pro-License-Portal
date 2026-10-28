-- JARVIS Pro licensing schema.
-- Run once in a new Supabase project. Existing AG JARVIS PAID already has these objects.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS public.paid_licenses (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  license_key_hash text NOT NULL UNIQUE CHECK (license_key_hash ~ '^[0-9a-f]{64}$'),
  email text,
  tier text NOT NULL DEFAULT 'PRO',
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired')),
  max_devices smallint NOT NULL DEFAULT 2 CHECK (max_devices BETWEEN 1 AND 10),
  features jsonb NOT NULL DEFAULT '{"webhooks":true,"connectors":false,"automations":true}'::jsonb,
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_verified_at timestamptz
);

CREATE TABLE IF NOT EXISTS public.paid_license_devices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  license_id uuid NOT NULL REFERENCES public.paid_licenses(id) ON DELETE CASCADE,
  device_hash text NOT NULL CHECK (device_hash ~ '^[0-9a-f]{64}$'),
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (license_id, device_hash)
);

ALTER TABLE public.paid_licenses ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.paid_license_devices ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.paid_licenses, public.paid_license_devices FROM anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.paid_licenses, public.paid_license_devices TO service_role;

CREATE OR REPLACE FUNCTION public.verify_paid_license(p_key_hash text, p_device_hash text DEFAULT NULL)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'pg_catalog', 'public'
AS $function$
DECLARE
  license_row public.paid_licenses%ROWTYPE;
  device_count integer;
BEGIN
  IF p_key_hash IS NULL OR p_key_hash !~ '^[0-9a-f]{64}$' THEN
    RETURN jsonb_build_object('valid', false, 'code', 'bad_request', 'message', 'Invalid license request.');
  END IF;
  IF p_device_hash IS NOT NULL AND p_device_hash !~ '^[0-9a-f]{64}$' THEN
    RETURN jsonb_build_object('valid', false, 'code', 'bad_request', 'message', 'Invalid device identifier.');
  END IF;

  SELECT * INTO license_row FROM public.paid_licenses WHERE license_key_hash = p_key_hash FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('valid', false, 'code', 'invalid_key', 'message', 'License key was not recognized.');
  END IF;
  IF license_row.status <> 'active' THEN
    RETURN jsonb_build_object('valid', false, 'code', 'revoked', 'message', 'This license is not active.');
  END IF;
  IF license_row.expires_at IS NOT NULL AND license_row.expires_at <= now() THEN
    RETURN jsonb_build_object('valid', false, 'code', 'expired', 'message', 'This license has expired.');
  END IF;

  IF p_device_hash IS NOT NULL THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.paid_license_devices d
      WHERE d.license_id = license_row.id AND d.device_hash = p_device_hash
    ) THEN
      SELECT count(*) INTO device_count FROM public.paid_license_devices d WHERE d.license_id = license_row.id;
      IF device_count >= license_row.max_devices THEN
        RETURN jsonb_build_object('valid', false, 'code', 'device_limit', 'message', 'This license has reached its device limit.');
      END IF;
      INSERT INTO public.paid_license_devices(license_id, device_hash) VALUES (license_row.id, p_device_hash);
    ELSE
      UPDATE public.paid_license_devices SET last_seen_at = now()
      WHERE license_id = license_row.id AND device_hash = p_device_hash;
    END IF;
  END IF;

  UPDATE public.paid_licenses SET last_verified_at = now() WHERE id = license_row.id;
  RETURN jsonb_build_object(
    'valid', true,
    'license_id', license_row.id,
    'tier', license_row.tier,
    'expires_at', license_row.expires_at,
    'features', license_row.features
  );
END;
$function$;

REVOKE ALL ON FUNCTION public.verify_paid_license(text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.verify_paid_license(text, text) TO service_role;

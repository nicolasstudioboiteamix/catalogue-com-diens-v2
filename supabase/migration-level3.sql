-- ════════════════════════════════════════════════════════════════
-- MIGRATION NIVEAU 3 — Sécurité complète
-- À exécuter UNE SEULE FOIS dans Supabase Dashboard > SQL Editor
--
-- Ce que fait cette migration :
--   1. Crée la table app_sessions (tokens de session)
--   2. Verrouille complètement l'accès anon sur toutes les tables
--      (seule l'Edge Function avec service_role peut lire/écrire)
--   3. Nettoie les anciennes politiques permissives
-- ════════════════════════════════════════════════════════════════


-- ────────────────────────────────────────────────────────────────
-- 1. TABLE DES SESSIONS
-- ────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS app_sessions (
    token       text        PRIMARY KEY,
    user_id     bigint      NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
    username    text        NOT NULL,
    role        text        NOT NULL,
    comedian_id bigint,
    created_at  timestamptz DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    last_seen   timestamptz DEFAULT now()
);

-- Index pour les requêtes de validation rapide
CREATE INDEX IF NOT EXISTS idx_app_sessions_token     ON app_sessions(token);
CREATE INDEX IF NOT EXISTS idx_app_sessions_expires   ON app_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_app_sessions_user_id   ON app_sessions(user_id);

-- RLS sur app_sessions — accessible UNIQUEMENT par service_role (Edge Function)
ALTER TABLE app_sessions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "sessions_deny_all"    ON app_sessions;
DROP POLICY IF EXISTS "sessions_service_all" ON app_sessions;

CREATE POLICY "sessions_deny_all"    ON app_sessions FOR ALL TO anon    USING (false);
CREATE POLICY "sessions_service_all" ON app_sessions FOR ALL TO service_role USING (true) WITH CHECK (true);


-- ────────────────────────────────────────────────────────────────
-- 2. VERROUILLAGE COMPLET — TOUTES LES TABLES
--    Supprimer TOUTES les politiques existantes puis n'autoriser
--    QUE le service_role. La clé anon n'a plus aucun accès.
-- ────────────────────────────────────────────────────────────────

-- ── app_users ────────────────────────────────────────────────────
DROP POLICY IF EXISTS "full_access"         ON app_users;
DROP POLICY IF EXISTS "users_anon_select"   ON app_users;
DROP POLICY IF EXISTS "users_anon_insert"   ON app_users;
DROP POLICY IF EXISTS "users_anon_update"   ON app_users;
DROP POLICY IF EXISTS "users_anon_delete"   ON app_users;
DROP POLICY IF EXISTS "users_service_all"   ON app_users;

ALTER TABLE app_users ENABLE ROW LEVEL SECURITY;
CREATE POLICY "deny_anon"    ON app_users FOR ALL TO anon         USING (false);
CREATE POLICY "service_all"  ON app_users FOR ALL TO service_role USING (true) WITH CHECK (true);


-- ── comedians ────────────────────────────────────────────────────
DROP POLICY IF EXISTS "full_access"            ON comedians;
DROP POLICY IF EXISTS "comedians_public_read"  ON comedians;
DROP POLICY IF EXISTS "comedians_secret_write" ON comedians;

ALTER TABLE comedians ENABLE ROW LEVEL SECURITY;
CREATE POLICY "deny_anon"    ON comedians FOR ALL TO anon         USING (false);
CREATE POLICY "service_all"  ON comedians FOR ALL TO service_role USING (true) WITH CHECK (true);


-- ── absences ─────────────────────────────────────────────────────
DROP POLICY IF EXISTS "full_access"           ON absences;
DROP POLICY IF EXISTS "absences_public_read"  ON absences;
DROP POLICY IF EXISTS "absences_secret_write" ON absences;

ALTER TABLE absences ENABLE ROW LEVEL SECURITY;
CREATE POLICY "deny_anon"    ON absences FOR ALL TO anon         USING (false);
CREATE POLICY "service_all"  ON absences FOR ALL TO service_role USING (true) WITH CHECK (true);


-- ── email_templates ──────────────────────────────────────────────
DROP POLICY IF EXISTS "full_access"             ON email_templates;
DROP POLICY IF EXISTS "templates_public_read"   ON email_templates;
DROP POLICY IF EXISTS "templates_secret_write"  ON email_templates;

ALTER TABLE email_templates ENABLE ROW LEVEL SECURITY;
CREATE POLICY "deny_anon"    ON email_templates FOR ALL TO anon         USING (false);
CREATE POLICY "service_all"  ON email_templates FOR ALL TO service_role USING (true) WITH CHECK (true);


-- ── shared_selections ────────────────────────────────────────────
DROP POLICY IF EXISTS "full_access"          ON shared_selections;
DROP POLICY IF EXISTS "shared_public_read"   ON shared_selections;
DROP POLICY IF EXISTS "shared_secret_write"  ON shared_selections;

ALTER TABLE shared_selections ENABLE ROW LEVEL SECURITY;
CREATE POLICY "deny_anon"    ON shared_selections FOR ALL TO anon         USING (false);
CREATE POLICY "service_all"  ON shared_selections FOR ALL TO service_role USING (true) WITH CHECK (true);


-- ── app_logs ─────────────────────────────────────────────────────
DROP POLICY IF EXISTS "full_access"       ON app_logs;
DROP POLICY IF EXISTS "logs_no_anon_read" ON app_logs;
DROP POLICY IF EXISTS "logs_anon_insert"  ON app_logs;
DROP POLICY IF EXISTS "logs_service_all"  ON app_logs;

ALTER TABLE app_logs ENABLE ROW LEVEL SECURITY;
CREATE POLICY "deny_anon"    ON app_logs FOR ALL TO anon         USING (false);
CREATE POLICY "service_all"  ON app_logs FOR ALL TO service_role USING (true) WITH CHECK (true);


-- ── app_settings ─────────────────────────────────────────────────
DROP POLICY IF EXISTS "full_access"          ON app_settings;
DROP POLICY IF EXISTS "settings_public_read" ON app_settings;
DROP POLICY IF EXISTS "settings_secret_write"ON app_settings;

ALTER TABLE app_settings ENABLE ROW LEVEL SECURITY;
CREATE POLICY "deny_anon"    ON app_settings FOR ALL TO anon         USING (false);
CREATE POLICY "service_all"  ON app_settings FOR ALL TO service_role USING (true) WITH CHECK (true);


-- ────────────────────────────────────────────────────────────────
-- 3. AUTO-NETTOYAGE DES SESSIONS EXPIRÉES (optionnel)
--    Supprime automatiquement les sessions > 24h
-- ────────────────────────────────────────────────────────────────

-- Activer pg_cron si disponible (Supabase Pro+)
-- SELECT cron.schedule('cleanup-sessions', '0 */6 * * *',
--   $$DELETE FROM app_sessions WHERE expires_at < now()$$);


-- ────────────────────────────────────────────────────────────────
-- 4. VÉRIFICATION FINALE
-- ────────────────────────────────────────────────────────────────

SELECT
    tablename,
    policyname,
    roles,
    cmd,
    CASE WHEN qual = 'false' THEN '🔒 BLOQUÉ' ELSE '✅ AUTORISÉ' END AS acces
FROM pg_policies
WHERE schemaname = 'public'
ORDER BY tablename, policyname;


-- ────────────────────────────────────────────────────────────────
-- 5. REALTIME — BROADCAST
-- Le client utilise les canaux Broadcast Supabase (pas Postgres Changes).
-- Aucune publication Postgres spécifique n'est requise pour Broadcast.
-- Le service_role de l'Edge Function envoie les notifications via REST.
-- Le client reçoit via la clé anon (lecture des signaux uniquement, pas des données).
-- ────────────────────────────────────────────────────────────────

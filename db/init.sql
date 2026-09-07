CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(120) NOT NULL,
  email VARCHAR(255) NOT NULL,
  password_hash TEXT NOT NULL,
  role VARCHAR(30) NOT NULL DEFAULT 'user',
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_uidx ON users (LOWER(email));

CREATE TABLE IF NOT EXISTS cifras (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title VARCHAR(300) NOT NULL DEFAULT 'Sem título',
  tone VARCHAR(20),
  text TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS cifras_user_updated_idx ON cifras(user_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS cantores (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name VARCHAR(120) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS cantores_user_name_lower_uidx ON cantores(user_id, LOWER(name));
CREATE INDEX IF NOT EXISTS cantores_user_name_idx ON cantores(user_id, name);

CREATE TABLE IF NOT EXISTS cifra_cantores (
  cifra_id UUID NOT NULL REFERENCES cifras(id) ON DELETE CASCADE,
  cantor_id UUID NOT NULL REFERENCES cantores(id) ON DELETE CASCADE,
  tone VARCHAR(20),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (cifra_id, cantor_id)
);

CREATE INDEX IF NOT EXISTS cifra_cantores_cantor_idx ON cifra_cantores(cantor_id);



-- =====================================================
-- V4 - GRUPOS E REPERTORIOS COMPARTILHADOS
-- =====================================================
CREATE TABLE IF NOT EXISTS music_groups (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(160) NOT NULL,
  description VARCHAR(500),
  owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS music_groups_owner_idx ON music_groups(owner_user_id);

CREATE TABLE IF NOT EXISTS group_members (
  group_id UUID NOT NULL REFERENCES music_groups(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role VARCHAR(20) NOT NULL DEFAULT 'viewer',
  invited_by UUID REFERENCES users(id) ON DELETE SET NULL,
  joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (group_id,user_id)
);

CREATE INDEX IF NOT EXISTS group_members_user_idx ON group_members(user_id);

CREATE TABLE IF NOT EXISTS group_invites (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  group_id UUID NOT NULL REFERENCES music_groups(id) ON DELETE CASCADE,
  email VARCHAR(255) NOT NULL,
  role VARCHAR(20) NOT NULL DEFAULT 'viewer',
  invited_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  accepted_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS group_invites_pending_uidx
ON group_invites(group_id, LOWER(email)) WHERE accepted_at IS NULL;
CREATE INDEX IF NOT EXISTS group_invites_email_idx ON group_invites(LOWER(email));

CREATE TABLE IF NOT EXISTS group_repertoires (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  group_id UUID NOT NULL REFERENCES music_groups(id) ON DELETE CASCADE,
  name VARCHAR(160) NOT NULL,
  description VARCHAR(500),
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS group_repertoires_group_name_lower_uidx
ON group_repertoires(group_id, LOWER(name));
CREATE INDEX IF NOT EXISTS group_repertoires_group_idx ON group_repertoires(group_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS repertoire_cifras (
  repertoire_id UUID NOT NULL REFERENCES group_repertoires(id) ON DELETE CASCADE,
  cifra_id UUID NOT NULL REFERENCES cifras(id) ON DELETE CASCADE,
  added_by UUID REFERENCES users(id) ON DELETE SET NULL,
  position INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (repertoire_id,cifra_id)
);

CREATE INDEX IF NOT EXISTS repertoire_cifras_cifra_idx ON repertoire_cifras(cifra_id);

CREATE TABLE IF NOT EXISTS group_activity (
  id BIGSERIAL PRIMARY KEY,
  group_id UUID NOT NULL REFERENCES music_groups(id) ON DELETE CASCADE,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  action VARCHAR(60) NOT NULL,
  entity_type VARCHAR(40),
  entity_id UUID,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS group_activity_group_created_idx ON group_activity(group_id, created_at DESC);


CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS users_set_updated_at ON users;
CREATE TRIGGER users_set_updated_at
BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS cifras_set_updated_at ON cifras;
CREATE TRIGGER cifras_set_updated_at
BEFORE UPDATE ON cifras
FOR EACH ROW EXECUTE FUNCTION set_updated_at();


DROP TRIGGER IF EXISTS cantores_set_updated_at ON cantores;
CREATE TRIGGER cantores_set_updated_at
BEFORE UPDATE ON cantores
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS music_groups_set_updated_at ON music_groups;
CREATE TRIGGER music_groups_set_updated_at
BEFORE UPDATE ON music_groups
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS group_repertoires_set_updated_at ON group_repertoires;
CREATE TRIGGER group_repertoires_set_updated_at
BEFORE UPDATE ON group_repertoires
FOR EACH ROW EXECUTE FUNCTION set_updated_at();


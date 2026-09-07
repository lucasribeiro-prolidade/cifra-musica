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

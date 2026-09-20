
'use strict';

const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const mammoth = require('mammoth');

const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL;
const SESSION_SECRET = process.env.SESSION_SECRET;
const AI_KEY = process.env.ANTHROPIC_API_KEY || '';
const AI_MODEL = process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-6';
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();

if (!DATABASE_URL) {
  console.error('ERRO: DATABASE_URL nao configurada. Adicione PostgreSQL ao projeto Railway.');
  process.exit(1);
}
if (!SESSION_SECRET || SESSION_SECRET.length < 20) {
  console.error('ERRO: SESSION_SECRET precisa existir e ter pelo menos 20 caracteres.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

async function initDatabase() {
  const sql = fs.readFileSync(path.join(__dirname, 'db', 'init.sql'), 'utf8');
  await pool.query(sql);
  if (ADMIN_EMAIL) {
    const promoted = await pool.query(
      `UPDATE users SET role='admin', is_active=TRUE
       WHERE LOWER(email)=LOWER($1) AND (role <> 'admin' OR is_active=FALSE)
       RETURNING id,email`,
      [ADMIN_EMAIL]
    );
    if (promoted.rowCount) console.log(`Administrador promovido: ${ADMIN_EMAIL}`);
  }
  console.log('Banco Cifra-Musica pronto.');
}

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: '40mb' }));
app.use((err, req, res, next) => {
  if (err && (err.type === 'entity.too.large' || err.status === 413)) {
    return res.status(413).json({ error: 'Arquivo excedeu o limite de envio do servidor.' });
  }
  next(err);
});

app.use(session({
  store: new pgSession({
    pool,
    tableName: 'user_sessions',
    createTableIfMissing: true
  }),
  name: 'ciframusica.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 30
  }
}));

const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 40,
  standardHeaders: true,
  legacyHeaders: false
});
const aiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 12,
  standardHeaders: true,
  legacyHeaders: false
});

function cleanString(value, max = 500) {
  return String(value ?? '').trim().slice(0, max);
}

function requireAuth(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ error: 'Sessao expirada. Entre novamente.' });
  next();
}

async function requireAdmin(req, res, next) {
  try {
    if (!req.session?.userId) return res.status(401).json({ error: 'Sessao expirada. Entre novamente.' });
    const result = await pool.query('SELECT id,email,role,is_active FROM users WHERE id=$1 LIMIT 1', [req.session.userId]);
    const user = result.rows[0];
    if (!user || !user.is_active) return res.status(401).json({ error: 'Conta indisponivel.' });
    if (ADMIN_EMAIL && String(user.email).toLowerCase() === ADMIN_EMAIL && user.role !== 'admin') {
      await pool.query("UPDATE users SET role='admin' WHERE id=$1", [user.id]);
      user.role = 'admin';
    }
    if (user.role !== 'admin') return res.status(403).json({ error: 'Acesso exclusivo do administrador.' });
    req.adminUser = user;
    next();
  } catch (err) {
    console.error('requireAdmin', err);
    res.status(500).json({ error: 'Nao foi possivel validar o administrador.' });
  }
}

function publicUser(row) {
  return { id: row.id, name: row.name, email: row.email, role: row.role };
}

app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, database: true });
  } catch {
    res.status(503).json({ ok: false, database: false });
  }
});

app.get('/api/status', (_req, res) => {
  res.json({ ok: true, aiConfigured: Boolean(AI_KEY), app: 'Cifra-Musica' });
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const name = cleanString(req.body?.name, 120);
    const email = cleanString(req.body?.email, 255).toLowerCase();
    const password = String(req.body?.password || '');
    if (!name) return res.status(400).json({ error: 'Informe seu nome.' });
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Informe um e-mail valido.' });
    if (password.length < 6 || password.length > 100) return res.status(400).json({ error: 'A senha deve ter entre 6 e 100 caracteres.' });

    const exists = await pool.query('SELECT 1 FROM users WHERE LOWER(email)=LOWER($1) LIMIT 1', [email]);
    if (exists.rowCount) return res.status(409).json({ error: 'Ja existe uma conta com este e-mail.' });

    const passwordHash = await bcrypt.hash(password, 12);
    const role = ADMIN_EMAIL && email === ADMIN_EMAIL ? 'admin' : 'user';
    const result = await pool.query(
      `INSERT INTO users(name,email,password_hash,role) VALUES($1,$2,$3,$4)
       RETURNING id,name,email,role`,
      [name, email, passwordHash, role]
    );
    req.session.userId = result.rows[0].id;
    await claimPendingGroupInvites(result.rows[0].id, email).catch(err => console.error('claim invites register', err));
    res.status(201).json({ user: publicUser(result.rows[0]) });
  } catch (err) {
    console.error('register', err);
    res.status(500).json({ error: 'Nao foi possivel criar a conta.' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const email = cleanString(req.body?.email, 255).toLowerCase();
    const password = String(req.body?.password || '');
    const result = await pool.query(
      'SELECT id,name,email,role,password_hash,is_active FROM users WHERE LOWER(email)=LOWER($1) LIMIT 1',
      [email]
    );
    const user = result.rows[0];
    if (!user || !user.is_active || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
    }
    if (ADMIN_EMAIL && String(user.email).toLowerCase() === ADMIN_EMAIL && user.role !== 'admin') {
      await pool.query("UPDATE users SET role='admin' WHERE id=$1", [user.id]);
      user.role = 'admin';
    }
    req.session.userId = user.id;
    await claimPendingGroupInvites(user.id, user.email).catch(err => console.error('claim invites login', err));
    res.json({ user: publicUser(user) });
  } catch (err) {
    console.error('login', err);
    res.status(500).json({ error: 'Nao foi possivel entrar.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  if (!req.session) return res.json({ ok: true });
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/auth/me', async (req, res) => {
  try {
    if (!req.session?.userId) return res.status(401).json({ error: 'Nao autenticado.' });
    const result = await pool.query(
      'SELECT id,name,email,role,is_active FROM users WHERE id=$1 LIMIT 1',
      [req.session.userId]
    );
    const user = result.rows[0];
    if (!user || !user.is_active) return res.status(401).json({ error: 'Conta nao encontrada.' });
    if (ADMIN_EMAIL && String(user.email).toLowerCase() === ADMIN_EMAIL && user.role !== 'admin') {
      await pool.query("UPDATE users SET role='admin' WHERE id=$1", [user.id]);
      user.role = 'admin';
    }
    await claimPendingGroupInvites(user.id, user.email).catch(err => console.error('claim invites me', err));
    res.json({ user: publicUser(user) });
  } catch (err) {
    console.error('me', err);
    res.status(500).json({ error: 'Nao foi possivel validar a sessao.' });
  }
});


function isUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value || ''));
}

async function replaceCifraCantores(client, cifraId, userId, rawSingerTones, options = {}) {
  const allowExisting = Boolean(options.allowExisting);
  let existingIds = new Set();
  if (allowExisting) {
    const existing = await client.query('SELECT cantor_id FROM cifra_cantores WHERE cifra_id=$1', [cifraId]);
    existingIds = new Set(existing.rows.map(x => String(x.cantor_id)));
  }

  const items = Array.isArray(rawSingerTones) ? rawSingerTones.slice(0, 50) : [];
  const normalized = [];
  const seen = new Set();
  for (const item of items) {
    const singerId = cleanString(item?.singer_id || item?.cantor_id, 80);
    if (!isUuid(singerId) || seen.has(singerId)) continue;
    seen.add(singerId);
    normalized.push({ singerId, tone: cleanString(item?.tone, 20) || null });
  }

  const validIds = new Set();
  if (normalized.length) {
    const ids = normalized.map(x => x.singerId);
    const own = await client.query(
      'SELECT id FROM cantores WHERE user_id=$1 AND id = ANY($2::uuid[])',
      [userId, ids]
    );
    own.rows.forEach(x => validIds.add(String(x.id)));
    if (allowExisting) existingIds.forEach(id => validIds.add(id));
  }

  await client.query('DELETE FROM cifra_cantores WHERE cifra_id=$1', [cifraId]);
  for (const item of normalized) {
    if (!validIds.has(item.singerId)) continue;
    await client.query(
      `INSERT INTO cifra_cantores(cifra_id,cantor_id,tone) VALUES($1,$2,$3)
       ON CONFLICT(cifra_id,cantor_id) DO UPDATE SET tone=EXCLUDED.tone`,
      [cifraId, item.singerId, item.tone]
    );
  }
}

async function fetchCifraRows(db, userId, cifraId = null) {
  const params = cifraId ? [userId, cifraId] : [userId];
  const extra = cifraId ? ' AND c.id=$2' : '';
  const result = await db.query(`
    SELECT c.id,c.title,c.tone,c.text,c.created_at,c.updated_at,
           (SELECT COUNT(*)::int FROM repertoire_cifras rc0 WHERE rc0.cifra_id=c.id) AS shared_count,
           COALESCE(
             jsonb_agg(
               jsonb_build_object('singer_id',ca.id,'name',ca.name,'tone',cc.tone,'owner_user_id',ca.user_id)
               ORDER BY ca.name
             ) FILTER (WHERE ca.id IS NOT NULL),
             '[]'::jsonb
           ) AS singers
    FROM cifras c
    LEFT JOIN cifra_cantores cc ON cc.cifra_id=c.id
    LEFT JOIN cantores ca ON ca.id=cc.cantor_id
    WHERE c.user_id=$1${extra}
    GROUP BY c.id
    ORDER BY c.updated_at DESC
  `, params);
  return result.rows;
}

async function ensureSingerByName(client, userId, rawName) {
  const name = cleanString(rawName, 120);
  if (!name) return null;
  const found = await client.query(
    'SELECT id,name FROM cantores WHERE user_id=$1 AND LOWER(name)=LOWER($2) LIMIT 1',
    [userId, name]
  );
  if (found.rowCount) return found.rows[0];
  try {
    const created = await client.query(
      'INSERT INTO cantores(user_id,name) VALUES($1,$2) RETURNING id,name',
      [userId, name]
    );
    return created.rows[0];
  } catch (err) {
    if (err.code !== '23505') throw err;
    const retry = await client.query(
      'SELECT id,name FROM cantores WHERE user_id=$1 AND LOWER(name)=LOWER($2) LIMIT 1',
      [userId, name]
    );
    return retry.rows[0] || null;
  }
}


// ══════════════════════════════════════════════════════
// V4 - GRUPOS / PASTAS / REPERTORIOS COMPARTILHADOS
// ══════════════════════════════════════════════════════
const GROUP_ROLES = new Set(['admin', 'editor', 'viewer']);

function groupCanWrite(access) {
  return Boolean(access && (access.role === 'admin' || access.role === 'editor'));
}
function groupCanAdmin(access) {
  return Boolean(access && access.role === 'admin');
}

async function logGroupActivity(db, groupId, userId, action, entityType = null, entityId = null, details = {}) {
  await db.query(
    `INSERT INTO group_activity(group_id,user_id,action,entity_type,entity_id,details)
     VALUES($1,$2,$3,$4,$5,$6::jsonb)`,
    [groupId, userId || null, action, entityType, entityId || null, JSON.stringify(details || {})]
  );
}

async function getGroupAccess(db, userId, groupId) {
  if (!isUuid(groupId)) return null;
  const result = await db.query(`
    SELECT g.id,g.name,g.description,g.owner_user_id,g.created_at,g.updated_at,
           gm.role,(g.owner_user_id=$2) AS is_owner
    FROM music_groups g
    JOIN group_members gm ON gm.group_id=g.id AND gm.user_id=$2
    WHERE g.id=$1
    LIMIT 1
  `, [groupId, userId]);
  return result.rows[0] || null;
}

async function getRepertoireAccess(db, userId, repertoireId) {
  if (!isUuid(repertoireId)) return null;
  const result = await db.query(`
    SELECT r.id AS repertoire_id,r.name AS repertoire_name,r.description AS repertoire_description,
           r.group_id,g.name AS group_name,g.owner_user_id,gm.role,
           (g.owner_user_id=$2) AS is_owner
    FROM group_repertoires r
    JOIN music_groups g ON g.id=r.group_id
    JOIN group_members gm ON gm.group_id=g.id AND gm.user_id=$2
    WHERE r.id=$1
    LIMIT 1
  `, [repertoireId, userId]);
  return result.rows[0] || null;
}

async function getCifraEditAccess(db, userId, cifraId, preferredGroupId = null) {
  if (!isUuid(cifraId)) return { allowed: false };
  const ownerResult = await db.query('SELECT id,user_id,title FROM cifras WHERE id=$1 LIMIT 1', [cifraId]);
  const cifraRow = ownerResult.rows[0];
  if (!cifraRow) return { allowed: false, notFound: true };
  const isOwner = String(cifraRow.user_id) === String(userId);

  if (preferredGroupId && isUuid(preferredGroupId)) {
    const shared = await db.query(`
      SELECT gr.group_id,gm.role
      FROM repertoire_cifras rc
      JOIN group_repertoires gr ON gr.id=rc.repertoire_id
      JOIN group_members gm ON gm.group_id=gr.group_id AND gm.user_id=$2
      WHERE rc.cifra_id=$1 AND gr.group_id=$3
      LIMIT 1
    `, [cifraId, userId, preferredGroupId]);
    if (shared.rowCount) {
      const role = shared.rows[0].role;
      return { allowed: isOwner || role === 'admin' || role === 'editor', isOwner, groupId: shared.rows[0].group_id, role, cifra: cifraRow };
    }
  }

  if (isOwner) return { allowed: true, isOwner: true, cifra: cifraRow };

  const shared = await db.query(`
    SELECT gr.group_id,gm.role
    FROM repertoire_cifras rc
    JOIN group_repertoires gr ON gr.id=rc.repertoire_id
    JOIN group_members gm ON gm.group_id=gr.group_id AND gm.user_id=$2
    WHERE rc.cifra_id=$1 AND gm.role IN ('admin','editor')
    LIMIT 1
  `, [cifraId, userId]);
  if (shared.rowCount) return { allowed: true, isOwner: false, groupId: shared.rows[0].group_id, role: shared.rows[0].role, cifra: cifraRow };
  return { allowed: false, isOwner: false, cifra: cifraRow };
}

async function claimPendingGroupInvites(userId, email) {
  const cleanEmail = cleanString(email, 255).toLowerCase();
  if (!isUuid(userId) || !cleanEmail) return;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const invites = await client.query(`
      SELECT id,group_id,role,invited_by
      FROM group_invites
      WHERE accepted_at IS NULL AND LOWER(email)=LOWER($1)
      FOR UPDATE
    `, [cleanEmail]);
    for (const invite of invites.rows) {
      const groupExists = await client.query('SELECT id FROM music_groups WHERE id=$1', [invite.group_id]);
      if (!groupExists.rowCount) continue;
      await client.query(`
        INSERT INTO group_members(group_id,user_id,role,invited_by)
        VALUES($1,$2,$3,$4)
        ON CONFLICT(group_id,user_id) DO NOTHING
      `, [invite.group_id, userId, GROUP_ROLES.has(invite.role) ? invite.role : 'viewer', invite.invited_by]);
      await client.query('UPDATE group_invites SET accepted_at=NOW() WHERE id=$1', [invite.id]);
      await logGroupActivity(client, invite.group_id, userId, 'invite_accepted', 'member', userId, { email: cleanEmail });
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

async function fetchSharedCifras(db, repertoireId, currentUserId, role) {
  const result = await db.query(`
    SELECT c.id,c.user_id AS owner_user_id,c.title,c.tone,c.text,c.created_at,c.updated_at,
           owner.name AS owner_name,owner.email AS owner_email,
           rc.created_at AS shared_at,adder.name AS added_by_name,
           COALESCE(
             jsonb_agg(
               jsonb_build_object('singer_id',ca.id,'name',ca.name,'tone',cc.tone,'owner_user_id',ca.user_id)
               ORDER BY ca.name
             ) FILTER (WHERE ca.id IS NOT NULL),
             '[]'::jsonb
           ) AS singers
    FROM repertoire_cifras rc
    JOIN cifras c ON c.id=rc.cifra_id
    JOIN users owner ON owner.id=c.user_id
    LEFT JOIN users adder ON adder.id=rc.added_by
    LEFT JOIN cifra_cantores cc ON cc.cifra_id=c.id
    LEFT JOIN cantores ca ON ca.id=cc.cantor_id
    WHERE rc.repertoire_id=$1
    GROUP BY c.id,owner.id,rc.repertoire_id,rc.created_at,rc.added_by,adder.id
    ORDER BY rc.created_at DESC,c.title
  `, [repertoireId]);
  return result.rows.map(row => ({
    ...row,
    can_edit: String(row.owner_user_id) === String(currentUserId) || role === 'admin' || role === 'editor',
    is_owner: String(row.owner_user_id) === String(currentUserId)
  }));
}

app.get('/api/groups', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT g.id,g.name,g.description,g.owner_user_id,g.created_at,g.updated_at,gm.role,
             (g.owner_user_id=$1) AS is_owner,
             (SELECT COUNT(*)::int FROM group_members m WHERE m.group_id=g.id) AS member_count,
             (SELECT COUNT(*)::int FROM group_repertoires r WHERE r.group_id=g.id) AS repertoire_count,
             (SELECT COUNT(*)::int FROM repertoire_cifras rc JOIN group_repertoires r2 ON r2.id=rc.repertoire_id WHERE r2.group_id=g.id) AS song_count
      FROM group_members gm
      JOIN music_groups g ON g.id=gm.group_id
      WHERE gm.user_id=$1
      ORDER BY g.updated_at DESC,g.name
    `, [req.session.userId]);
    res.json({ items: result.rows });
  } catch (err) {
    console.error('list groups', err);
    res.status(500).json({ error: 'Erro ao carregar grupos.' });
  }
});

app.post('/api/groups', requireAuth, async (req, res) => {
  const client = await pool.connect();
  try {
    const name = cleanString(req.body?.name, 160);
    const description = cleanString(req.body?.description, 500) || null;
    if (!name) return res.status(400).json({ error: 'Informe o nome do grupo.' });
    await client.query('BEGIN');
    const created = await client.query(
      `INSERT INTO music_groups(name,description,owner_user_id) VALUES($1,$2,$3)
       RETURNING id,name,description,owner_user_id,created_at,updated_at`,
      [name, description, req.session.userId]
    );
    const group = created.rows[0];
    await client.query(
      `INSERT INTO group_members(group_id,user_id,role,invited_by) VALUES($1,$2,'admin',$2)`,
      [group.id, req.session.userId]
    );
    await client.query(
      `INSERT INTO group_repertoires(group_id,name,description,created_by) VALUES($1,'Geral','Pasta principal do grupo',$2)`,
      [group.id, req.session.userId]
    );
    await logGroupActivity(client, group.id, req.session.userId, 'group_created', 'group', group.id, { name });
    await client.query('COMMIT');
    res.status(201).json({ group: { ...group, role: 'admin', is_owner: true } });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('create group', err);
    res.status(500).json({ error: 'Erro ao criar grupo.' });
  } finally {
    client.release();
  }
});

app.get('/api/groups/:id', requireAuth, async (req, res) => {
  try {
    const access = await getGroupAccess(pool, req.session.userId, req.params.id);
    if (!access) return res.status(404).json({ error: 'Grupo nao encontrado ou sem acesso.' });
    const members = await pool.query(`
      SELECT u.id,u.name,u.email,gm.role,gm.joined_at,(u.id=$2) AS is_owner
      FROM group_members gm
      JOIN users u ON u.id=gm.user_id
      WHERE gm.group_id=$1
      ORDER BY (u.id=$2) DESC,LOWER(u.name)
    `, [access.id, access.owner_user_id]);
    const repertoires = await pool.query(`
      SELECT r.id,r.name,r.description,r.created_at,r.updated_at,
             COUNT(rc.cifra_id)::int AS song_count
      FROM group_repertoires r
      LEFT JOIN repertoire_cifras rc ON rc.repertoire_id=r.id
      WHERE r.group_id=$1
      GROUP BY r.id
      ORDER BY r.updated_at DESC,r.name
    `, [access.id]);
    const activity = await pool.query(`
      SELECT a.id,a.action,a.entity_type,a.entity_id,a.details,a.created_at,u.name AS user_name,u.email AS user_email
      FROM group_activity a
      LEFT JOIN users u ON u.id=a.user_id
      WHERE a.group_id=$1
      ORDER BY a.created_at DESC
      LIMIT 30
    `, [access.id]);
    let invites = [];
    if (groupCanAdmin(access)) {
      const inv = await pool.query(`
        SELECT id,email,role,created_at
        FROM group_invites
        WHERE group_id=$1 AND accepted_at IS NULL
        ORDER BY created_at DESC
      `, [access.id]);
      invites = inv.rows;
    }
    res.json({
      group: access,
      can_write: groupCanWrite(access),
      can_admin: groupCanAdmin(access),
      members: members.rows,
      invites,
      repertoires: repertoires.rows,
      activity: activity.rows
    });
  } catch (err) {
    console.error('group detail', err);
    res.status(500).json({ error: 'Erro ao carregar grupo.' });
  }
});

app.put('/api/groups/:id', requireAuth, async (req, res) => {
  try {
    const access = await getGroupAccess(pool, req.session.userId, req.params.id);
    if (!access) return res.status(404).json({ error: 'Grupo nao encontrado.' });
    if (!groupCanAdmin(access)) return res.status(403).json({ error: 'Somente administradores do grupo podem alterar o grupo.' });
    const name = cleanString(req.body?.name, 160);
    const description = cleanString(req.body?.description, 500) || null;
    if (!name) return res.status(400).json({ error: 'Informe o nome do grupo.' });
    const result = await pool.query(
      `UPDATE music_groups SET name=$1,description=$2 WHERE id=$3 RETURNING id,name,description,owner_user_id,created_at,updated_at`,
      [name, description, access.id]
    );
    await logGroupActivity(pool, access.id, req.session.userId, 'group_updated', 'group', access.id, { name });
    res.json({ group: result.rows[0] });
  } catch (err) {
    console.error('update group', err);
    res.status(500).json({ error: 'Erro ao atualizar grupo.' });
  }
});

app.delete('/api/groups/:id', requireAuth, async (req, res) => {
  try {
    const access = await getGroupAccess(pool, req.session.userId, req.params.id);
    if (!access) return res.status(404).json({ error: 'Grupo nao encontrado.' });
    if (!access.is_owner) return res.status(403).json({ error: 'Somente o dono pode excluir o grupo.' });
    await pool.query('DELETE FROM music_groups WHERE id=$1', [access.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('delete group', err);
    res.status(500).json({ error: 'Erro ao excluir grupo.' });
  }
});

app.post('/api/groups/:id/leave', requireAuth, async (req, res) => {
  try {
    const access = await getGroupAccess(pool, req.session.userId, req.params.id);
    if (!access) return res.status(404).json({ error: 'Grupo nao encontrado.' });
    if (access.is_owner) return res.status(400).json({ error: 'O dono nao pode sair do proprio grupo. Transfira a gestao ou exclua o grupo.' });
    await logGroupActivity(pool, access.id, req.session.userId, 'member_left', 'member', req.session.userId, {});
    await pool.query('DELETE FROM group_members WHERE group_id=$1 AND user_id=$2', [access.id, req.session.userId]);
    res.json({ ok: true });
  } catch (err) {
    console.error('leave group', err);
    res.status(500).json({ error: 'Erro ao sair do grupo.' });
  }
});

app.post('/api/groups/:id/invite', requireAuth, async (req, res) => {
  const client = await pool.connect();
  try {
    const access = await getGroupAccess(client, req.session.userId, req.params.id);
    if (!access) return res.status(404).json({ error: 'Grupo nao encontrado.' });
    if (!groupCanAdmin(access)) return res.status(403).json({ error: 'Somente administradores podem convidar integrantes.' });
    const email = cleanString(req.body?.email, 255).toLowerCase();
    const role = cleanString(req.body?.role, 20) || 'viewer';
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Informe um e-mail valido.' });
    if (!GROUP_ROLES.has(role)) return res.status(400).json({ error: 'Permissao invalida.' });
    await client.query('BEGIN');
    const userResult = await client.query('SELECT id,name,email FROM users WHERE LOWER(email)=LOWER($1) LIMIT 1', [email]);
    let pending = false;
    if (userResult.rowCount) {
      const target = userResult.rows[0];
      if (String(target.id) === String(access.owner_user_id)) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'O dono do grupo ja faz parte do grupo.' });
      }
      await client.query(`
        INSERT INTO group_members(group_id,user_id,role,invited_by)
        VALUES($1,$2,$3,$4)
        ON CONFLICT(group_id,user_id) DO UPDATE SET role=EXCLUDED.role
      `, [access.id, target.id, role, req.session.userId]);
      await client.query(`UPDATE group_invites SET accepted_at=NOW() WHERE group_id=$1 AND accepted_at IS NULL AND LOWER(email)=LOWER($2)`, [access.id, email]);
      await logGroupActivity(client, access.id, req.session.userId, 'member_added', 'member', target.id, { email, name: target.name, role });
    } else {
      const existing = await client.query(`SELECT id FROM group_invites WHERE group_id=$1 AND accepted_at IS NULL AND LOWER(email)=LOWER($2) LIMIT 1`, [access.id, email]);
      if (existing.rowCount) {
        await client.query('UPDATE group_invites SET role=$1,invited_by=$2,created_at=NOW() WHERE id=$3', [role, req.session.userId, existing.rows[0].id]);
      } else {
        await client.query('INSERT INTO group_invites(group_id,email,role,invited_by) VALUES($1,$2,$3,$4)', [access.id, email, role, req.session.userId]);
      }
      pending = true;
      await logGroupActivity(client, access.id, req.session.userId, 'invite_created', 'invite', null, { email, role });
    }
    await client.query('COMMIT');
    res.json({ ok: true, pending });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('invite group member', err);
    res.status(500).json({ error: 'Erro ao convidar integrante.' });
  } finally {
    client.release();
  }
});

app.patch('/api/groups/:id/members/:userId', requireAuth, async (req, res) => {
  try {
    const access = await getGroupAccess(pool, req.session.userId, req.params.id);
    if (!access) return res.status(404).json({ error: 'Grupo nao encontrado.' });
    if (!groupCanAdmin(access)) return res.status(403).json({ error: 'Somente administradores podem alterar permissoes.' });
    const targetId = cleanString(req.params.userId, 80);
    const role = cleanString(req.body?.role, 20);
    if (!isUuid(targetId) || !GROUP_ROLES.has(role)) return res.status(400).json({ error: 'Dados invalidos.' });
    if (String(targetId) === String(access.owner_user_id)) return res.status(400).json({ error: 'O dono do grupo deve permanecer administrador.' });
    const result = await pool.query(
      `UPDATE group_members SET role=$1 WHERE group_id=$2 AND user_id=$3 RETURNING user_id,role`,
      [role, access.id, targetId]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Integrante nao encontrado.' });
    await logGroupActivity(pool, access.id, req.session.userId, 'member_role_changed', 'member', targetId, { role });
    res.json({ ok: true });
  } catch (err) {
    console.error('change member role', err);
    res.status(500).json({ error: 'Erro ao alterar permissao.' });
  }
});

app.delete('/api/groups/:id/members/:userId', requireAuth, async (req, res) => {
  try {
    const access = await getGroupAccess(pool, req.session.userId, req.params.id);
    if (!access) return res.status(404).json({ error: 'Grupo nao encontrado.' });
    if (!groupCanAdmin(access)) return res.status(403).json({ error: 'Somente administradores podem remover integrantes.' });
    const targetId = cleanString(req.params.userId, 80);
    if (!isUuid(targetId)) return res.status(400).json({ error: 'Integrante invalido.' });
    if (String(targetId) === String(access.owner_user_id)) return res.status(400).json({ error: 'O dono do grupo nao pode ser removido.' });
    const result = await pool.query('DELETE FROM group_members WHERE group_id=$1 AND user_id=$2', [access.id, targetId]);
    if (!result.rowCount) return res.status(404).json({ error: 'Integrante nao encontrado.' });
    await logGroupActivity(pool, access.id, req.session.userId, 'member_removed', 'member', targetId, {});
    res.json({ ok: true });
  } catch (err) {
    console.error('remove member', err);
    res.status(500).json({ error: 'Erro ao remover integrante.' });
  }
});

app.delete('/api/groups/:id/invites/:inviteId', requireAuth, async (req, res) => {
  try {
    const access = await getGroupAccess(pool, req.session.userId, req.params.id);
    if (!access) return res.status(404).json({ error: 'Grupo nao encontrado.' });
    if (!groupCanAdmin(access)) return res.status(403).json({ error: 'Somente administradores podem cancelar convites.' });
    const result = await pool.query('DELETE FROM group_invites WHERE id=$1 AND group_id=$2 AND accepted_at IS NULL', [req.params.inviteId, access.id]);
    if (!result.rowCount) return res.status(404).json({ error: 'Convite nao encontrado.' });
    res.json({ ok: true });
  } catch (err) {
    console.error('cancel invite', err);
    res.status(500).json({ error: 'Erro ao cancelar convite.' });
  }
});

app.post('/api/groups/:id/repertoires', requireAuth, async (req, res) => {
  try {
    const access = await getGroupAccess(pool, req.session.userId, req.params.id);
    if (!access) return res.status(404).json({ error: 'Grupo nao encontrado.' });
    if (!groupCanWrite(access)) return res.status(403).json({ error: 'Voce nao tem permissao para criar pastas.' });
    const name = cleanString(req.body?.name, 160);
    const description = cleanString(req.body?.description, 500) || null;
    if (!name) return res.status(400).json({ error: 'Informe o nome da pasta.' });
    const result = await pool.query(
      `INSERT INTO group_repertoires(group_id,name,description,created_by) VALUES($1,$2,$3,$4)
       RETURNING id,name,description,created_at,updated_at`,
      [access.id, name, description, req.session.userId]
    );
    await logGroupActivity(pool, access.id, req.session.userId, 'repertoire_created', 'repertoire', result.rows[0].id, { name });
    res.status(201).json({ repertoire: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Ja existe uma pasta com este nome.' });
    console.error('create repertoire', err);
    res.status(500).json({ error: 'Erro ao criar pasta.' });
  }
});

app.put('/api/repertoires/:id', requireAuth, async (req, res) => {
  try {
    const access = await getRepertoireAccess(pool, req.session.userId, req.params.id);
    if (!access) return res.status(404).json({ error: 'Pasta nao encontrada.' });
    if (!groupCanWrite(access)) return res.status(403).json({ error: 'Sem permissao para alterar esta pasta.' });
    const name = cleanString(req.body?.name, 160);
    const description = cleanString(req.body?.description, 500) || null;
    if (!name) return res.status(400).json({ error: 'Informe o nome da pasta.' });
    const result = await pool.query(
      `UPDATE group_repertoires SET name=$1,description=$2 WHERE id=$3 RETURNING id,name,description,created_at,updated_at`,
      [name, description, access.repertoire_id]
    );
    await logGroupActivity(pool, access.group_id, req.session.userId, 'repertoire_updated', 'repertoire', access.repertoire_id, { name });
    res.json({ repertoire: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Ja existe uma pasta com este nome.' });
    console.error('update repertoire', err);
    res.status(500).json({ error: 'Erro ao atualizar pasta.' });
  }
});

app.delete('/api/repertoires/:id', requireAuth, async (req, res) => {
  try {
    const access = await getRepertoireAccess(pool, req.session.userId, req.params.id);
    if (!access) return res.status(404).json({ error: 'Pasta nao encontrada.' });
    if (!groupCanWrite(access)) return res.status(403).json({ error: 'Sem permissao para excluir esta pasta.' });
    await logGroupActivity(pool, access.group_id, req.session.userId, 'repertoire_deleted', 'repertoire', access.repertoire_id, { name: access.repertoire_name });
    await pool.query('DELETE FROM group_repertoires WHERE id=$1', [access.repertoire_id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('delete repertoire', err);
    res.status(500).json({ error: 'Erro ao excluir pasta.' });
  }
});

app.get('/api/repertoires/:id/cifras', requireAuth, async (req, res) => {
  try {
    const access = await getRepertoireAccess(pool, req.session.userId, req.params.id);
    if (!access) return res.status(404).json({ error: 'Pasta nao encontrada ou sem acesso.' });
    const items = await fetchSharedCifras(pool, access.repertoire_id, req.session.userId, access.role);
    res.json({
      repertoire: {
        id: access.repertoire_id,
        name: access.repertoire_name,
        description: access.repertoire_description,
        group_id: access.group_id,
        group_name: access.group_name,
        role: access.role,
        can_write: groupCanWrite(access)
      },
      items
    });
  } catch (err) {
    console.error('shared repertoire songs', err);
    res.status(500).json({ error: 'Erro ao carregar musicas compartilhadas.' });
  }
});

app.post('/api/repertoires/:id/cifras', requireAuth, async (req, res) => {
  try {
    const access = await getRepertoireAccess(pool, req.session.userId, req.params.id);
    if (!access) return res.status(404).json({ error: 'Pasta nao encontrada.' });
    if (!groupCanWrite(access)) return res.status(403).json({ error: 'Voce nao tem permissao para adicionar musicas.' });
    const cifraId = cleanString(req.body?.cifra_id, 80);
    if (!isUuid(cifraId)) return res.status(400).json({ error: 'Musica invalida.' });
    const allowed = await pool.query(`
      SELECT c.id,c.title
      FROM cifras c
      WHERE c.id=$1 AND (
        c.user_id=$2 OR EXISTS(
          SELECT 1 FROM repertoire_cifras rc2
          JOIN group_repertoires gr2 ON gr2.id=rc2.repertoire_id
          WHERE rc2.cifra_id=c.id AND gr2.group_id=$3
        )
      )
      LIMIT 1
    `, [cifraId, req.session.userId, access.group_id]);
    if (!allowed.rowCount) return res.status(403).json({ error: 'Voce so pode adicionar suas musicas ou musicas que ja pertencem a este grupo.' });
    await pool.query(
      `INSERT INTO repertoire_cifras(repertoire_id,cifra_id,added_by) VALUES($1,$2,$3)`,
      [access.repertoire_id, cifraId, req.session.userId]
    );
    await logGroupActivity(pool, access.group_id, req.session.userId, 'song_added', 'cifra', cifraId, { title: allowed.rows[0].title, repertoire: access.repertoire_name });
    res.status(201).json({ ok: true });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Esta musica ja esta nesta pasta.' });
    console.error('add song to repertoire', err);
    res.status(500).json({ error: 'Erro ao compartilhar musica.' });
  }
});

app.delete('/api/repertoires/:id/cifras/:cifraId', requireAuth, async (req, res) => {
  try {
    const access = await getRepertoireAccess(pool, req.session.userId, req.params.id);
    if (!access) return res.status(404).json({ error: 'Pasta nao encontrada.' });
    if (!groupCanWrite(access)) return res.status(403).json({ error: 'Sem permissao para remover musicas.' });
    const titleResult = await pool.query('SELECT title FROM cifras WHERE id=$1 LIMIT 1', [req.params.cifraId]);
    const result = await pool.query('DELETE FROM repertoire_cifras WHERE repertoire_id=$1 AND cifra_id=$2', [access.repertoire_id, req.params.cifraId]);
    if (!result.rowCount) return res.status(404).json({ error: 'Musica nao encontrada nesta pasta.' });
    await logGroupActivity(pool, access.group_id, req.session.userId, 'song_removed', 'cifra', req.params.cifraId, { title: titleResult.rows[0]?.title || '', repertoire: access.repertoire_name });
    res.json({ ok: true });
  } catch (err) {
    console.error('remove song from repertoire', err);
    res.status(500).json({ error: 'Erro ao remover musica da pasta.' });
  }
});

// ══════════════════════════════════════════════════════
// CANTORES DO USUARIO
// ══════════════════════════════════════════════════════
app.get('/api/cantores', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT ca.id,ca.name,ca.created_at,ca.updated_at,COUNT(cc.cifra_id)::int AS cifra_count
       FROM cantores ca
       LEFT JOIN cifra_cantores cc ON cc.cantor_id=ca.id
       WHERE ca.user_id=$1
       GROUP BY ca.id
       ORDER BY LOWER(ca.name)`,
      [req.session.userId]
    );
    res.json({ items: result.rows });
  } catch (err) {
    console.error('list cantores', err);
    res.status(500).json({ error: 'Erro ao carregar cantores.' });
  }
});

app.post('/api/cantores', requireAuth, async (req, res) => {
  try {
    const name = cleanString(req.body?.name, 120);
    if (!name) return res.status(400).json({ error: 'Informe o nome do cantor.' });
    const result = await pool.query(
      'INSERT INTO cantores(user_id,name) VALUES($1,$2) RETURNING id,name,created_at,updated_at',
      [req.session.userId, name]
    );
    res.status(201).json({ item: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Este cantor ja esta cadastrado.' });
    console.error('create cantor', err);
    res.status(500).json({ error: 'Erro ao cadastrar cantor.' });
  }
});

app.put('/api/cantores/:id', requireAuth, async (req, res) => {
  try {
    const name = cleanString(req.body?.name, 120);
    if (!name) return res.status(400).json({ error: 'Informe o nome do cantor.' });
    const result = await pool.query(
      `UPDATE cantores SET name=$1 WHERE id=$2 AND user_id=$3
       RETURNING id,name,created_at,updated_at`,
      [name, req.params.id, req.session.userId]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Cantor nao encontrado.' });
    res.json({ item: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Ja existe outro cantor com este nome.' });
    console.error('update cantor', err);
    res.status(500).json({ error: 'Erro ao atualizar cantor.' });
  }
});

app.delete('/api/cantores/:id', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM cantores WHERE id=$1 AND user_id=$2', [req.params.id, req.session.userId]);
    if (!result.rowCount) return res.status(404).json({ error: 'Cantor nao encontrado.' });
    res.json({ ok: true });
  } catch (err) {
    console.error('delete cantor', err);
    res.status(500).json({ error: 'Erro ao excluir cantor.' });
  }
});



// ══════════════════════════════════════════════════════
// ADMINISTRACAO DE USUARIOS
// ══════════════════════════════════════════════════════
app.get('/api/admin/users', requireAdmin, async (_req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.id,u.name,u.email,u.role,u.is_active,u.created_at,u.updated_at,
             COUNT(c.id)::int AS cifra_count
      FROM users u
      LEFT JOIN cifras c ON c.user_id=u.id
      GROUP BY u.id,u.name,u.email,u.role,u.is_active,u.created_at,u.updated_at
      ORDER BY u.created_at DESC
    `);
    const users = result.rows;
    res.json({
      users,
      summary: {
        total: users.length,
        active: users.filter(x => x.is_active).length,
        blocked: users.filter(x => !x.is_active).length,
        admins: users.filter(x => x.role === 'admin').length,
        cifras: users.reduce((sum, x) => sum + Number(x.cifra_count || 0), 0)
      }
    });
  } catch (err) {
    console.error('admin users', err);
    res.status(500).json({ error: 'Erro ao carregar usuarios.' });
  }
});

app.patch('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    const targetId = cleanString(req.params.id, 80);
    const found = await pool.query('SELECT id,name,email,role,is_active FROM users WHERE id=$1 LIMIT 1', [targetId]);
    const target = found.rows[0];
    if (!target) return res.status(404).json({ error: 'Usuario nao encontrado.' });

    let role = target.role;
    let isActive = target.is_active;
    if (req.body?.role !== undefined) {
      if (!['user', 'admin'].includes(req.body.role)) return res.status(400).json({ error: 'Perfil invalido.' });
      role = req.body.role;
    }
    if (req.body?.is_active !== undefined) isActive = Boolean(req.body.is_active);

    const isSelf = String(target.id) === String(req.session.userId);
    const isMainAdmin = ADMIN_EMAIL && String(target.email).toLowerCase() === ADMIN_EMAIL;
    if ((isSelf || isMainAdmin) && (!isActive || role !== 'admin')) {
      return res.status(400).json({ error: 'O administrador principal nao pode ser bloqueado nem rebaixado.' });
    }

    const result = await pool.query(
      `UPDATE users SET role=$1,is_active=$2 WHERE id=$3
       RETURNING id,name,email,role,is_active,created_at,updated_at`,
      [role, isActive, targetId]
    );
    res.json({ user: result.rows[0] });
  } catch (err) {
    console.error('admin update user', err);
    res.status(500).json({ error: 'Erro ao atualizar usuario.' });
  }
});

app.get('/api/cifras', requireAuth, async (req, res) => {
  try {
    const items = await fetchCifraRows(pool, req.session.userId);
    res.json({ items });
  } catch (err) {
    console.error('list cifras', err);
    res.status(500).json({ error: 'Erro ao carregar cifras.' });
  }
});

app.post('/api/cifras', requireAuth, async (req, res) => {
  const client = await pool.connect();
  try {
    const title = cleanString(req.body?.title || 'Sem titulo', 300) || 'Sem titulo';
    const tone = cleanString(req.body?.tone, 20) || null;
    const text = String(req.body?.text || '');
    if (!text.trim()) return res.status(400).json({ error: 'A cifra esta vazia.' });
    if (text.length > 250000) return res.status(413).json({ error: 'Cifra muito grande.' });
    await client.query('BEGIN');
    const result = await client.query(
      `INSERT INTO cifras(user_id,title,tone,text) VALUES($1,$2,$3,$4) RETURNING id`,
      [req.session.userId, title, tone, text]
    );
    const cifraId = result.rows[0].id;
    await replaceCifraCantores(client, cifraId, req.session.userId, req.body?.singer_tones);
    await client.query('COMMIT');
    const item = (await fetchCifraRows(pool, req.session.userId, cifraId))[0];
    res.status(201).json({ item });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('create cifra', err);
    res.status(500).json({ error: 'Erro ao salvar cifra.' });
  } finally {
    client.release();
  }
});

app.put('/api/cifras/:id', requireAuth, async (req, res) => {
  const client = await pool.connect();
  try {
    const title = cleanString(req.body?.title || 'Sem titulo', 300) || 'Sem titulo';
    const tone = cleanString(req.body?.tone, 20) || null;
    const text = String(req.body?.text || '');
    if (!text.trim()) return res.status(400).json({ error: 'A cifra esta vazia.' });
    const editAccess = await getCifraEditAccess(client, req.session.userId, req.params.id, req.body?.group_id);
    if (editAccess.notFound) return res.status(404).json({ error: 'Cifra nao encontrada.' });
    if (!editAccess.allowed) return res.status(403).json({ error: 'Voce nao tem permissao para editar esta cifra compartilhada.' });

    await client.query('BEGIN');
    const result = await client.query(
      `UPDATE cifras SET title=$1,tone=$2,text=$3 WHERE id=$4 RETURNING id`,
      [title, tone, text, req.params.id]
    );
    if (!result.rowCount) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Cifra nao encontrada.' });
    }
    await replaceCifraCantores(client, req.params.id, req.session.userId, req.body?.singer_tones, { allowExisting: !editAccess.isOwner });

    const linkedGroups = await client.query(`
      SELECT DISTINCT gr.group_id
      FROM repertoire_cifras rc
      JOIN group_repertoires gr ON gr.id=rc.repertoire_id
      WHERE rc.cifra_id=$1
    `, [req.params.id]);
    for (const row of linkedGroups.rows) {
      await logGroupActivity(client, row.group_id, req.session.userId, 'song_updated', 'cifra', req.params.id, { title });
    }
    await client.query('COMMIT');

    if (editAccess.isOwner) {
      const item = (await fetchCifraRows(pool, req.session.userId, req.params.id))[0];
      return res.json({ item });
    }
    const sharedInfo = await pool.query(`
      SELECT rc.repertoire_id,gr.group_id,gm.role
      FROM repertoire_cifras rc
      JOIN group_repertoires gr ON gr.id=rc.repertoire_id
      JOIN group_members gm ON gm.group_id=gr.group_id AND gm.user_id=$2
      WHERE rc.cifra_id=$1
      ORDER BY (gr.group_id=$3) DESC
      LIMIT 1
    `, [req.params.id, req.session.userId, editAccess.groupId || null]);
    const sr = sharedInfo.rows[0];
    const items = sr ? await fetchSharedCifras(pool, sr.repertoire_id, req.session.userId, sr.role) : [];
    res.json({ item: items.find(x => String(x.id) === String(req.params.id)) || { id: req.params.id, title, tone, text, singers: [] } });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('update cifra', err);
    res.status(500).json({ error: 'Erro ao atualizar cifra.' });
  } finally {
    client.release();
  }
});

app.delete('/api/cifras/:id', requireAuth, async (req, res) => {
  try {
    const owned = await pool.query('SELECT id,title FROM cifras WHERE id=$1 AND user_id=$2 LIMIT 1', [req.params.id, req.session.userId]);
    if (!owned.rowCount) return res.status(404).json({ error: 'Cifra nao encontrada.' });
    const shared = await pool.query('SELECT COUNT(*)::int AS total FROM repertoire_cifras WHERE cifra_id=$1', [req.params.id]);
    const total = Number(shared.rows[0]?.total || 0);
    if (total > 0) return res.status(409).json({ error: `Esta cifra esta compartilhada em ${total} pasta(s). Remova-a dos grupos antes de excluir.` });
    await pool.query('DELETE FROM cifras WHERE id=$1 AND user_id=$2', [req.params.id, req.session.userId]);
    res.json({ ok: true });
  } catch (err) {
    console.error('delete cifra', err);
    res.status(500).json({ error: 'Erro ao excluir cifra.' });
  }
});

app.post('/api/cifras/import', requireAuth, async (req, res) => {
  const client = await pool.connect();
  try {
    const items = Array.isArray(req.body?.items) ? req.body.items.slice(0, 1000) : [];
    if (!items.length) return res.status(400).json({ error: 'Nenhuma cifra para importar.' });
    await client.query('BEGIN');
    let added = 0;
    for (const item of items) {
      const text = String(item?.text || '');
      if (!text.trim() || text.length > 250000) continue;
      const title = cleanString(item?.title || 'Sem titulo', 300) || 'Sem titulo';
      const tone = cleanString(item?.tone, 20) || null;
      const created = await client.query(
        'INSERT INTO cifras(user_id,title,tone,text) VALUES($1,$2,$3,$4) RETURNING id',
        [req.session.userId, title, tone, text]
      );
      const importedSingers = Array.isArray(item?.singers) ? item.singers.slice(0, 50) : [];
      const singerTones = [];
      for (const singer of importedSingers) {
        const ensured = await ensureSingerByName(client, req.session.userId, singer?.name);
        if (ensured) singerTones.push({ singer_id: ensured.id, tone: cleanString(singer?.tone, 20) || null });
      }
      await replaceCifraCantores(client, created.rows[0].id, req.session.userId, singerTones);
      added++;
    }
    await client.query('COMMIT');
    res.json({ ok: true, added });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('import cifras', err);
    res.status(500).json({ error: 'Erro ao importar cifras.' });
  } finally {
    client.release();
  }
});

async function callAnthropic(body) {
  if (!AI_KEY) {
    const err = new Error('A IA ainda nao foi configurada no servidor.');
    err.status = 503;
    throw err;
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 60000);
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': AI_KEY,
        'anthropic-version': '2023-06-01'
      },
      signal: controller.signal,
      body: JSON.stringify(body)
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const err = new Error(data?.error?.message || `Erro da IA (${response.status})`);
      err.status = response.status >= 500 ? 502 : 400;
      throw err;
    }
    return data;
  } finally {
    clearTimeout(timeout);
  }
}

function anthropicText(data) {
  return (data?.content || []).filter(x => x.type === 'text').map(x => x.text).join('\n').trim();
}


// ══════════════════════════════════════════════════════
// POSIÇÃO EXATA DOS ACORDES — v6.16
// ══════════════════════════════════════════════════════
const EXACT_CHORD_TOKEN = '[A-G](?:#|b)?(?:maj|min|m(?!aj)|dim|aug|sus\\d*|add\\d*|°|ø|\\d+)*(?:\\/[A-G](?:#|b)?)?';
const exactChordOnlyRx = new RegExp('^\\s*' + EXACT_CHORD_TOKEN + '(?:\\s+' + EXACT_CHORD_TOKEN + ')*\\s*$');

function expandTabsExact(line, tabSize = 8) {
  let out = '';
  let col = 0;
  for (const ch of String(line || '')) {
    if (ch === '\t') {
      const count = tabSize - (col % tabSize);
      out += ' '.repeat(count);
      col += count;
    } else {
      out += ch;
      col += 1;
    }
  }
  return out;
}

function isExactChordRow(line) {
  const t = String(line || '');
  return !!t.trim() && exactChordOnlyRx.test(t);
}

function parseExactChordRow(line) {
  const src = expandTabsExact(line);
  const out = [];
  const re = /\S+/g;
  let m;
  const oneChordRx = new RegExp('^' + EXACT_CHORD_TOKEN + '$');
  while ((m = re.exec(src)) !== null) {
    if (oneChordRx.test(m[0])) out.push({ chord: m[0], pos: m.index });
  }
  return out;
}

// Converte linha de acordes + linha de letra em [ACORDE] exatamente
// na MESMA COLUNA do texto original. Nenhuma IA participa desta etapa.
function rowsToInlineChordMarkers(input) {
  const lines = String(input || '').replace(/\r\n?/g, '\n').split('\n').map(x => expandTabsExact(x));
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const chordLine = lines[i];
    const lyricLine = i + 1 < lines.length ? lines[i + 1] : null;
    if (isExactChordRow(chordLine) && lyricLine !== null && !isExactChordRow(lyricLine) && !/^\s*\[[^\]]+\]\s*$/.test(lyricLine)) {
      const chords = parseExactChordRow(chordLine);
      if (chords.length && /[A-Za-zÀ-ÿ]/.test(lyricLine)) {
        let marked = lyricLine;
        for (const c of [...chords].sort((a, b) => b.pos - a.pos)) {
          const p = Math.max(0, Math.min(c.pos, marked.length));
          marked = marked.slice(0, p) + '[' + c.chord + ']' + marked.slice(p);
        }
        out.push(marked);
        i += 1;
        continue;
      }
    }
    out.push(chordLine);
  }
  return out.join('\n');
}

function hasInlineChordMarkers(text) {
  return new RegExp('\\[' + EXACT_CHORD_TOKEN + '\\]').test(String(text || ''));
}

function stripObviousCifraNoisePreserveLayout(input) {
  const blocked = /(?:cifraclub|letras\.mus|vagalume|palco mp3|baixar|download|compartilhe|publicidade|anúncio|propaganda|acesse|visite|inscreva|seguidores|instagram|facebook|twitter|youtube\.com|adblock|ads by|advertisement|sponsored)/i;
  return String(input || '')
    .replace(/\r\n?/g, '\n')
    .split('\n')
    .map(x => expandTabsExact(x))
    .filter(line => !blocked.test(line.trim()))
    .join('\n')
    .replace(/\n{4,}/g, '\n\n\n')
    .trim();
}

async function extractCifraMetadataOnly(raw) {
  const prompt = `Analise o material de cifra abaixo APENAS para identificar metadados.
NÃO reescreva a letra. NÃO reescreva os acordes. NÃO organize o corpo.

Retorne SOMENTE:
TITULO: [título, se identificável]
ARTISTA: [artista, se identificável]
TOM: [tom, se identificável]

MATERIAL:
${String(raw || '').slice(0, 120000)}`;
  try {
    const data = await callAnthropic({
      model: AI_MODEL,
      max_tokens: 300,
      messages: [{ role: 'user', content: prompt }]
    });
    return anthropicText(data).trim();
  } catch {
    return '';
  }
}

function normalizeMarkerAiResult(raw) {
  const txt = String(raw || '').trim();
  if (!txt) return '';
  return inlineChordMarkersToRows(txt);
}

app.post('/api/ai/organize', requireAuth, aiLimiter, async (req, res) => {
  try {
    const raw = String(req.body?.text || '').slice(0, 200000);
    if (!raw.trim()) return res.status(400).json({ error: 'Texto vazio.' });

    const cleaned = stripObviousCifraNoisePreserveLayout(raw);
    const markerized = rowsToInlineChordMarkers(cleaned);
    const hadReliableRows = markerized !== cleaned && hasInlineChordMarkers(markerized);

    // CIFRA COLADA JÁ ALINHADA:
    // preserva o corpo 100% por cálculo de coluna; IA só lê metadados.
    if (hadReliableRows) {
      const meta = await extractCifraMetadataOnly(cleaned);
      const body = inlineChordMarkersToRows(markerized);
      const text = [meta, body].filter(Boolean).join('\n\n').trim();
      return res.json({ text, position_mode: 'preserved' });
    }

    // Conteúdo já marcado [ACORDE]palavra: converte sem reinterpretar.
    if (hasInlineChordMarkers(cleaned)) {
      const meta = await extractCifraMetadataOnly(cleaned);
      const body = inlineChordMarkersToRows(cleaned);
      const text = [meta, body].filter(Boolean).join('\n\n').trim();
      return res.json({ text, position_mode: 'markers' });
    }

    // Só usa IA para criar âncoras quando o texto realmente não contém
    // posição confiável.
    const prompt = `Você recebeu uma cifra musical em texto que NÃO possui posição confiável dos acordes.

OBJETIVO:
Organizar sem alterar a harmonia e marcar o ponto de entrada de cada acorde.

REGRAS ABSOLUTAS:
- Preserve a letra fornecida.
- Preserve EXATAMENTE o nome de cada acorde, incluindo extensões e baixos.
- NÃO invente, simplifique, transponha ou rearmonize.
- NÃO junte dois versos e NÃO divida um verso em outro ponto.
- Quando o material permitir saber onde um acorde entra, escreva [ACORDE] imediatamente antes da palavra/sílaba correspondente.
- Se a posição não estiver clara, NÃO adivinhe: mantenha a linha de acordes separada.
- Remova somente propaganda, link e texto claramente estranho à música.

RETORNE SOMENTE:
TITULO: [nome, se identificável]
ARTISTA: [artista, se identificável]
TOM: [tom, se identificável]

CIFRA:
[corpo com [ACORDE] antes da palavra/sílaba quando a posição for segura]

MATERIAL ORIGINAL:
${cleaned}`;

    const data = await callAnthropic({
      model: AI_MODEL,
      max_tokens: 8000,
      messages: [{ role: 'user', content: prompt }]
    });
    const text = normalizeMarkerAiResult(anthropicText(data));
    if (!text) throw new Error('A IA nao retornou resultado.');
    res.json({ text, position_mode: 'anchored' });
  } catch (err) {
    console.error('ai organize', err.message);
    res.status(err.status || 500).json({ error: err.message || 'Erro ao organizar com IA.' });
  }
});

app.post('/api/ai/read-document', requireAuth, aiLimiter, async (req, res) => {
  try {
    const base64 = String(req.body?.base64 || '');
    const mediaType = cleanString(req.body?.mediaType || 'application/pdf', 150);
    const filename = cleanString(req.body?.filename || '', 300);

    if (!base64) {
      return res.status(400).json({ error: 'Arquivo ausente.' });
    }
    // ~25 MB de arquivo binário depois da conversão para base64.
    if (base64.length > 35_000_000) {
      return res.status(413).json({ error: 'Arquivo muito grande. Use um PDF de até 25 MB.' });
    }

    const isImage = /^image\/(jpeg|png|webp|gif)$/i.test(mediaType);
    const isPdf = mediaType === 'application/pdf';
    const isDocx = mediaType === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';

    if (!isImage && !isPdf && !isDocx) {
      return res.status(400).json({ error: 'Formato não suportado. Use PDF, Word (.docx) ou imagem.' });
    }

    // WORD: extrai o texto no próprio servidor. Não depende mais de CDN no celular.
    if (isDocx) {
      const buffer = Buffer.from(base64, 'base64');
      if (!buffer.length) return res.status(400).json({ error: 'Word vazio ou inválido.' });

      const result = await mammoth.extractRawText({ buffer });
      const raw = String(result?.value || '').trim();
      if (!raw) return res.status(400).json({ error: 'Não consegui encontrar texto neste Word.' });
      if (raw.length > 120_000) return res.status(400).json({ error: 'O Word tem texto demais. Envie apenas a cifra desejada.' });

      const cleaned = stripObviousCifraNoisePreserveLayout(raw);
      const markerized = rowsToInlineChordMarkers(cleaned);

      // Word cujo texto extraído já traz acordes em colunas:
      // preserva a posição sem deixar a IA mover nada.
      if (markerized !== cleaned && hasInlineChordMarkers(markerized)) {
        const meta = await extractCifraMetadataOnly(cleaned);
        const body = inlineChordMarkersToRows(markerized);
        return res.json({
          text: [meta, body].filter(Boolean).join('\n\n').trim(),
          position_mode: 'preserved'
        });
      }

      const prompt = `Leia o texto extraído deste Word (${filename || 'arquivo.docx'}) e organize a cifra.

REGRA MAIS IMPORTANTE — POSIÇÃO:
- NÃO tente alinhar acordes usando espaços aproximados.
- Para cada acorde cuja entrada possa ser determinada pelo documento, coloque [ACORDE] imediatamente antes da palavra/sílaba onde ele entra.
- NÃO mova a troca para uma palavra anterior ou posterior.
- Se a posição não puder ser determinada com segurança, NÃO adivinhe: mantenha o acorde em linha separada.

FIDELIDADE:
- Preserve letra, estrofes e quebras de verso.
- Preserve EXATAMENTE nomes de acordes, extensões e baixos.
- NÃO invente, simplifique, transponha ou rearmonize.
- Remova apenas cabeçalho, rodapé, número de página e ruído óbvio.

RETORNE SOMENTE:
TITULO: [nome, se identificado]
ARTISTA: [artista, se identificado]
TOM: [tom, se identificado]

CIFRA:
[cifra com [ACORDE] antes da palavra/sílaba]

CONTEÚDO DO WORD:
${cleaned}`;

      const data = await callAnthropic({
        model: AI_MODEL,
        max_tokens: 8000,
        messages: [{ role: 'user', content: prompt }]
      });
      const text = normalizeMarkerAiResult(anthropicText(data));
      if (!text) throw new Error('A IA não conseguiu organizar o Word.');
      return res.json({ text, position_mode: 'anchored' });
    }

    const visualBlock = isImage
      ? { type: 'image', source: { type: 'base64', media_type: mediaType, data: base64 } }
      : { type: 'document', source: { type: 'base64', media_type: mediaType, data: base64 } };

    const instruction = isImage
      ? `Leia esta fotografia de uma cifra musical (${filename || 'imagem'}).

OBJETIVO:
Transformar a foto em cifra editável PRESERVANDO O MOMENTO EXATO DA TROCA.

REGRA MAIS IMPORTANTE — POSIÇÃO:
- Observe visualmente onde cada acorde está em relação à linha da letra.
- NÃO devolva a posição por espaços aproximados.
- Escreva [ACORDE] imediatamente antes da palavra/sílaba que está diretamente abaixo daquele acorde.
- A posição deve vir da FOTO, não do que parece musicalmente provável.
- NÃO antecipe nem atrase a troca.
- Se não for possível determinar a posição com segurança, NÃO adivinhe: mantenha o acorde em uma linha separada.

FIDELIDADE:
- Preserve o texto visível.
- Preserve EXATAMENTE cada acorde, incluindo 7, 9, sus e baixos como D/F#.
- NÃO invente, simplifique, transponha ou rearmonize.
- Preserve estrofes, refrões e quebras de verso.
- Ignore partitura, número de página, cabeçalho, rodapé e propaganda.
- Se algo estiver ilegível, use [?].

RETORNE SOMENTE:
TITULO: [nome, se identificado]
ARTISTA: [artista, se identificado]
TOM: [tom, se identificado]

CIFRA:
[letra com [ACORDE] antes da palavra/sílaba exata]`
      : `Leia VISUALMENTE este PDF de cifra (${filename || 'arquivo'}).

OBJETIVO:
Extrair a cifra PRESERVANDO O MOMENTO EXATO DA TROCA mostrado no PDF.

REGRA MAIS IMPORTANTE — POSIÇÃO:
- Observe a coluna visual de cada acorde e a palavra/sílaba diretamente abaixo dele.
- NÃO devolva a posição por quantidade aproximada de espaços.
- Escreva [ACORDE] imediatamente antes da palavra/sílaba correspondente.
- A posição deve vir do PDF, não de inferência musical.
- NÃO antecipe nem atrase a troca.
- Se a posição não puder ser determinada com segurança, NÃO adivinhe: mantenha o acorde em linha separada.

FIDELIDADE:
- Preserve EXATAMENTE nomes de acordes, extensões e baixos.
- NÃO invente, simplifique, transponha ou rearmonize.
- Preserve a letra, estrofes e quebras de verso como no PDF.
- Remova somente cabeçalho, rodapé, propaganda e ruído externo.
- Se algo estiver ilegível, use [?].

RETORNE SOMENTE:
TITULO: [nome, se identificado]
ARTISTA: [artista, se identificado]
TOM: [tom, se identificado]

CIFRA:
[letra com [ACORDE] antes da palavra/sílaba exata]`;

    const data = await callAnthropic({
      model: AI_MODEL,
      max_tokens: 8000,
      messages: [{
        role: 'user',
        content: [visualBlock, { type: 'text', text: instruction }]
      }]
    });

    const text = normalizeMarkerAiResult(anthropicText(data));
    if (!text) throw new Error('A IA não conseguiu ler o arquivo.');
    res.json({ text, position_mode: 'anchored' });
  } catch (err) {
    console.error('ai document', err.message);
    res.status(err.status || 500).json({ error: err.message || 'Erro ao ler arquivo.' });
  }
});

function parseAiSearchField(raw, name) {
  const rx = new RegExp(`^${name}:\\s*(.*)$`, 'im');
  return String(raw || '').match(rx)?.[1]?.trim() || '';
}

function safeHttpUrl(value) {
  const url = String(value || '').trim();
  if (!url) return '';
  try {
    const parsed = new URL(url);
    return ['http:', 'https:'].includes(parsed.protocol) ? parsed.toString() : '';
  } catch {
    return '';
  }
}

function parseAiSearchSources(raw) {
  const out = [];
  const seen = new Set();
  const text = String(raw || '');
  const rx = /^FONTE_(\d+):\s*(.*?)\s*\|\s*(https?:\/\/\S+)\s*$/gim;
  let m;
  while ((m = rx.exec(text)) !== null) {
    const name = cleanString(m[2] || 'Fonte', 120) || 'Fonte';
    const url = safeHttpUrl(m[3]);
    if (!url || seen.has(url)) continue;
    seen.add(url);
    out.push({ name, url });
    if (out.length >= 5) break;
  }

  if (!out.length) {
    const name = parseAiSearchField(text, 'FONTE');
    const url = safeHttpUrl(parseAiSearchField(text, 'URL'));
    if (url) out.push({ name: name || 'Fonte', url });
  }
  return out;
}

function looksLikeUsableChordSheet(text) {
  const raw = String(text || '').trim();
  if (!raw) return false;

  const blocked = [
    /material protegido/i,
    /direitos autorais/i,
    /copyright/i,
    /não (?:posso|é possível|posso fornecer).*letra/i,
    /nao (?:posso|e possivel|posso fornecer).*letra/i,
    /acordes principais encontrados/i,
    /artista\s*\/\s*vers[aã]o/i,
    /^\s*\|.*\|\s*$/m,
    /orienta[cç][aã]o/i
  ];
  if (blocked.some(rx => rx.test(raw))) return false;

  const lines = raw.split(/\r?\n/).map(x => x.trimEnd()).filter(Boolean);
  if (lines.length < 4) return false;

  const chordToken = /(^|\s)(?:[A-G](?:#|b)?(?:m|maj|min|dim|aug|sus|add)?(?:2|4|5|6|7|9|11|13)?(?:\([^)]*\))?(?:\/[A-G](?:#|b)?)?)(?=\s|$)/g;
  let chordCount = 0;
  let lyricLines = 0;
  for (const line of lines) {
    const chords = line.match(chordToken) || [];
    chordCount += chords.length;
    const withoutChords = line.replace(chordToken, ' ').replace(/[\[\](){}|_-]/g, ' ').trim();
    if (/[A-Za-zÀ-ÿ]{3,}/.test(withoutChords) && !/^(intro|verso|refr[aã]o|coro|ponte|final)\b/i.test(withoutChords)) lyricLines++;
  }
  return chordCount >= 2 && lyricLines >= 3;
}

function userRequestedAlternateArrangement(query) {
  return /\b(?:ukulele|reggae|iniciante|simplificad[ao]|vers[aã]o\s*\d+|version\s*\d+)\b/i.test(String(query || ''));
}

function isAlternateArrangementSource(url, source, query) {
  if (userRequestedAlternateArrangement(query)) return false;
  const value = `${String(url || '')} ${String(source || '')}`.toLowerCase();
  return /ukecifras|ukulele|\/iniciante(?:\.html)?|\/reggae(?:\.html)?|\/indefinida[-_/]|simplificad|vers[aã]o\s*\d+|version\s*\d+/.test(value);
}

function buildCifraSearchPrompt(q, excludedUrl = '') {
  return `Você é especialista em localizar cifras musicais na web.

BUSCA DO USUÁRIO: "${q}"

OBJETIVO:
Encontrar UMA única cifra principal, coerente e bem formatada da música correta.

ORDEM DE ESCOLHA DA FONTE:
1. Primeiro identifique com segurança o compositor/intérprete/versão pedida.
2. Prefira a página PRINCIPAL de cifra para violão/guitarra do artista correto.
3. Se houver uma página principal no Cifra Club para o artista correto, ela pode ser usada; caso contrário use Cifras.com.br, Banana Cifras ou outra fonte de cifra com estrutura clara.
4. NÃO fique preso a um único site: pesquise outras fontes quando necessário.
5. NÃO use página de ukulele, versão iniciante, reggae, simplificada, versão numerada ou arranjo alternativo quando existir uma versão principal — a menos que o usuário peça explicitamente esse arranjo.
6. NÃO use uma fonte em que não seja possível identificar com segurança EM QUAL PALAVRA/SÍLABA cada acorde entra.
${excludedUrl ? `7. NÃO use novamente esta fonte rejeitada: ${excludedUrl}` : ''}

REGRA DE FONTE ÚNICA:
- Use outras páginas apenas para confirmar título/artista.
- Depois de escolher a fonte principal, TODA a harmonia deve vir dessa MESMA página.
- Nunca misture acordes de duas versões.

FIDELIDADE MUSICAL — REGRA MAIS IMPORTANTE:
- Copie os acordes da fonte principal sem transpor, simplificar ou rearmonizar.
- Preserve EXATAMENTE extensões e baixos: F#m7 não pode virar F#m; D/F# não pode sumir; A4 continua A4.
- Preserve EXATAMENTE as quebras de versos da fonte. NÃO junte dois versos e NÃO divida um verso em outro ponto.
- NÃO mova acorde para outra palavra só para "organizar" visualmente.
- NÃO invente acordes ausentes.

MARCAÇÃO DA TROCA DE ACORDE:
- Para cada linha que contém letra, coloque o acorde ENTRE COLCHETES imediatamente antes da palavra ou sílaba onde ele APARECE NA FONTE escolhida.
- A posição vem da fonte visual/textual. NÃO escolha a posição pelo que parece musicalmente provável.
- Exemplo genérico de formato: Eu quero [G]cantar para [D]Ti
- Se a fonte mostra o acorde sobre uma palavra mais à frente, o marcador deve ficar nessa palavra mais à frente, mesmo que outra posição pareça musicalmente possível.
- Se houver mais de um acorde na mesma linha, marque TODOS exatamente no ponto mostrado pela fonte.
- Linhas apenas de acordes (intro/interlúdio) podem continuar como linha normal: G  D  G
- Títulos de seção continuam como [Intro], [Verso], [Refrão], [Ponte] etc.
- NÃO use espaços para tentar posicionar acordes sobre a letra. A posição será definida pelos marcadores [ACORDE].
- Antes de responder, confira cada marcador contra a fonte escolhida: palavra/sílaba, extensão do acorde e baixo devem coincidir.

RETORNE SOMENTE:
TITULO: [nome]
ARTISTA: [artista/versão]
TOM: [tom da fonte principal, em C, C#, D, Eb, E, F, F#, G, Ab, A, Bb ou B]
FONTE: [nome do site]
URL: [URL direta da página principal escolhida]

CIFRA:
[cifra da única fonte escolhida usando [ACORDE] antes da palavra/sílaba]

Se nenhuma fonte principal tiver estrutura suficientemente clara para marcar as trocas sem adivinhar, retorne somente:
ERRO: Não encontrei uma cifra principal confiável desta versão.`;
}

// v6.15 — converte [ACORDE]colado à palavra em duas linhas monoespaçadas.
// Assim a posição musical não depende dos espaços gerados pela IA.
function inlineChordMarkersToRows(input) {
  const chordInside = '[A-G](?:#|b)?(?:maj|min|m(?!aj)|dim|aug|sus\\d*|add\\d*|°|ø|\\d+)*(?:\\/[A-G](?:#|b)?)?';
  const markerRx = new RegExp('\\[(' + chordInside + ')\\]', 'g');
  const out = [];

  for (const originalLine of String(input || '').replace(/\r\n?/g, '\n').split('\n')) {
    markerRx.lastIndex = 0;
    let match;
    let last = 0;
    let lyric = '';
    const markers = [];

    while ((match = markerRx.exec(originalLine)) !== null) {
      lyric += originalLine.slice(last, match.index);
      markers.push({ chord: match[1], pos: lyric.length });
      last = match.index + match[0].length;
    }

    if (!markers.length) {
      out.push(originalLine);
      continue;
    }

    lyric += originalLine.slice(last);

    // Linha marcada sem letra: intro/interlúdio vira linha simples de acordes.
    if (!/[A-Za-zÀ-ÿ]/.test(lyric)) {
      out.push(markers.map(x => x.chord).join('  '));
      continue;
    }

    const chordLine = [];
    for (const item of markers) {
      // A âncora é EXATAMENTE a coluna da palavra/sílaba.
      // Não desloca o acorde para "caber"; isso mudaria a hora da troca.
      const pos = Math.max(0, item.pos);
      const needed = pos + item.chord.length;
      while (chordLine.length < needed) chordLine.push(' ');
      for (let i = 0; i < item.chord.length; i++) {
        // Se houver sobreposição rara, mantém a primeira âncora e só preenche
        // posições ainda vazias; nunca empurra nenhum acorde horizontalmente.
        if (chordLine[pos + i] === undefined || chordLine[pos + i] === ' ') chordLine[pos + i] = item.chord[i];
      }
    }

    out.push(chordLine.join('').replace(/\s+$/, ''));
    out.push(lyric.replace(/\s+$/, ''));
  }

  return out.join('\n');
}

async function runCifraWebSearch(prompt) {
  const data = await callAnthropic({
    model: AI_MODEL,
    max_tokens: 8000,
    tools: [{ type: 'web_search_20250305', name: 'web_search' }],
    messages: [{ role: 'user', content: prompt }]
  });
  return anthropicText(data).trim();
}

app.post('/api/ai/search', requireAuth, aiLimiter, async (req, res) => {
  try {
    const q = cleanString(req.body?.q, 300);
    if (!q) return res.status(400).json({ error: 'Digite o nome da musica.' });

    let raw = await runCifraWebSearch(buildCifraSearchPrompt(q));
    if (!raw) throw new Error('Nenhum resultado encontrado.');

    if (/^ERRO\s*:/i.test(raw)) {
      return res.status(404).json({
        error: 'Não consegui encontrar uma cifra principal completa. Tente informar também o cantor ou a versão.'
      });
    }

    // Se a IA escolheu uma fonte alternativa/achatada sem o usuário pedir,
    // fazemos UMA nova busca excluindo aquela fonte. Isso evita casos como
    // cifra de ukulele sendo usada como se fosse a versão principal de violão.
    let source = parseAiSearchField(raw, 'FONTE');
    let url = safeHttpUrl(parseAiSearchField(raw, 'URL'));
    if (isAlternateArrangementSource(url, source, q)) {
      const retry = await runCifraWebSearch(buildCifraSearchPrompt(q, url || source));
      if (retry && !/^ERRO\s*:/i.test(retry)) {
        const retrySource = parseAiSearchField(retry, 'FONTE');
        const retryUrl = safeHttpUrl(parseAiSearchField(retry, 'URL'));
        if (!isAlternateArrangementSource(retryUrl, retrySource, q)) {
          raw = retry;
          source = retrySource;
          url = retryUrl;
        }
      }
    }

    // Se mesmo após o retry só apareceu arranjo alternativo, é melhor avisar
    // do que carregar uma harmonia errada como se fosse a principal.
    if (isAlternateArrangementSource(url, source, q)) {
      return res.status(404).json({
        error: 'Encontrei apenas versões alternativas desta música. Informe o cantor/versão para eu buscar a cifra correta.'
      });
    }

    const title = parseAiSearchField(raw, 'TITULO') || q;
    const artist = parseAiSearchField(raw, 'ARTISTA');
    const tone = parseAiSearchField(raw, 'TOM');
    source = parseAiSearchField(raw, 'FONTE');
    url = safeHttpUrl(parseAiSearchField(raw, 'URL'));

    let text = raw
      .replace(/^```(?:text|txt|markdown)?\s*$/gim, '')
      .replace(/^```\s*$/gim, '')
      .replace(/^TITULO:\s*.*$/gim, '')
      .replace(/^ARTISTA:\s*.*$/gim, '')
      .replace(/^TOM:\s*.*$/gim, '')
      .replace(/^CIFRA:\s*$/gim, '')
      .replace(/^STATUS:\s*.*$/gim, '')
      .replace(/^MOTIVO:\s*.*$/gim, '')
      .replace(/^FONTE(?:_\d+)?:\s*.*$/gim, '')
      .replace(/^URL:\s*.*$/gim, '')
      .replace(/\n{3,}/g, '\n\n')
      .trim();

    // A busca retorna os acordes presos à palavra/sílaba: [D]Cada... [G]fé...
    // Convertemos aqui para o formato atual do app (linha de acordes + linha de letra).
    // Isso preserva a hora da troca sem depender de espaços aproximados da IA.
    text = inlineChordMarkersToRows(text);

    const refusalOrExplanation = /(?:direitos autorais|material protegido|copyright|não posso fornecer|nao posso fornecer|não é possível fornecer|nao e possivel fornecer|acordes principais encontrados|artista\s*\/\s*vers[aã]o)/i;
    if (!text || text.length < 60 || refusalOrExplanation.test(text)) {
      return res.status(404).json({
        error: 'Encontrei a música, mas não uma cifra completa e confiável para carregar. Tente informar também o cantor.'
      });
    }

    const lines = text.split(/\r?\n/).filter(x => x.trim());
    const chordRx = /(?:^|\s)[A-G](?:#|b)?(?:m|maj|min|dim|aug|sus|add)?(?:2|4|5|6|7|9|11|13)?(?:\([^)]*\))?(?:\/[A-G](?:#|b)?)?(?=\s|$)/g;
    const chordCount = (text.match(chordRx) || []).length;
    const lyricCount = lines.filter(line => /[A-Za-zÀ-ÿ]{3,}/.test(line) && !/^\s*[A-G](?:#|b)?(?:\S*\s+)*$/i.test(line)).length;
    if (lines.length < 4 || chordCount < 1 || lyricCount < 2) {
      return res.status(404).json({
        error: 'A fonte encontrada não veio bem estruturada. Tente incluir o nome do cantor ou da versão.'
      });
    }

    res.json({
      status: 'cifra',
      title,
      artist,
      tone,
      source,
      url,
      text
    });
  } catch (err) {
    console.error('ai search', err.message);
    res.status(err.status || 500).json({ error: err.message || 'Erro na busca.' });
  }
});

app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.use((_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

async function startWithRetry() {
  let lastError;
  for (let attempt = 1; attempt <= 12; attempt++) {
    try {
      await initDatabase();
      app.listen(PORT, '0.0.0.0', () => console.log(`Cifra-Musica rodando na porta ${PORT}`));
      return;
    } catch (err) {
      lastError = err;
      console.error(`Banco ainda indisponivel (tentativa ${attempt}/12):`, err.message);
      await new Promise(resolve => setTimeout(resolve, 5000));
    }
  }
  console.error('Falha ao preparar banco:', lastError);
  process.exit(1);
}

startWithRetry();

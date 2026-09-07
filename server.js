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
app.use(express.json({ limit: '22mb' }));

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
    res.json({ user: publicUser(user) });
  } catch (err) {
    console.error('me', err);
    res.status(500).json({ error: 'Nao foi possivel validar a sessao.' });
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
    const result = await pool.query(
      `SELECT id,title,tone,text,created_at,updated_at
       FROM cifras WHERE user_id=$1 ORDER BY updated_at DESC`,
      [req.session.userId]
    );
    res.json({ items: result.rows });
  } catch (err) {
    console.error('list cifras', err);
    res.status(500).json({ error: 'Erro ao carregar cifras.' });
  }
});

app.post('/api/cifras', requireAuth, async (req, res) => {
  try {
    const title = cleanString(req.body?.title || 'Sem titulo', 300) || 'Sem titulo';
    const tone = cleanString(req.body?.tone, 20) || null;
    const text = String(req.body?.text || '');
    if (!text.trim()) return res.status(400).json({ error: 'A cifra esta vazia.' });
    if (text.length > 250000) return res.status(413).json({ error: 'Cifra muito grande.' });
    const result = await pool.query(
      `INSERT INTO cifras(user_id,title,tone,text) VALUES($1,$2,$3,$4)
       RETURNING id,title,tone,text,created_at,updated_at`,
      [req.session.userId, title, tone, text]
    );
    res.status(201).json({ item: result.rows[0] });
  } catch (err) {
    console.error('create cifra', err);
    res.status(500).json({ error: 'Erro ao salvar cifra.' });
  }
});

app.put('/api/cifras/:id', requireAuth, async (req, res) => {
  try {
    const title = cleanString(req.body?.title || 'Sem titulo', 300) || 'Sem titulo';
    const tone = cleanString(req.body?.tone, 20) || null;
    const text = String(req.body?.text || '');
    if (!text.trim()) return res.status(400).json({ error: 'A cifra esta vazia.' });
    const result = await pool.query(
      `UPDATE cifras SET title=$1,tone=$2,text=$3
       WHERE id=$4 AND user_id=$5
       RETURNING id,title,tone,text,created_at,updated_at`,
      [title, tone, text, req.params.id, req.session.userId]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Cifra nao encontrada.' });
    res.json({ item: result.rows[0] });
  } catch (err) {
    console.error('update cifra', err);
    res.status(500).json({ error: 'Erro ao atualizar cifra.' });
  }
});

app.delete('/api/cifras/:id', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM cifras WHERE id=$1 AND user_id=$2', [req.params.id, req.session.userId]);
    if (!result.rowCount) return res.status(404).json({ error: 'Cifra nao encontrada.' });
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
      await client.query('INSERT INTO cifras(user_id,title,tone,text) VALUES($1,$2,$3,$4)', [req.session.userId, title, tone, text]);
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

app.post('/api/ai/organize', requireAuth, aiLimiter, async (req, res) => {
  try {
    const raw = String(req.body?.text || '').slice(0, 200000);
    if (!raw.trim()) return res.status(400).json({ error: 'Texto vazio.' });
    const prompt = `Voce e especialista em limpar e organizar cifras musicais para musicos.\n\nCIFRA ORIGINAL:\n${raw}\n\nREGRA ABSOLUTA: NAO MOVA NENHUM ACORDE DE LUGAR. NAO ALTERE NOMES DE ACORDES.\nA posicao de cada acorde representa o momento exato da troca no instrumento.\n\nO QUE FAZER:\n- Remover propagandas, links e textos de site\n- Remover capotraste, BPM e tabs numericas quando nao forem parte essencial da cifra\n- Identificar secoes: [Intro] [Verso 1] [Refrao] [Ponte]\n- Extrair titulo e artista quando estiverem no material fornecido\n\nO QUE NUNCA FAZER:\n- Mover acordes de coluna\n- Renomear ou simplificar acordes\n- Juntar ou separar linhas de forma que altere o alinhamento\n\nRETORNE SOMENTE:\nTITULO: [nome]\nARTISTA: [artista]\nTOM: [tom]\n\n[cifra organizada preservando as posicoes]`;
    const data = await callAnthropic({ model: AI_MODEL, max_tokens: 8000, messages: [{ role: 'user', content: prompt }] });
    const text = anthropicText(data);
    if (!text) throw new Error('A IA nao retornou resultado.');
    res.json({ text });
  } catch (err) {
    console.error('ai organize', err.message);
    res.status(err.status || 500).json({ error: err.message || 'Erro ao organizar com IA.' });
  }
});

app.post('/api/ai/read-document', requireAuth, aiLimiter, async (req, res) => {
  try {
    const base64 = String(req.body?.base64 || '');
    const mediaType = cleanString(req.body?.mediaType || 'application/pdf', 100);
    if (!base64 || base64.length > 28_000_000) return res.status(400).json({ error: 'Arquivo ausente ou muito grande.' });
    const data = await callAnthropic({
      model: AI_MODEL,
      max_tokens: 8000,
      messages: [{ role: 'user', content: [
        { type: 'document', source: { type: 'base64', media_type: mediaType, data: base64 } },
        { type: 'text', text: 'Extraia e organize a cifra deste arquivo. Preserve exatamente o alinhamento e os nomes dos acordes. Remova cabecalhos, rodapes e textos que nao fazem parte da cifra. Se houver titulo, comece com TITULO: [nome]. Retorne apenas a cifra limpa e organizada.' }
      ] }]
    });
    const text = anthropicText(data);
    if (!text) throw new Error('A IA nao conseguiu ler o arquivo.');
    res.json({ text });
  } catch (err) {
    console.error('ai document', err.message);
    res.status(err.status || 500).json({ error: err.message || 'Erro ao ler arquivo.' });
  }
});

app.post('/api/ai/search', requireAuth, aiLimiter, async (req, res) => {
  try {
    const q = cleanString(req.body?.q, 300);
    if (!q) return res.status(400).json({ error: 'Digite o nome da musica.' });
    const prompt = `Voce e um assistente para musicos. Pesquise informacoes de cifra para a musica: "${q}". Use fontes publicas disponiveis na web. Respeite direitos autorais e nao reproduza material protegido alem do permitido. Quando for possivel fornecer legitimamente uma cifra, preserve exatamente as posicoes dos acordes. Retorne no formato:\nTITULO: [nome]\nARTISTA: [artista]\nTOM: [tom]\n\n[conteudo disponivel/permitido ou uma orientacao curta para o usuario colar/importar a cifra que possui]`;
    const data = await callAnthropic({
      model: AI_MODEL,
      max_tokens: 6000,
      tools: [{ type: 'web_search_20250305', name: 'web_search' }],
      messages: [{ role: 'user', content: prompt }]
    });
    const text = anthropicText(data);
    if (!text) throw new Error('Nenhum resultado encontrado.');
    res.json({ text });
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

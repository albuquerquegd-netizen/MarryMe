const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

require('dotenv').config({ path: path.join(__dirname, '.env') });

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data', 'convites.json');

// --- Armazenamento persistente (Supabase) ---
// Sem isso configurado, os dados ficam num arquivo local que se perde a cada
// deploy no Render (disco não-permanente). Veja .env.example.
const { createClient } = require('@supabase/supabase-js');
const { SUPABASE_URL, SUPABASE_SERVICE_KEY } = process.env;
const supabaseAtivado = SUPABASE_URL && SUPABASE_SERVICE_KEY;
const supabase = supabaseAtivado ? createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY) : null;

if (!supabaseAtivado) {
  console.log('[Supabase não configurado — veja .env.example] usando arquivo local (não sobrevive a deploys).');
} else {
  console.log('[Supabase conectado] convites serão salvos de forma permanente.');
}

// --- Notificação por e-mail para os noivos (via Gmail) ---
const nodemailer = require('nodemailer');
const { EMAIL_USER, EMAIL_PASSWORD, COUPLE_EMAILS } = process.env;
const emailAtivado = EMAIL_USER && EMAIL_PASSWORD && COUPLE_EMAILS;
const emailTransporter = emailAtivado
  ? nodemailer.createTransport({ service: 'gmail', auth: { user: EMAIL_USER, pass: EMAIL_PASSWORD } })
  : null;
const emailsNoivos = emailAtivado ? COUPLE_EMAILS.split(',').map((e) => e.trim()).filter(Boolean) : [];

// --- Notificação por SMS para os noivos (via Twilio, opcional) ---
const { TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER, COUPLE_PHONE_NUMBERS } = process.env;
const smsAtivado = TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN && TWILIO_FROM_NUMBER && COUPLE_PHONE_NUMBERS;
const twilioClient = smsAtivado ? require('twilio')(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN) : null;
const numerosNoivos = smsAtivado ? COUPLE_PHONE_NUMBERS.split(',').map((n) => n.trim()).filter(Boolean) : [];

async function notificarNoivos(assunto, mensagem) {
  if (!emailAtivado && !smsAtivado) {
    console.log('[Notificação não configurada — veja .env.example] ' + assunto + ' | ' + mensagem);
    return;
  }

  if (emailAtivado) {
    try {
      await emailTransporter.sendMail({
        from: EMAIL_USER,
        to: emailsNoivos.join(','),
        subject: assunto,
        text: mensagem,
      });
    } catch (err) {
      console.error('Falha ao enviar e-mail:', err.message);
    }
  }

  if (smsAtivado) {
    for (const numero of numerosNoivos) {
      try {
        await twilioClient.messages.create({ body: mensagem, from: TWILIO_FROM_NUMBER, to: numero });
      } catch (err) {
        console.error(`Falha ao enviar SMS para ${numero}:`, err.message);
      }
    }
  }
}

// Edite os dados do casamento aqui:
const WEDDING = {
  noivos: 'Gabriel & Bianca',
  data: '2026-11-07',
  local: 'Igreja do Carmo - Cidade Velha',
  horario: '16h00',
};

async function readConvites() {
  if (supabaseAtivado) {
    const { data, error } = await supabase
      .from('app_dados')
      .select('valor')
      .eq('chave', 'convites')
      .maybeSingle();
    if (error) {
      console.error('Erro ao ler convites do Supabase:', error.message);
      return [];
    }
    return data?.valor || [];
  }

  if (!fs.existsSync(DATA_FILE)) return [];
  const raw = fs.readFileSync(DATA_FILE, 'utf-8').trim();
  return raw ? JSON.parse(raw) : [];
}

async function writeConvites(list) {
  if (supabaseAtivado) {
    const { error } = await supabase
      .from('app_dados')
      .upsert({ chave: 'convites', valor: list });
    if (error) console.error('Erro ao salvar convites no Supabase:', error.message);
    return;
  }

  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  fs.writeFileSync(DATA_FILE, JSON.stringify(list, null, 2), 'utf-8');
}

function gerarToken() {
  return crypto.randomBytes(5).toString('hex');
}

// --- Autenticação do painel dos noivos (login por cookie de sessão) ---
const { ADMIN_USER, ADMIN_PASSWORD } = process.env;
const SESSION_COOKIE = 'casorio_sessao';
const SESSION_DURACAO_MS = 7 * 24 * 60 * 60 * 1000; // 7 dias

function compararSeguro(a, b) {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function segredoSessao() {
  return crypto.createHash('sha256').update(`${ADMIN_USER}:${ADMIN_PASSWORD}`).digest();
}

function criarTokenSessao() {
  const payload = Buffer.from(JSON.stringify({ exp: Date.now() + SESSION_DURACAO_MS })).toString('base64url');
  const assinatura = crypto.createHmac('sha256', segredoSessao()).update(payload).digest('base64url');
  return `${payload}.${assinatura}`;
}

function tokenSessaoValido(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return false;
  const [payload, assinatura] = token.split('.');
  const esperada = crypto.createHmac('sha256', segredoSessao()).update(payload).digest('base64url');
  if (!compararSeguro(assinatura, esperada)) return false;
  try {
    const dados = JSON.parse(Buffer.from(payload, 'base64url').toString('utf-8'));
    return typeof dados.exp === 'number' && dados.exp > Date.now();
  } catch {
    return false;
  }
}

function lerCookies(req) {
  const header = req.headers.cookie || '';
  const cookies = {};
  header.split(';').forEach((par) => {
    const [chave, ...resto] = par.trim().split('=');
    if (chave) cookies[chave] = decodeURIComponent(resto.join('='));
  });
  return cookies;
}

function exigirAutenticacao(req, res, next) {
  if (!ADMIN_USER || !ADMIN_PASSWORD) {
    return res.status(503).send('Painel indisponível: configure ADMIN_USER e ADMIN_PASSWORD nas variáveis de ambiente do servidor.');
  }

  const cookies = lerCookies(req);
  if (tokenSessaoValido(cookies[SESSION_COOKIE])) {
    return next();
  }

  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ error: 'Sessão expirada ou inválida. Faça login novamente.' });
  }
  res.redirect('/login');
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/convite/:token', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'convite.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/api/login', (req, res) => {
  if (!ADMIN_USER || !ADMIN_PASSWORD) {
    return res.status(503).json({ error: 'Painel indisponível: configure ADMIN_USER e ADMIN_PASSWORD.' });
  }
  const { usuario, senha, manterConectado } = req.body || {};
  if (
    typeof usuario === 'string' && typeof senha === 'string' &&
    compararSeguro(usuario, ADMIN_USER) && compararSeguro(senha, ADMIN_PASSWORD)
  ) {
    const opcoesCookie = {
      httpOnly: true,
      sameSite: 'lax',
      secure: req.protocol === 'https' || req.headers['x-forwarded-proto'] === 'https',
    };
    // Sem maxAge = cookie de sessão: some quando o navegador é fechado por completo.
    if (manterConectado === true) {
      opcoesCookie.maxAge = SESSION_DURACAO_MS;
    }
    res.cookie(SESSION_COOKIE, criarTokenSessao(), opcoesCookie);
    return res.json({ ok: true });
  }
  res.status(401).json({ error: 'Usuário ou senha incorretos.' });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie(SESSION_COOKIE);
  res.json({ ok: true });
});

app.get('/admin', exigirAutenticacao, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/api/config', (req, res) => {
  res.json(WEDDING);
});

// --- Rotas do convidado (via token, sem login) ---

app.get('/api/convite/:token', async (req, res) => {
  const convites = await readConvites();
  const convite = convites.find((c) => c.token === req.params.token);
  if (!convite) return res.status(404).json({ error: 'Convite não encontrado.' });
  res.json(convite);
});

app.post('/api/convite/:token/confirmar', async (req, res) => {
  const convites = await readConvites();
  const convite = convites.find((c) => c.token === req.params.token);
  if (!convite) return res.status(404).json({ error: 'Convite não encontrado.' });

  const { respostas, mensagem } = req.body || {};
  if (!Array.isArray(respostas)) {
    return res.status(400).json({ error: 'Respostas inválidas.' });
  }

  const idsValidos = new Set(convite.pessoas.map((p) => p.id));
  for (const r of respostas) {
    if (!idsValidos.has(r.id) || typeof r.vai !== 'boolean') {
      return res.status(400).json({ error: 'Resposta inválida.' });
    }
  }

  const mudancas = [];
  respostas.forEach((r) => {
    const pessoa = convite.pessoas.find((p) => p.id === r.id);
    if (pessoa.vai !== r.vai) {
      mudancas.push({ nome: pessoa.nome, vai: r.vai });
    }
    pessoa.vai = r.vai;
  });

  convite.mensagem = typeof mensagem === 'string' ? mensagem.trim().slice(0, 500) : (convite.mensagem || '');
  convite.confirmadoEm = new Date().toISOString();

  await writeConvites(convites);
  res.json({ ok: true, convite });

  if (mudancas.length > 0) {
    let confirmados = 0, naoVao = 0, pendentes = 0;
    convites.forEach((c) => c.pessoas.forEach((p) => {
      if (p.vai === true) confirmados++;
      else if (p.vai === false) naoVao++;
      else pendentes++;
    }));

    mudancas.forEach((m) => {
      const assunto = m.vai
        ? `✅ ${m.nome} confirmou presença — ${convite.titulo}`
        : `❌ ${m.nome} avisou que não vai — ${convite.titulo}`;
      const texto = m.vai
        ? `🔔 RSVP: ${m.nome} confirmou presença! ✅ (${convite.titulo})`
        : `🔔 RSVP: ${m.nome} avisou que não poderá comparecer. ❌ (${convite.titulo})`;
      notificarNoivos(assunto, `${texto}\nTotal: ${confirmados} confirmados, ${naoVao} não vão, ${pendentes} pendentes.`);
    });
  }
});

// --- Rotas do admin (casal) ---

app.use('/api/admin', exigirAutenticacao);

app.get('/api/admin/convites', async (req, res) => {
  res.json(await readConvites());
});

app.get('/api/admin/backup', async (req, res) => {
  const dataFormatada = new Date().toISOString().slice(0, 10);
  res.setHeader('Content-Disposition', `attachment; filename="rsvp-backup-${dataFormatada}.json"`);
  res.json(await readConvites());
});

app.post('/api/admin/restore', async (req, res) => {
  const convites = req.body;
  if (!Array.isArray(convites)) {
    return res.status(400).json({ error: 'Arquivo de backup inválido.' });
  }
  const valido = convites.every((c) =>
    typeof c.token === 'string' && typeof c.titulo === 'string' && Array.isArray(c.pessoas)
  );
  if (!valido) {
    return res.status(400).json({ error: 'Arquivo de backup inválido.' });
  }
  await writeConvites(convites);
  res.json({ ok: true, total: convites.length });
});

app.post('/api/admin/convites', async (req, res) => {
  const { titulo, nomes, telefone } = req.body || {};

  if (typeof titulo !== 'string' || !titulo.trim()) {
    return res.status(400).json({ error: 'Título do convite é obrigatório.' });
  }
  if (!Array.isArray(nomes) || nomes.length === 0 || nomes.some((n) => typeof n !== 'string' || !n.trim())) {
    return res.status(400).json({ error: 'Informe ao menos um nome válido.' });
  }

  const convites = await readConvites();

  let token;
  do {
    token = gerarToken();
  } while (convites.some((c) => c.token === token));

  const novoConvite = {
    token,
    titulo: titulo.trim(),
    pessoas: nomes.map((nome, i) => ({
      id: `${token}-${i}`,
      nome: nome.trim(),
      vai: null,
    })),
    mensagem: '',
    telefone: typeof telefone === 'string' ? telefone.trim() : '',
    criadoEm: new Date().toISOString(),
    confirmadoEm: null,
  };

  convites.push(novoConvite);
  await writeConvites(convites);

  res.status(201).json(novoConvite);
});

app.delete('/api/admin/convites/:token', async (req, res) => {
  const convites = await readConvites();
  const filtrado = convites.filter((c) => c.token !== req.params.token);
  if (filtrado.length === convites.length) {
    return res.status(404).json({ error: 'Convite não encontrado.' });
  }
  await writeConvites(filtrado);
  res.json({ ok: true });
});

app.listen(PORT, async () => {
  console.log(`RSVP rodando em http://localhost:${PORT}`);

  if (supabaseAtivado) {
    const { error } = await supabase.from('app_dados').select('chave').limit(1);
    if (error) {
      console.error('[Supabase] Falha ao conectar/consultar a tabela app_dados:', error.message);
      console.error('[Supabase] Confira se a tabela foi criada e se SUPABASE_URL/SUPABASE_SERVICE_KEY estão corretos.');
    } else {
      console.log('[Supabase] Conexão testada com sucesso — tabela app_dados acessível.');
    }
  }
});

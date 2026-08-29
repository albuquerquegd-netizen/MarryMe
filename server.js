require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data', 'convites.json');

// --- Notificação por SMS para os noivos (via Twilio) ---
const { TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER, COUPLE_PHONE_NUMBERS } = process.env;
const smsAtivado = TWILIO_ACCOUNT_SID && TWILIO_AUTH_TOKEN && TWILIO_FROM_NUMBER && COUPLE_PHONE_NUMBERS;
const twilioClient = smsAtivado ? require('twilio')(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN) : null;
const numerosNoivos = smsAtivado ? COUPLE_PHONE_NUMBERS.split(',').map((n) => n.trim()).filter(Boolean) : [];

async function notificarNoivos(mensagem) {
  if (!smsAtivado) {
    console.log('[SMS não configurado — veja .env.example] ' + mensagem);
    return;
  }
  for (const numero of numerosNoivos) {
    try {
      await twilioClient.messages.create({ body: mensagem, from: TWILIO_FROM_NUMBER, to: numero });
    } catch (err) {
      console.error(`Falha ao enviar SMS para ${numero}:`, err.message);
    }
  }
}

// Edite os dados do casamento aqui:
const WEDDING = {
  noivos: 'Ana & João',
  data: '2026-11-14',
  local: 'Espaço Jardim das Flores, São Paulo',
  horario: '17h00',
};

function readConvites() {
  if (!fs.existsSync(DATA_FILE)) return [];
  const raw = fs.readFileSync(DATA_FILE, 'utf-8').trim();
  return raw ? JSON.parse(raw) : [];
}

function writeConvites(list) {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  fs.writeFileSync(DATA_FILE, JSON.stringify(list, null, 2), 'utf-8');
}

function gerarToken() {
  return crypto.randomBytes(5).toString('hex');
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/convite/:token', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'convite.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/api/config', (req, res) => {
  res.json(WEDDING);
});

// --- Rotas do convidado (via token, sem login) ---

app.get('/api/convite/:token', (req, res) => {
  const convites = readConvites();
  const convite = convites.find((c) => c.token === req.params.token);
  if (!convite) return res.status(404).json({ error: 'Convite não encontrado.' });
  res.json(convite);
});

app.post('/api/convite/:token/confirmar', (req, res) => {
  const convites = readConvites();
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

  writeConvites(convites);
  res.json({ ok: true, convite });

  if (mudancas.length > 0) {
    let confirmados = 0, naoVao = 0, pendentes = 0;
    convites.forEach((c) => c.pessoas.forEach((p) => {
      if (p.vai === true) confirmados++;
      else if (p.vai === false) naoVao++;
      else pendentes++;
    }));

    mudancas.forEach((m) => {
      const texto = m.vai
        ? `🔔 RSVP: ${m.nome} confirmou presença! ✅ (${convite.titulo})`
        : `🔔 RSVP: ${m.nome} avisou que não poderá comparecer. ❌ (${convite.titulo})`;
      notificarNoivos(`${texto}\nTotal: ${confirmados} confirmados, ${naoVao} não vão, ${pendentes} pendentes.`);
    });
  }
});

// --- Rotas do admin (casal) ---

app.get('/api/admin/convites', (req, res) => {
  res.json(readConvites());
});

app.get('/api/admin/backup', (req, res) => {
  const dataFormatada = new Date().toISOString().slice(0, 10);
  res.setHeader('Content-Disposition', `attachment; filename="rsvp-backup-${dataFormatada}.json"`);
  res.json(readConvites());
});

app.post('/api/admin/restore', (req, res) => {
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
  writeConvites(convites);
  res.json({ ok: true, total: convites.length });
});

app.post('/api/admin/convites', (req, res) => {
  const { titulo, nomes, telefone } = req.body || {};

  if (typeof titulo !== 'string' || !titulo.trim()) {
    return res.status(400).json({ error: 'Título do convite é obrigatório.' });
  }
  if (!Array.isArray(nomes) || nomes.length === 0 || nomes.some((n) => typeof n !== 'string' || !n.trim())) {
    return res.status(400).json({ error: 'Informe ao menos um nome válido.' });
  }

  const convites = readConvites();

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
  writeConvites(convites);

  res.status(201).json(novoConvite);
});

app.delete('/api/admin/convites/:token', (req, res) => {
  const convites = readConvites();
  const filtrado = convites.filter((c) => c.token !== req.params.token);
  if (filtrado.length === convites.length) {
    return res.status(404).json({ error: 'Convite não encontrado.' });
  }
  writeConvites(filtrado);
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`RSVP rodando em http://localhost:${PORT}`);
});

const express = require('express');
const cors    = require('cors');
const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL     = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

const app = express();
app.use(cors());
app.use(express.json());

// ── Helper: cliente autenticado por token ──
function db(token) {
  return createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    global: { headers: { Authorization: `Bearer ${token}` } }
  });
}

// ── Middleware de autenticação ──
async function autenticar(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer '))
    return res.status(401).json({ ok: false, erro: 'Faça login primeiro.' });
  const token = auth.split(' ')[1];
  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (error || !user)
    return res.status(401).json({ ok: false, erro: 'Sessão expirada. Faça login novamente.' });
  req.user  = user;
  req.token = token;
  next();
}

function erro(res, msg, status = 500) {
  res.status(status).json({ ok: false, erro: msg });
}

function requireParams(req, res, ...params) {
  const missing = params.filter(p => !req.query[p]);
  if (missing.length) {
    res.status(400).json({ ok: false, erro: `Parâmetro(s) obrigatório(s): ${missing.join(', ')}` });
    return false;
  }
  return true;
}

// ════════════════════════════════
// ROTAS PÚBLICAS
// ════════════════════════════════

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, status: 'online', db: 'supabase' });
});

app.post('/api/auth/registro', async (req, res) => {
  const { nome, email, senha } = req.body || {};
  if (!nome || !email || !senha)
    return erro(res, 'Campos obrigatórios: nome, email, senha', 400);
  if (senha.length < 6)
    return erro(res, 'A senha deve ter no mínimo 6 caracteres.', 400);

  const { data, error } = await supabase.auth.signUp({
    email, password: senha, options: { data: { nome } }
  });
  if (error) return erro(res, error.message, 400);

  res.status(201).json({
    ok: true,
    mensagem: 'Conta criada com sucesso! Faça login para continuar.',
    usuario: { id: data.user.id, email: data.user.email, nome }
  });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, senha } = req.body || {};
  if (!email || !senha) return erro(res, 'Informe e-mail e senha.', 400);

  const { data, error } = await supabase.auth.signInWithPassword({
    email, password: senha
  });
  if (error) return erro(res, 'E-mail ou senha incorretos.', 401);

  res.json({
    ok: true,
    mensagem: 'Login realizado!',
    token:         data.session.access_token,
    refresh_token: data.session.refresh_token,
    expira_em:     data.session.expires_at,
    usuario: {
      id:    data.user.id,
      email: data.user.email,
      nome:  data.user.user_metadata?.nome || email.split('@')[0]
    }
  });
});

app.post('/api/auth/recuperar-senha', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return erro(res, 'E-mail obrigatório.', 400);
  const { error } = await supabase.auth.resetPasswordForEmail(email);
  if (error) return erro(res, error.message);
  res.json({ ok: true, mensagem: 'E-mail de recuperação enviado!' });
});

// ════════════════════════════════
// ROTAS PROTEGIDAS — AUTH
// ════════════════════════════════

app.post('/api/auth/logout', autenticar, async (req, res) => {
  const client = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    global: { headers: { Authorization: `Bearer ${req.token}` } }
  });
  await client.auth.signOut();
  res.json({ ok: true, mensagem: 'Logout realizado.' });
});

app.get('/api/auth/perfil', autenticar, async (req, res) => {
  const { data, error } = await db(req.token)
    .from('perfis').select('*').eq('id', req.user.id).single();
  if (error) return erro(res, error.message);
  res.json({ ok: true, perfil: data });
});

// ════════════════════════════════
// ROTAS PROTEGIDAS — PEÇAS
// ════════════════════════════════

app.get('/api/marcas', autenticar, async (req, res) => {
  const { data, error } = await db(req.token)
    .from('pecas_compativeis').select('montadora').order('montadora');
  if (error) return erro(res, error.message);
  const marcas = [...new Set(data.map(r => r.montadora))];
  res.json({ ok: true, total: marcas.length, dados: marcas });
});

app.get('/api/modelos', autenticar, async (req, res) => {
  if (!requireParams(req, res, 'marca')) return;
  const { data, error } = await db(req.token)
    .from('pecas_compativeis').select('carro')
    .ilike('montadora', req.query.marca).order('carro');
  if (error) return erro(res, error.message);
  const modelos = [...new Set(data.map(r => r.carro))];
  if (!modelos.length) return erro(res, `Nenhum modelo para "${req.query.marca}"`, 404);
  res.json({ ok: true, dados: modelos });
});

app.get('/api/anos', autenticar, async (req, res) => {
  if (!requireParams(req, res, 'marca', 'modelo')) return;
  const { data, error } = await db(req.token)
    .from('pecas_compativeis').select('ano')
    .ilike('montadora', req.query.marca)
    .ilike('carro', req.query.modelo).order('ano');
  if (error) return erro(res, error.message);
  const anos = [...new Set(data.map(r => r.ano))];
  if (!anos.length) return erro(res, 'Nenhum ano encontrado.', 404);
  res.json({ ok: true, dados: anos });
});

app.get('/api/pecas', autenticar, async (req, res) => {
  if (!requireParams(req, res, 'marca', 'modelo', 'ano')) return;
  const { data, error } = await db(req.token)
    .from('pecas_compativeis')
    .select('id,peca_nome,codigo_referencia,fabricante,preco_original,preco_equivalente,economia_percentual,carro_equivalente_barato')
    .ilike('montadora', req.query.marca)
    .ilike('carro', req.query.modelo)
    .eq('ano', req.query.ano)
    .order('peca_nome');
  if (error) return erro(res, error.message);
  if (!data.length) return erro(res, 'Nenhuma peça encontrada.', 404);

  const agrupado = {};
  for (const r of data) {
    if (!agrupado[r.peca_nome]) {
      agrupado[r.peca_nome] = { peca_nome: r.peca_nome, codigo_referencia: r.codigo_referencia, fabricantes: [] };
    }
    agrupado[r.peca_nome].fabricantes.push({
      id: r.id, fabricante: r.fabricante,
      preco_original: r.preco_original, preco_equivalente: r.preco_equivalente,
      economia_percentual: r.economia_percentual, carro_equivalente_barato: r.carro_equivalente_barato
    });
  }
  res.json({ ok: true, dados: Object.values(agrupado) });
});

app.get('/api/buscar', autenticar, async (req, res) => {
  if (!requireParams(req, res, 'marca', 'modelo', 'ano', 'peca')) return;
  const { marca, modelo, ano, peca } = req.query;
  const client = db(req.token);

  const { data: origem, error: e1 } = await client
    .from('pecas_compativeis')
    .select('codigo_referencia,peca_nome,fabricante,preco_original')
    .ilike('montadora', marca).ilike('carro', modelo)
    .eq('ano', ano).ilike('peca_nome', peca)
    .limit(1).single();
  if (e1) return erro(res, `Peça "${peca}" não encontrada para ${marca} ${modelo} ${ano}.`, 404);

  const { data: todos, error: e2 } = await client
    .from('pecas_compativeis').select('*')
    .eq('codigo_referencia', origem.codigo_referencia)
    .order('preco_original');
  if (e2) return erro(res, e2.message);

  const veicConsultado = todos.find(r =>
    r.montadora.toLowerCase() === marca.toLowerCase() &&
    r.carro.toLowerCase()     === modelo.toLowerCase() &&
    r.ano === ano
  );
  const maisBarato  = todos[0];
  const precoMax    = Math.max(...todos.map(r => parseFloat(r.preco_original)));
  const economiaMax = (((precoMax - maisBarato.preco_original) / precoMax) * 100).toFixed(1);

  res.json({
    ok: true,
    consulta: { veiculo: `${marca} ${modelo} ${ano}`, peca: origem.peca_nome, codigo_referencia: origem.codigo_referencia },
    resumo: {
      total_veiculos_compativeis:  todos.length,
      preco_no_veiculo_consultado: veicConsultado?.preco_original ?? null,
      preco_mais_barato:           maisBarato.preco_original,
      veiculo_mais_barato:         `${maisBarato.montadora} ${maisBarato.carro} ${maisBarato.ano}`,
      economia_maxima_percentual:  parseFloat(economiaMax),
      dica: `Compre a peça ${origem.codigo_referencia} (${maisBarato.fabricante}) pedindo pelo ${maisBarato.carro} ${maisBarato.ano} e economize até ${economiaMax}%.`
    },
    resultados: todos.map(r => ({
      ...r,
      e_veiculo_consultado: r.montadora.toLowerCase()===marca.toLowerCase() && r.carro.toLowerCase()===modelo.toLowerCase() && r.ano===ano,
      e_mais_barato: r.id === maisBarato.id
    }))
  });
});

app.get('/api/buscar-codigo', autenticar, async (req, res) => {
  if (!requireParams(req, res, 'codigo')) return;
  const { data, error } = await db(req.token)
    .from('pecas_compativeis').select('*')
    .eq('codigo_referencia', req.query.codigo).order('preco_original');
  if (error) return erro(res, error.message);
  if (!data.length) return erro(res, `Código "${req.query.codigo}" não encontrado.`, 404);
  res.json({ ok: true, codigo_referencia: req.query.codigo, peca_nome: data[0].peca_nome, total_veiculos: data.length, mais_barato: data[0], todos: data });
});

app.get('/api/stats', autenticar, async (req, res) => {
  const { data, error } = await db(req.token)
    .from('pecas_compativeis').select('montadora,economia_percentual,codigo_referencia');
  if (error) return erro(res, error.message);
  const porMarca = {}, codigos = new Set();
  let totalEco = 0, maxEco = 0;
  for (const r of data) {
    porMarca[r.montadora] = (porMarca[r.montadora] || 0) + 1;
    const eco = parseFloat(r.economia_percentual);
    totalEco += eco; if (eco > maxEco) maxEco = eco;
    codigos.add(r.codigo_referencia);
  }
  res.json({
    ok: true,
    totais: { total_registros: data.length, total_marcas: Object.keys(porMarca).length, total_codigos_unicos: codigos.size, economia_media_percentual: parseFloat((totalEco/data.length).toFixed(1)), maior_economia_percentual: maxEco },
    por_marca: Object.entries(porMarca).map(([m,c])=>({montadora:m,pecas:c})).sort((a,b)=>b.pecas-a.pecas)
  });
});

module.exports = app;

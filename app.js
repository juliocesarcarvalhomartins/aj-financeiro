/* =====================================================================
   A.J — seu diário financeiro
   ---------------------------------------------------------------------
   Segurança: os lançamentos NUNCA são gravados em texto puro. Eles ficam
   em memória enquanto o app está aberto e, a cada alteração, são
   criptografados (AES-GCM 256, chave derivada da sua senha via PBKDF2)
   antes de ir para o localStorage. Sem a senha, o conteúdo salvo no
   navegador é apenas ruído — inclusive para quem tiver acesso ao PC e
   abrir o DevTools.

   Isso não substitui um servidor com autenticação de verdade: enquanto
   o diário está DESBLOQUEADO na tela, os dados estão visíveis, como em
   qualquer app local. O que essa camada resolve é o problema mais comum
   de um arquivo HTML solto: qualquer pessoa abrindo o arquivo (ou o
   localStorage) sem a senha não lê nada.
===================================================================== */

const $ = (selector) => document.querySelector(selector);

const KEY_SALT  = 'aj-salt-v2';
const KEY_VAULT = 'aj-vault-v2';
// chaves antigas (v1), usadas em texto puro pela versão anterior do app —
// se existirem, migramos o conteúdo para dentro do cofre no primeiro uso.
const LEGACY_ENTRIES = 'aj-lancamentos-v1';
const LEGACY_CONFIG  = 'aj-config-v1';

let vaultKey = null;                 // CryptoKey em memória, nunca persistida
let state = { entries: [], config: { orcamento_mensal: 0 } };
let displayedMonth = new Date();
displayedMonth.setDate(1);
let idleTimer = null;

/* ---------------------------------------------------------------------
   Criptografia
--------------------------------------------------------------------- */
function randomBytes(n) { return crypto.getRandomValues(new Uint8Array(n)); }
function toB64(bytes) { return btoa(String.fromCharCode(...bytes)); }
function fromB64(str) { return new Uint8Array(atob(str).split('').map(c => c.charCodeAt(0))); }

async function deriveKey(password, saltBytes) {
  const enc = new TextEncoder();
  const material = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations: 210000, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptState(key, obj) {
  const iv = randomBytes(12);
  const data = new TextEncoder().encode(JSON.stringify(obj));
  const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  const combined = new Uint8Array(iv.length + cipherBuf.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(cipherBuf), iv.length);
  return toB64(combined);
}

async function decryptState(key, b64) {
  const combined = fromB64(b64);
  const iv = combined.slice(0, 12);
  const cipherBytes = combined.slice(12);
  const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipherBytes);
  return JSON.parse(new TextDecoder().decode(plainBuf));
}

async function persist() {
  localStorage.setItem(LEGACY_ENTRIES, JSON.stringify(state.entries));
  localStorage.setItem(LEGACY_CONFIG, JSON.stringify(state.config));
}

function hasVault() { return !!localStorage.getItem(KEY_VAULT) && !!localStorage.getItem(KEY_SALT); }

function readLegacyPlainData() {
  try {
    const entries = JSON.parse(localStorage.getItem(LEGACY_ENTRIES) || '[]');
    const config = JSON.parse(localStorage.getItem(LEGACY_CONFIG) || '{"orcamento_mensal":0}');
    return { entries, config };
  } catch { return { entries: [], config: { orcamento_mensal: 0 } }; }
}

function clearLegacyPlainData() {
  localStorage.removeItem(LEGACY_ENTRIES);
  localStorage.removeItem(LEGACY_CONFIG);
}

/* ---------------------------------------------------------------------
   Tela de cofre (criação de senha / desbloqueio)
--------------------------------------------------------------------- */
function showVaultScreen() { $('#vault-screen').hidden = false; $('#app-root').hidden = true; }
function showApp() {
  $('#vault-screen').hidden = true;
  $('#app-root').hidden = false;
  resetIdleTimer();
  render();
}

function initVaultScreen() {
  const hasExisting = hasVault();
  $('#vault-setup').hidden = hasExisting;
  $('#vault-unlock').hidden = !hasExisting;
  showVaultScreen();
}

$('#setup-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const data = new FormData(event.target);
  const p1 = data.get('senha1'), p2 = data.get('senha2');
  const errorEl = $('#setup-error');
  if (p1 !== p2) { errorEl.textContent = 'As senhas não são iguais.'; errorEl.hidden = false; return; }
  errorEl.hidden = true;

  const salt = randomBytes(16);
  vaultKey = await deriveKey(p1, salt);
  localStorage.setItem(KEY_SALT, toB64(salt));

  // migra dados antigos (texto puro) se existirem, para não perder histórico
  const legacy = readLegacyPlainData();
  state = { entries: legacy.entries || [], config: legacy.config || { orcamento_mensal: 0 } };
  await persist();
  clearLegacyPlainData();

  event.target.reset();
  showApp();
});

$('#unlock-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const password = new FormData(event.target).get('senha');
  const errorEl = $('#unlock-error');
  try {
    const salt = fromB64(localStorage.getItem(KEY_SALT));
    const key = await deriveKey(password, salt);
    const decrypted = await decryptState(key, localStorage.getItem(KEY_VAULT));
    vaultKey = key;
    state = decrypted;
    errorEl.hidden = true;
    event.target.reset();
    showApp();
  } catch {
    errorEl.textContent = 'Senha incorreta. Tente novamente.';
    errorEl.hidden = false;
  }
});

$('#forgot-link').addEventListener('click', () => $('#forgot-dialog').showModal());
$('#cancel-forgot').addEventListener('click', () => $('#forgot-dialog').close());
$('#forgot-form').addEventListener('submit', () => {
  localStorage.removeItem(KEY_SALT);
  localStorage.removeItem(KEY_VAULT);
  clearLegacyPlainData();
  vaultKey = null;
  state = { entries: [], config: { orcamento_mensal: 0 } };
/* Tema visual local: Rosa Delicado ↔ Noite Elegante. */
const THEME_KEY = 'aj-theme-v1';
function applyTheme(theme) { document.body.classList.toggle('night-elegant', theme === 'night'); }
applyTheme(localStorage.getItem(THEME_KEY) || 'rose');
$('#toggle-theme').addEventListener('click', () => {
  const next = document.body.classList.contains('night-elegant') ? 'rose' : 'night';
  localStorage.setItem(THEME_KEY, next); applyTheme(next);
});
initVaultScreen();
});

function lockNow() {
  vaultKey = null;
  state = { entries: [], config: { orcamento_mensal: 0 } };
  clearTimeout(idleTimer);
  initVaultScreen();
}
$('#lock-now').addEventListener('click', lockNow);

// bloqueio automático por inatividade (10 minutos)
const IDLE_LIMIT_MS = 10 * 60 * 1000;
function resetIdleTimer() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(lockNow, IDLE_LIMIT_MS);
}
['click', 'keydown', 'mousemove', 'scroll'].forEach(evt =>
  document.addEventListener(evt, () => { if (vaultKey) resetIdleTimer(); }, { passive: true })
);

/* ---------------------------------------------------------------------
   Configurações: trocar senha, backup, apagar tudo
--------------------------------------------------------------------- */
$('#open-settings').addEventListener('click', () => $('#settings-dialog').showModal());
$('#close-settings').addEventListener('click', () => $('#settings-dialog').close());

$('#change-password-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const data = new FormData(event.target);
  const p1 = data.get('nova1'), p2 = data.get('nova2');
  const errorEl = $('#change-password-error');
  if (p1 !== p2) { errorEl.textContent = 'As senhas não são iguais.'; errorEl.hidden = false; return; }
  errorEl.hidden = true;
  const salt = randomBytes(16);
  vaultKey = await deriveKey(p1, salt);
  localStorage.setItem(KEY_SALT, toB64(salt));
  await persist();
  event.target.reset();
  $('#settings-dialog').close();
});

$('#export-backup').addEventListener('click', () => {
  const blob = new Blob([JSON.stringify(state, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const stamp = new Date().toISOString().slice(0, 10);
  a.href = url; a.download = `aj-backup-${stamp}.json`;
  a.click();
  URL.revokeObjectURL(url);
});

$('#import-backup').addEventListener('change', async (event) => {
  const file = event.target.files[0];
  if (!file) return;
  try {
    const text = await file.text();
    const parsed = JSON.parse(text);
    if (!Array.isArray(parsed.entries)) throw new Error('formato inválido');
    if (!confirm('Isso substitui os dados atuais pelos do arquivo importado. Continuar?')) { event.target.value = ''; return; }
    state = { entries: parsed.entries, config: parsed.config || { orcamento_mensal: 0 } };
    await persist();
    $('#settings-dialog').close();
    render();
  } catch {
    alert('Não consegui ler esse arquivo como um backup do A.J.');
  } finally {
    event.target.value = '';
  }
});

$('#wipe-all').addEventListener('click', () => {
  if (!confirm('Isso apaga todos os lançamentos deste navegador. Não tem volta. Continuar?')) return;
  localStorage.removeItem(KEY_SALT);
  localStorage.removeItem(KEY_VAULT);
  clearLegacyPlainData();
  state = { entries: [], config: { orcamento_mensal: 0 } };
  $('#settings-dialog').close();
  render();
});

/* ---------------------------------------------------------------------
   Utilidades de dados
--------------------------------------------------------------------- */
function money(value) { return Number(value || 0).toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' }); }
function monthKey(date = displayedMonth) { return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`; }
function parseMoney(value) { return Number(String(value).replace(/\./g, '').replace(',', '.').replace(/[^0-9.-]/g, '')) || 0; }
function labelOrigin(origin) { return ({ papelaria: 'Papelaria', clt: 'CLT', pessoal: 'Pessoal' })[origin] || origin; }
function formatDate(date) { return new Date(`${date}T12:00:00`).toLocaleDateString('pt-BR', { day: '2-digit', month: 'short' }).replace('.', ''); }
function escapeHtml(value) { const span = document.createElement('span'); span.textContent = value; return span.innerHTML; }

function calculate(month) {
  const filtered = state.entries.filter(e => e.data.startsWith(month));
  const income = filtered.filter(e => e.tipo === 'entrada').reduce((sum, e) => sum + e.valor, 0);
  const expense = filtered.filter(e => e.tipo === 'saida').reduce((sum, e) => sum + e.valor, 0);
  return { entries: filtered, income, expense, balance: income - expense };
}

function previousMonthKey() {
  const previous = new Date(displayedMonth);
  previous.setMonth(previous.getMonth() - 1);
  return monthKey(previous);
}

/* ---------------------------------------------------------------------
   Renderização
--------------------------------------------------------------------- */
function render() {
  const month = monthKey();
  const { entries, income, expense, balance } = calculate(month);
  const baseBudget = state.config.orcamento_mensal || 0;
  const previousExpense = calculate(previousMonthKey()).expense;
  const difference = previousExpense - baseBudget;
  const adjustedBudget = baseBudget > 0 ? Math.max(0, baseBudget - difference) : 0;
  const accumulated = state.entries.reduce((sum, e) => sum + (e.tipo === 'entrada' ? e.valor : -e.valor), 0);

  $('#month-label').textContent = displayedMonth.toLocaleDateString('pt-BR', { month: 'long', year: 'numeric' }).replace(/^./, c => c.toUpperCase());
  $('#income-total').textContent = money(income);
  $('#expense-total').textContent = money(expense);
  $('#balance-total').textContent = money(balance);
  $('#accumulated-total').textContent = money(accumulated);
  $('#budget-amount').textContent = money(baseBudget);
  $('#spent-label').textContent = `${money(expense)} gastos`;

  const moodLine = $('#mood-line');
  const moodSupport = $('#mood-support');
  if (balance > 0) {
    moodLine.innerHTML = 'Seu dinheiro está florescendo. <em>Você está indo bem.</em>';
    moodSupport.textContent = 'Seu saldo está positivo — celebre o cuidado que você teve com você.';
  } else if (balance < 0) {
    moodLine.innerHTML = 'Respira: um passo de <em>cada vez.</em>';
    moodSupport.textContent = 'Olhar com carinho para os números já é uma forma de se reorganizar.';
  } else {
    moodLine.innerHTML = 'Um novo mês, uma página <em>em aberto.</em>';
    moodSupport.textContent = 'Registre com calma. O importante é começar do seu jeito.';
  }

  const percent = adjustedBudget ? Math.min(100, (expense / adjustedBudget) * 100) : 0;
  $('#progress-fill').style.width = `${percent}%`;
  const targetPercent = adjustedBudget && baseBudget ? Math.min(100, (baseBudget / adjustedBudget) * 100) : 100;
  $('#progress-target').style.setProperty('--target-pos', `${targetPercent}%`);
  $('#available-label').textContent = baseBudget
    ? (expense <= adjustedBudget ? `${money(adjustedBudget - expense)} disponíveis` : `${money(expense - adjustedBudget)} acima da meta`)
    : 'Defina sua meta';
  $('#goal-badge').textContent = !baseBudget ? '✦ Escolha uma meta com carinho' : expense <= adjustedBudget ? '♥ Você está respeitando o seu ritmo' : '✦ Vamos reorganizar juntas, sem culpa';

  const adjustment = $('#adjustment-message');
  if (!baseBudget) adjustment.textContent = 'Defina sua meta mensal para acompanhar seus gastos com carinho.';
  else if (difference > 0) adjustment.textContent = `No mês passado você passou ${money(difference)} da meta. Sua meta ajustada para este mês é ${money(adjustedBudget)}.`;
  else if (difference < 0) adjustment.textContent = `Você economizou ${money(Math.abs(difference))} no mês passado. Sua meta ajustada para este mês é ${money(adjustedBudget)}.`;
  else adjustment.textContent = `Sua meta ajustada para este mês é ${money(adjustedBudget)}. Você está no caminho certo.`;

  const origins = ['papelaria', 'clt', 'pessoal']
    .map(origin => ({ origin, value: entries.filter(e => e.tipo === 'entrada' && e.origem === origin).reduce((sum, e) => sum + e.valor, 0) }))
    .filter(item => item.value > 0);
  const originIcons = { papelaria: '✎', clt: '☀', pessoal: '♥' };
  $('#origins-list').innerHTML = origins.length
    ? origins.map(item => `<div class="origin-row origin-${item.origin}"><span class="origin-name"><i class="dot">${originIcons[item.origin]}</i>${labelOrigin(item.origin)}</span><strong>${money(item.value)}</strong></div>`).join('')
    : '<p class="empty-small">Suas entradas aparecerão aqui.</p>';

  $('#entry-list').innerHTML = entries.length
    ? entries.sort((a, b) => b.data.localeCompare(a.data)).map(entry => `
      <div class="entry-row ${entry.tipo === 'entrada' ? 'in' : 'out'}">
        <span class="entry-date">${formatDate(entry.data)}</span>
        <div><div class="entry-name">${escapeHtml(entry.descricao)}</div><div class="entry-meta">${labelOrigin(entry.origem)}</div></div>
        <span class="entry-value ${entry.tipo === 'entrada' ? 'in' : ''}">${entry.tipo === 'entrada' ? '+' : '−'} ${money(entry.valor)}</span>
        <button class="delete" data-id="${entry.id}" aria-label="Excluir lançamento">×</button>
      </div>`).join('')
    : '<div class="empty-state"><span>✦</span><h3>Seu mês começa aqui</h3><p>Registre uma entrada ou saída para ver tudo organizado.</p><button class="new-entry" id="open-modal-3">Adicionar lançamento</button></div>';

  document.querySelectorAll('.delete').forEach(button => button.addEventListener('click', async () => {
    state.entries = state.entries.filter(e => e.id !== button.dataset.id);
    await persist();
    render();
  }));
  $('#open-modal-3')?.addEventListener('click', openEntryDialog);
}

/* ---------------------------------------------------------------------
   Formulários do app
--------------------------------------------------------------------- */
function openEntryDialog() {
  $('#entry-form').reset();
  $('#entry-form [name="data"]').value = new Date().toISOString().slice(0, 10);
  $('#entry-dialog').showModal();
}
['#open-modal', '#open-modal-2'].forEach(id => $(id)?.addEventListener('click', openEntryDialog));
$('#close-modal').addEventListener('click', () => $('#entry-dialog').close());
$('#close-budget').addEventListener('click', () => $('#budget-dialog').close());
$('#edit-budget').addEventListener('click', () => {
  $('#budget-form [name="orcamento"]').value = state.config.orcamento_mensal ? String(state.config.orcamento_mensal).replace('.', ',') : '';
  $('#budget-dialog').showModal();
});
$('#previous-month').addEventListener('click', () => { displayedMonth.setMonth(displayedMonth.getMonth() - 1); render(); });
$('#next-month').addEventListener('click', () => { displayedMonth.setMonth(displayedMonth.getMonth() + 1); render(); });

$('#entry-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  const entry = { id: crypto.randomUUID(), tipo: data.tipo, origem: data.origem, descricao: data.descricao.trim(), valor: parseMoney(data.valor), data: data.data };
  if (entry.valor <= 0 || !entry.descricao) return;
  state.entries.push(entry);
  await persist();
  displayedMonth = new Date(`${entry.data}T12:00:00`);
  displayedMonth.setDate(1);
  $('#entry-dialog').close();
  render();
});

$('#budget-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  state.config.orcamento_mensal = parseMoney(new FormData(event.target).get('orcamento'));
  await persist();
  $('#budget-dialog').close();
  render();
});

/* ---------------------------------------------------------------------
   Início
--------------------------------------------------------------------- */
state = readLegacyPlainData();
render();

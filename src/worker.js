import { SCHEMA, DEFAULT_SETTINGS } from "./schema.js";

/* ---------- util ---------- */
class ApiError extends Error { constructor(msg, code = 400) { super(msg); this.code = code; } }
const toInt = (v, d = 0) => { const n = Math.round(parseFloat(v)); return Number.isFinite(n) ? n : d; };
const J = (o, status = 200, extra = {}) => new Response(JSON.stringify(o), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...extra } });
const WIB = 7 * 3600e3; // semua tanggal memakai WIB
const nowIso = () => new Date(Date.now() + WIB).toISOString().slice(0, 19).replace("T", " ");
const todayWib = () => nowIso().slice(0, 10);
// tanggal yang dipilih admin/kasir (YYYY-MM-DD) dipakai sebagai tanggal transaksi; jamnya mengikuti jam sekarang
function stampFor(d) {
  if (!d) return nowIso();
  d = String(d).slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d) || isNaN(Date.parse(d))) throw new ApiError("Format tanggal tidak valid");
  if (d > todayWib()) throw new ApiError("Tanggal tidak boleh di masa depan");
  return d + nowIso().slice(10);
}
const addDays = (ymd, n) => new Date(Date.parse(ymd + "T00:00:00Z") + n * 864e5).toISOString().slice(0, 10);
const SESSION_DAYS = 30, MAX_FAILS = 5, LOCK_SECONDS = 300, PBKDF2_ITER = 100000;

const all = async (env, sql, ...a) => (await env.DB.prepare(sql).bind(...a).all()).results;
const one = (env, sql, ...a) => env.DB.prepare(sql).bind(...a).first();
const run = (env, sql, ...a) => env.DB.prepare(sql).bind(...a).run();
const st = (env, sql, ...a) => env.DB.prepare(sql).bind(...a);

/* ---------- password ---------- */
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
async function hashPw(pw, salt = hex(crypto.getRandomValues(new Uint8Array(8)))) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: new TextEncoder().encode(salt), iterations: PBKDF2_ITER }, key, 256);
  return `${salt}$${hex(bits)}`;
}
async function checkPw(pw, stored) {
  const salt = String(stored).split("$")[0];
  const h = await hashPw(pw, salt);
  if (h.length !== stored.length) return false;
  let d = 0; for (let i = 0; i < h.length; i++) d |= h.charCodeAt(i) ^ stored.charCodeAt(i);
  return d === 0;
}

/* ---------- init (buat tabel + akun admin pertama) ---------- */
let initP = null;
function ensureInit(env) {
  if (!initP) initP = (async () => {
    await env.DB.batch(SCHEMA.map(s => env.DB.prepare(s)));
    for (const t of ["products", "order_items"]) { // migrasi database lama: tambah kolom kode produk
      const cols = (await all(env, `PRAGMA table_info(${t})`)).map(r => r.name);
      if (!cols.includes("code")) await run(env, `ALTER TABLE ${t} ADD COLUMN code TEXT NOT NULL DEFAULT ''`);
    }
    const oiCols = (await all(env, "PRAGMA table_info(order_items)")).map(r => r.name);
    if (!oiCols.includes("inv_id")) await run(env, "ALTER TABLE order_items ADD COLUMN inv_id INTEGER");
    const oCols = (await all(env, "PRAGMA table_info(orders)")).map(r => r.name);
    for (const [col, def] of [["done_at", "TEXT"], ["tracking", "TEXT NOT NULL DEFAULT ''"], ["refund", "INTEGER NOT NULL DEFAULT 0"]]) if (!oCols.includes(col)) await run(env, `ALTER TABLE orders ADD COLUMN ${col} ${def}`);
    const eCols = (await all(env, "PRAGMA table_info(expenses)")).map(r => r.name);
    if (!eCols.includes("incident_id")) await run(env, "ALTER TABLE expenses ADD COLUMN incident_id INTEGER");
    await run(env, "INSERT OR IGNORE INTO settings(key,value) SELECT 'gate_id', CAST(COALESCE(MAX(id),0) AS TEXT) FROM orders"); // order lama (sebelum aturan laba-saat-selesai) tetap diakui saat lunas
    await env.DB.batch(Object.entries(DEFAULT_SETTINGS).map(([k, v]) => st(env, "INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", k, JSON.stringify(v))));
    if (!(await one(env, "SELECT id FROM customers LIMIT 1"))) await run(env, "INSERT INTO customers(name,phone) VALUES('Umum','')");
    if (!(await one(env, "SELECT id FROM users LIMIT 1")) && env.ADMIN_PASSWORD) {
      await run(env, "INSERT INTO users(username,name,password,role,must_change) VALUES('admin','Administrator',?,'admin',0)", await hashPw(String(env.ADMIN_PASSWORD)));
    }
  })().catch(e => { initP = null; throw e; });
  return initP;
}

async function getSettings(env) {
  const s = { ...DEFAULT_SETTINGS };
  for (const r of await all(env, "SELECT key,value FROM settings")) { try { s[r.key] = JSON.parse(r.value); } catch { } }
  return s;
}

/* ---------- auth ---------- */
async function authUser(env, token) {
  if (!token) return null;
  const cutoff = new Date(Date.now() + WIB - SESSION_DAYS * 864e5).toISOString().slice(0, 19).replace("T", " ");
  return await one(env, "SELECT u.id,u.username,u.name,u.role,u.must_change FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND u.active=1 AND s.created_at>?", token, cutoff);
}

async function hLogin(c) {
  const { env, body: b } = c;
  const username = String(b.username || "").trim();
  const key = `${c.ip}|${username.toLowerCase()}`;
  const rec = await one(env, "SELECT n,locked_until FROM login_fails WHERE k=?", key);
  const now = Math.floor(Date.now() / 1000);
  if (rec && rec.locked_until > now) throw new ApiError(`Terlalu banyak percobaan login. Coba lagi dalam ${rec.locked_until - now + 1} detik.`, 429);
  if (!(await one(env, "SELECT id FROM users LIMIT 1"))) throw new ApiError("Akun admin belum dibuat. Isi ADMIN_PASSWORD di pengaturan Cloudflare, lalu muat ulang halaman.", 503);
  const u = await one(env, "SELECT * FROM users WHERE username=? AND active=1", username);
  if (!u || !(await checkPw(String(b.password || ""), u.password))) {
    const n = ((rec && rec.n) || 0) + 1;
    await run(env, "INSERT OR REPLACE INTO login_fails(k,n,locked_until) VALUES(?,?,?)", key, n >= MAX_FAILS ? 0 : n, n >= MAX_FAILS ? now + LOCK_SECONDS : 0);
    throw new ApiError("Username atau password salah", 401);
  }
  await run(env, "DELETE FROM login_fails WHERE k=?", key);
  const cutoff = new Date(Date.now() + WIB - SESSION_DAYS * 864e5).toISOString().slice(0, 19).replace("T", " ");
  await run(env, "DELETE FROM sessions WHERE created_at<?", cutoff);
  const token = hex(crypto.getRandomValues(new Uint8Array(24)));
  await run(env, "INSERT INTO sessions(token,user_id,created_at) VALUES(?,?,?)", token, u.id, nowIso());
  return { token, user: { id: u.id, username: u.username, name: u.name, role: u.role, must_change: u.must_change } };
}
const hLogout = async c => { await run(c.env, "DELETE FROM sessions WHERE token=?", c.token); return { ok: true }; };
const SECRET_KEYS = ["pay_people", "capital_pct"];
const hidePrivate = s => { for (const k of SECRET_KEYS) delete s[k]; return s; };
const hPublicSettings = async c => hidePrivate(await getSettings(c.env));
const hBootstrap = async c => ({
  user: c.user, poll: 30, settings: c.user.role === "admin" ? await getSettings(c.env) : hidePrivate(await getSettings(c.env)),
  products: await all(c.env, "SELECT * FROM products WHERE active=1 ORDER BY category,name"),
  customers: await all(c.env, "SELECT * FROM customers ORDER BY name"),
});

/* ---------- produk ---------- */
const hProductsList = c => all(c.env, "SELECT * FROM products ORDER BY active DESC, category, name");
function productPayload(b) {
  const name = String(b.name || "").trim();
  if (!name) throw new ApiError("Nama produk wajib diisi");
  const stock = b.stock === null || b.stock === undefined || b.stock === "" ? null : toInt(b.stock);
  const p = [name, String(b.category || "Umum").trim() || "Umum", Math.max(0, toInt(b.price)), Math.max(0, toInt(b.cost)), Math.max(0, toInt(b.dp)), stock, (b.active ?? 1) ? 1 : 0, String(b.country || "").trim().slice(0, 30), String(b.code || "").trim().toUpperCase().slice(0, 30)];
  if (p[4] > p[2]) throw new ApiError("DP tidak boleh lebih besar dari harga");
  return p;
}
async function dupCheck(env, p, selfId) {
  const d = await one(env, "SELECT id FROM products WHERE lower(name)=lower(?) AND code=? AND id<>?", p[0], p[8], selfId || 0);
  if (d) throw new ApiError("Produk dengan kode dan deskripsi yang sama sudah ada di master. Kalau beda kode, silakan isi kodenya.");
}
async function hProductDedupe(c) {
  const dups = await all(c.env, "SELECT p.id, (SELECT MIN(id) FROM products q WHERE lower(q.name)=lower(p.name) AND q.code=p.code) AS keep FROM products p");
  const gone = dups.filter(d => d.id !== d.keep);
  const stmts = [];
  for (const d of gone) { stmts.push(st(c.env, "UPDATE order_items SET product_id=? WHERE product_id=?", d.keep, d.id)); stmts.push(st(c.env, "DELETE FROM products WHERE id=?", d.id)); }
  if (stmts.length) await c.env.DB.batch(stmts);
  return { removed: gone.length };
}
async function hProductCreate(c) {
  await dupCheck(c.env, productPayload(c.body));
  const r = await run(c.env, "INSERT INTO products(name,category,price,cost,dp,stock,active,country,code) VALUES(?,?,?,?,?,?,?,?,?)", ...productPayload(c.body));
  return await one(c.env, "SELECT * FROM products WHERE id=?", r.meta.last_row_id);
}
async function hProductUpdate(c, id) {
  await dupCheck(c.env, productPayload(c.body), id);
  await run(c.env, "UPDATE products SET name=?,category=?,price=?,cost=?,dp=?,stock=?,active=?,country=?,code=? WHERE id=?", ...productPayload(c.body), id);
  const r = await one(c.env, "SELECT * FROM products WHERE id=?", id);
  if (!r) throw new ApiError("Produk tidak ditemukan", 404);
  return r;
}
const hProductDelete = async (c, id) => { await run(c.env, "DELETE FROM products WHERE id=?", id); return { ok: true }; };

/* ---------- pelanggan ---------- */
const hCustomersList = c => all(c.env, `SELECT cu.*, COALESCE(s.cnt,0) AS orders, COALESCE(s.total,0) AS spent FROM customers cu LEFT JOIN (SELECT customer_id, COUNT(*) cnt, SUM(total) total FROM orders WHERE status!='batal' GROUP BY customer_id) s ON s.customer_id=cu.id ORDER BY cu.name`);
function customerPayload(b) {
  const name = String(b.name || "").trim();
  if (!name) throw new ApiError("Nama pelanggan wajib diisi");
  return [name, String(b.phone || "").trim(), String(b.address || "").trim(), String(b.note || "").trim()];
}
async function hCustomerCreate(c) {
  const r = await run(c.env, "INSERT INTO customers(name,phone,address,note) VALUES(?,?,?,?)", ...customerPayload(c.body));
  return await one(c.env, "SELECT * FROM customers WHERE id=?", r.meta.last_row_id);
}
async function hCustomerUpdate(c, id) {
  await run(c.env, "UPDATE customers SET name=?,phone=?,address=?,note=? WHERE id=?", ...customerPayload(c.body), id);
  const r = await one(c.env, "SELECT * FROM customers WHERE id=?", id);
  if (!r) throw new ApiError("Pelanggan tidak ditemukan", 404);
  return r;
}
const hCustomerDelete = async (c, id) => { await run(c.env, "DELETE FROM customers WHERE id=?", id); return { ok: true }; };

/* ---------- inventory (stok ready stock, direkap manual) ---------- */
const invClean = (c, rows) => rows;
const LEGACY_BASE = "oi.inv_id IS NULL AND o.status!='batal'";
// order lama yang cocok: kode sama (deskripsi boleh beda ejaan); kalau kode kosong, deskripsi harus sama persis
const legacyMatch = code => code ? { w: `${LEGACY_BASE} AND oi.code=?`, a: [code] } : { w: `${LEGACY_BASE} AND oi.code='' AND lower(oi.name)=lower(?)`, a: [] };
function invPayload(b) {
  const name = String(b.name || "").split(/\s+/).filter(Boolean).join(" ");
  if (!name) throw new ApiError("Deskripsi produk wajib diisi");
  return { name, code: String(b.code || "").trim().toUpperCase().slice(0, 30), country: String(b.country || "").trim().slice(0, 30), cost: Math.max(0, toInt(b.cost)), price: Math.max(0, toInt(b.price)), note: String(b.note || "").trim() };
}
const hInvList = async c => invClean(c, await all(c.env, `SELECT i.*, (SELECT COALESCE(SUM(oi.qty),0) FROM order_items oi JOIN orders o ON o.id=oi.order_id WHERE ${LEGACY_BASE} AND ((i.code<>'' AND oi.code=i.code) OR (i.code='' AND oi.code='' AND lower(oi.name)=lower(i.name)))) AS legacy_qty FROM inventory i WHERE i.active=1 ORDER BY i.name, i.code`));
// order Ready Stock lama (sebelum ada inventory) yang cocok, dikelompokkan per deskripsi yang pernah diketik
async function legacyVariants(env, name, code) {
  const m = legacyMatch(code), args = code ? m.a : [name];
  const rows = await all(env, `SELECT MIN(oi.name) name, (o.type='Ready Stock') ready, COUNT(DISTINCT o.id) orders, SUM(oi.qty) qty FROM order_items oi JOIN orders o ON o.id=oi.order_id WHERE ${m.w} GROUP BY lower(oi.name), ready ORDER BY ready DESC, qty DESC`, ...args);
  return rows.map(r => ({ ...r, ready: !!r.ready, key: r.name.toLowerCase() + "|" + (r.ready ? 1 : 0), exact: r.name.toLowerCase() === name.toLowerCase() }));
}
async function hInvLegacy(c) {
  const name = String(c.query.get("name") || "").trim(), code = String(c.query.get("code") || "").trim().toUpperCase();
  if (!name && !code) return { variants: [] };
  return { variants: await legacyVariants(c.env, name, code) };
}
async function hInvLinkOld(c, id) {
  const iv = await one(c.env, "SELECT * FROM inventory WHERE id=?", id);
  if (!iv) throw new ApiError("Item tidak ditemukan", 404);
  const all_ = await legacyVariants(c.env, iv.name, iv.code);
  const pick = new Set((Array.isArray(c.body.names) ? c.body.names : all_.filter(v => v.exact && v.ready).map(v => v.key)).map(n => String(n).toLowerCase()));
  const m = legacyMatch(iv.code), args = iv.code ? m.a : [iv.name];
  const rows = (await all(c.env, `SELECT oi.id, oi.qty, oi.order_id oid, lower(oi.name) || '|' || (o.type='Ready Stock') n FROM order_items oi JOIN orders o ON o.id=oi.order_id WHERE ${m.w}`, ...args)).filter(r => pick.has(r.n));
  if (!rows.length) throw new ApiError("Tidak ada order Ready Stock lama yang dipilih");
  const sold = rows.reduce((a, r) => a + r.qty, 0);
  if (sold > iv.qty) throw new ApiError(`Stok di Inventory (${iv.qty}) lebih kecil dari yang sudah terjual di order lama (${sold}). Tambah stok dulu lewat ± Stok.`);
  const ids = rows.map(r => Number(r.id)).join(","), oids = [...new Set(rows.map(r => Number(r.oid)))].join(",");
  await c.env.DB.batch([
    st(c.env, `UPDATE order_items SET inv_id=?, cost=CASE WHEN cost=0 THEN ? ELSE cost END, country=CASE WHEN country='' THEN ? ELSE country END${c.body.rename ? ", name=?, code=?" : ""} WHERE id IN (${ids})`, id, iv.cost, iv.country, ...(c.body.rename ? [iv.name, iv.code] : [])),
    // order yang semua barisnya kini dari inventory otomatis menjadi jenis Ready Stock
    st(c.env, `UPDATE orders SET type='Ready Stock' WHERE id IN (${oids}) AND NOT EXISTS (SELECT 1 FROM order_items x WHERE x.order_id=orders.id AND x.inv_id IS NULL)`),
    st(c.env, "UPDATE inventory SET qty=qty-? WHERE id=?", sold, id),
    st(c.env, "INSERT INTO inv_moves(inv_id,delta,reason,ref,created_at) VALUES(?,?,?,?,?)", id, -sold, "tarik order lama", c.user.name, nowIso()),
  ]);
  return { linked: rows.length, qty: sold };
}

async function hInvCreate(c) {
  const v = invPayload(c.body), qty = Math.max(0, toInt(c.body.qty));
  if (await one(c.env, "SELECT id FROM inventory WHERE lower(name)=lower(?) AND code=? AND active=1", v.name, v.code)) throw new ApiError("Produk dengan kode dan deskripsi yang sama sudah ada di inventory. Pakai tombol ± Stok untuk menambah jumlahnya.");
  await c.env.DB.batch([
    st(c.env, "INSERT INTO inventory(code,name,country,qty,cost,price,note,active) VALUES(?,?,?,?,?,?,?,1)", v.code, v.name, v.country, qty, v.cost, v.price, v.note),
    st(c.env, "INSERT INTO inv_moves(inv_id,delta,reason,ref,created_at) VALUES((SELECT MAX(id) FROM inventory),?,?,?,?)", qty, "stok awal", c.user.name, nowIso()),
  ]);
  return await one(c.env, "SELECT * FROM inventory WHERE id=(SELECT MAX(id) FROM inventory)");
}
async function hInvUpdate(c, id) {
  const v = invPayload(c.body);
  if (await one(c.env, "SELECT id FROM inventory WHERE lower(name)=lower(?) AND code=? AND active=1 AND id<>?", v.name, v.code, id)) throw new ApiError("Produk dengan kode dan deskripsi yang sama sudah ada di inventory.");
  await run(c.env, "UPDATE inventory SET code=?,name=?,country=?,cost=?,price=?,note=? WHERE id=?", v.code, v.name, v.country, v.cost, v.price, v.note, id);
  const r = await one(c.env, "SELECT * FROM inventory WHERE id=?", id);
  if (!r) throw new ApiError("Item tidak ditemukan", 404);
  return r;
}
async function hInvStock(c, id) {
  const r = await one(c.env, "SELECT * FROM inventory WHERE id=?", id);
  if (!r) throw new ApiError("Item tidak ditemukan", 404);
  const delta = toInt(c.body.delta); if (!delta) throw new ApiError("Isi jumlah stok yang ditambah atau dikurangi");
  if (r.qty + delta < 0) throw new ApiError(`Stok tidak cukup (sisa ${r.qty})`);
  const newCost = Math.max(0, toInt(c.body.cost)), reason = String(c.body.reason || (delta > 0 ? "tambah stok" : "koreksi")).slice(0, 60);
  await c.env.DB.batch([
    st(c.env, "UPDATE inventory SET qty=qty+?, cost=CASE WHEN ?>0 THEN ? ELSE cost END WHERE id=?", delta, newCost, newCost, id),
    st(c.env, "INSERT INTO inv_moves(inv_id,delta,reason,ref,created_at) VALUES(?,?,?,?,?)", id, delta, reason, c.user.name, nowIso()),
  ]);
  return await one(c.env, "SELECT * FROM inventory WHERE id=?", id);
}
async function hInvDelete(c, id) { await run(c.env, "UPDATE inventory SET active=0 WHERE id=?", id); return { ok: true }; }
async function hInvMoves(c, id) { return all(c.env, "SELECT * FROM inv_moves WHERE inv_id=? ORDER BY id DESC LIMIT 100", id); }

// baris order: boleh dari inventory (ready stock) atau diketik manual (jastip)
async function buildLines(env, items, type, oldItems = []) {
  let subtotal = 0, dpTarget = 0; const lines = [], need = {};
  const ready = type === "Ready Stock";
  for (const it of items) {
    const invId = toInt(it.inv_id) || null;
    if (ready && !invId && !oldItems.some(o => !o.inv_id && String(o.name).toLowerCase() === String(it.name || "").trim().toLowerCase() && (o.code || "") === String(it.code || "").trim().toUpperCase())) throw new ApiError("Order Ready Stock hanya bisa dari produk Inventory");
    let name = String(it.name || "").split(/\s+/).filter(Boolean).join(" "), code = String(it.code || "").trim().toUpperCase().slice(0, 30), country = String(it.country || "").trim().slice(0, 30), cost = Math.max(0, toInt(it.cost));
    if (invId) {
      const iv = await one(env, "SELECT * FROM inventory WHERE id=?", invId);
      if (!iv) throw new ApiError("Produk inventory tidak ditemukan");
      name = iv.name; code = iv.code; country = iv.country; cost = iv.cost;
      need[invId] = (need[invId] || 0) + Math.max(1, toInt(it.qty, 1));
    }
    if (!name) throw new ApiError("Nama produk wajib diisi");
    const qty = Math.max(1, toInt(it.qty, 1)), price = Math.max(0, toInt(it.price)), dp = Math.max(0, toInt(it.dp));
    if (dp > price) throw new ApiError(`DP untuk ${name} tidak boleh lebih besar dari harganya`);
    lines.push({ name, price, dp, cost, qty, note: String(it.note || "").trim(), country, code, inv_id: invId });
    subtotal += price * qty; dpTarget += dp * qty;
  }
  for (const [id, q] of Object.entries(need)) {
    const iv = await one(env, "SELECT name,qty FROM inventory WHERE id=?", id);
    const back = oldItems.filter(o => o.inv_id == id).reduce((a, o) => a + o.qty, 0);
    if (q > iv.qty + back) throw new ApiError(`Stok ${iv.name} tidak cukup (tersedia ${iv.qty + back}, diminta ${q})`);
  }
  return { lines, subtotal, dpTarget };
}
const restoreStmts = (env, items, ref, reason) => items.filter(i => i.inv_id).flatMap(i => [
  st(env, "UPDATE inventory SET qty=qty+? WHERE id=?", i.qty, i.inv_id),
  st(env, "INSERT INTO inv_moves(inv_id,delta,reason,ref,created_at) VALUES(?,?,?,?,?)", i.inv_id, i.qty, reason, ref, nowIso()),
]);
function itemStmts(env, l, oidSql, oidArg, ref) {
  if (l.inv_id) return [
    st(env, `INSERT INTO order_items(order_id,product_id,name,price,dp,cost,qty,note,country,code,inv_id) VALUES(${oidSql},NULL,?,?,?,?,?,?,?,?,?)`, oidArg, l.name, l.price, l.dp, l.cost, l.qty, l.note, l.country, l.code, l.inv_id),
    st(env, "UPDATE inventory SET qty=qty-? WHERE id=?", l.qty, l.inv_id),
    st(env, "INSERT INTO inv_moves(inv_id,delta,reason,ref,created_at) VALUES(?,?,?,?,?)", l.inv_id, -l.qty, "order", ref, nowIso()),
  ];
  return [
    st(env, "UPDATE products SET price=?,dp=?,cost=?,active=1,country=CASE WHEN country='' THEN ? ELSE country END WHERE lower(name)=lower(?) AND code=?", l.price, l.dp, l.cost, l.country, l.name, l.code),
    st(env, "INSERT INTO products(name,category,price,cost,dp,stock,active,country,code) SELECT ?,'Umum',?,?,?,NULL,1,?,? WHERE NOT EXISTS(SELECT 1 FROM products WHERE lower(name)=lower(?) AND code=?)", l.name, l.price, l.cost, l.dp, l.country, l.code, l.name, l.code),
    st(env, `INSERT INTO order_items(order_id,product_id,name,price,dp,cost,qty,note,country,code) VALUES(${oidSql},(SELECT id FROM products WHERE lower(name)=lower(?) AND code=? LIMIT 1),?,?,?,?,?,?,?,?)`, oidArg, l.name, l.code, l.name, l.price, l.dp, l.cost, l.qty, l.note, l.country, l.code),
  ];
}

/* ---------- order ---------- */
async function loadOrder(env, id) {
  const o = await one(env, "SELECT * FROM orders WHERE id=?", id);
  if (!o) throw new ApiError("Order tidak ditemukan", 404);
  o.items = await all(env, "SELECT * FROM order_items WHERE order_id=? ORDER BY id", id);
  o.payments = await all(env, "SELECT * FROM payments WHERE order_id=? ORDER BY id", id);
  o.remaining = o.total - o.paid_amount;
  return o;
}
// nama pelanggan yang diketik langsung otomatis masuk menu Pelanggan
async function ensureCustomer(env, name) {
  if (!name || name.toLowerCase() === "umum") return null;
  const ex = await one(env, "SELECT id FROM customers WHERE lower(name)=lower(?) ORDER BY id LIMIT 1", name);
  if (ex) return ex.id;
  const r = await run(env, "INSERT INTO customers(name,phone,address,note) VALUES(?,?,?,?)", name, "", "", "");
  return r.meta.last_row_id;
}
// ambil nama pelanggan dari riwayat order yang belum terhubung ke menu Pelanggan
async function hCustomersSync(c) {
  const rows = await all(c.env, "SELECT DISTINCT customer_name AS n FROM orders WHERE customer_id IS NULL AND trim(customer_name)<>'' AND lower(customer_name)<>'umum'");
  let added = 0;
  for (const r of rows) {
    const before = await one(c.env, "SELECT id FROM customers WHERE lower(name)=lower(?)", r.n);
    const id = await ensureCustomer(c.env, r.n.trim());
    if (!before) added++;
    await run(c.env, "UPDATE orders SET customer_id=? WHERE customer_id IS NULL AND lower(customer_name)=lower(?)", id, r.n);
  }
  return { added };
}
async function hOrdersList(c) {
  const q = c.query, date = q.get("date") || "today", search = (q.get("q") || "").trim();
  const where = [], args = [];
  if (date === "today") { where.push("date(created_at)=?"); args.push(todayWib()); }
  else if (date !== "all" && date !== "") { where.push("date(created_at)=?"); args.push(date); }
  if (search) { where.push("(number LIKE ? OR customer_name LIKE ?)"); args.push(`%${search}%`, `%${search}%`); }
  const w = where.length ? " WHERE " + where.join(" AND ") : "";
  const orders = await all(c.env, `SELECT * FROM orders${w} ORDER BY id DESC LIMIT 500`, ...args);
  const items = await all(c.env, `SELECT order_id,name,qty,country FROM order_items WHERE order_id IN (SELECT id FROM orders${w} ORDER BY id DESC LIMIT 500) ORDER BY id`, ...args);
  const by = {};
  for (const i of items) (by[i.order_id] ||= []).push(i);
  for (const o of orders) {
    const its = by[o.id] || [];
    o.item_count = its.reduce((a, i) => a + i.qty, 0);
    o.countries = [...new Set(its.map(i => i.country).filter(Boolean))].sort();
    o.preview = its.length ? its[0].name + (its.length > 1 ? ` +${its.length - 1} lainnya` : "") : "";
  }
  return orders;
}
async function hOrderGet(c, id) {
  const o = await loadOrder(c.env, id);
  const s = await getSettings(c.env);
  o.incidents = (await all(c.env, "SELECT * FROM incidents WHERE order_id=? ORDER BY id DESC", id)).map(r => incView(r, true));
  o.settings = Object.fromEntries(Object.entries(s).filter(([k]) => k.startsWith("store_") || k.startsWith("invoice_") || k === "currency" || k === "pay_info"));
  return o;
}
function paymentPlan(total, paidAmount, amount, method, cash) {
  const remaining = total - paidAmount;
  if (amount <= 0) throw new ApiError("Nominal pembayaran harus lebih dari 0");
  if (amount > remaining) throw new ApiError(`Pembayaran melebihi sisa tagihan (${remaining})`);
  if (method === "Tunai" && cash && cash < amount) throw new ApiError("Uang diterima kurang dari nominal yang dibayar");
  const kind = paidAmount === 0 ? (amount === remaining ? "bayar" : "dp") : (amount === remaining ? "pelunasan" : "cicilan");
  const newPaid = paidAmount + amount, full = newPaid >= total ? 1 : 0;
  return { kind, newPaid, full };
}
const paymentStmts = (env, oid, total, paidAmount, amount, method, cash, cashier, t = nowIso()) => {
  const p = paymentPlan(total, paidAmount, amount, method, cash);
  return [
    st(env, "INSERT INTO payments(order_id,amount,method,kind,cash_received,cashier,created_at) VALUES(?,?,?,?,?,?,?)", oid, amount, method, p.kind, method === "Tunai" ? cash : 0, cashier, t),
    st(env, "UPDATE orders SET paid_amount=?, paid=?, method=?, paid_at=CASE WHEN ?=1 THEN ? ELSE paid_at END WHERE id=?", p.newPaid, p.full, method, p.full, t, oid),
  ];
};
async function nextNumber(env, prefix, year = todayWib().slice(0, 4)) {
  const last = await one(env, "SELECT number FROM orders WHERE number LIKE ? ORDER BY id DESC LIMIT 1", `${prefix}-${year}-%`);
  let n = 1;
  if (last) { const x = parseInt(String(last.number).split("-").pop(), 10); n = Number.isFinite(x) ? x + 1 : 1; }
  return `${prefix}-${year}-${String(n).padStart(3, "0")}`;
}
async function hOrderCreate(c) {
  const { env, body: b } = c;
  const items = b.items || [];
  if (!items.length) throw new ApiError("Keranjang masih kosong");
  const s = await getSettings(env);
  const type = String(b.type || "Jastip");
  const { lines, subtotal, dpTarget } = await buildLines(env, items, type);
  const discount = Math.min(Math.max(0, toInt(b.discount)), subtotal);
  const taxable = subtotal - discount, tax = Math.round(taxable * (parseFloat(s.tax_percent) || 0) / 100), total = taxable + tax;
  let paidFull = !!b.paid, dp = paidFull ? 0 : Math.max(0, toInt(b.dp));
  if (dp > 0 && dp >= total) { paidFull = true; dp = 0; }
  const method = String(b.method || "Tunai"), cash = toInt(b.cash_received);
  let custId = b.customer_id || null, custName = "Umum";
  if (custId) { const cu = await one(env, "SELECT name FROM customers WHERE id=?", custId); if (cu) custName = cu.name; else custId = null; }
  if (b.customer_name && !custId) { custName = String(b.customer_name).trim() || "Umum"; custId = await ensureCustomer(env, custName); }
  const note = String(b.note || "").trim(), cashier = c.user.name, stamp = stampFor(b.order_date);
  for (let attempt = 0; attempt < 4; attempt++) {
    const number = await nextNumber(env, s.invoice_prefix || "INV", stamp.slice(0, 4));
    const oidSql = "(SELECT id FROM orders WHERE number=?)";
    const stmts = [st(env, "INSERT INTO orders(number,customer_id,customer_name,type,status,paid,method,subtotal,discount,tax,total,cash_received,note,cashier,created_at,paid_at,dp_target) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
      number, custId, custName, type, "baru", 0, "", subtotal, discount, tax, total, 0, note, cashier, stamp, null, dpTarget)];
    for (const l of lines) stmts.push(...itemStmts(env, l, oidSql, number, number));
    try { await env.DB.batch(stmts); } catch (e) { if (/UNIQUE/i.test(String(e)) && attempt < 3) continue; throw e; }
    const oid = (await one(env, "SELECT id FROM orders WHERE number=?", number)).id;
    if (paidFull) {
      if (total > 0) await env.DB.batch(paymentStmts(env, oid, total, 0, total, method, cash, cashier, stamp));
      else await run(env, "UPDATE orders SET paid=1, paid_at=? WHERE id=?", stamp, oid);
    } else if (dp > 0) await env.DB.batch(paymentStmts(env, oid, total, 0, dp, method, cash, cashier, stamp));
    return loadOrder(env, oid);
  }
  throw new ApiError("Gagal membuat nomor invoice, coba lagi", 409);
}
async function hOrderUpdate(c, id) {
  const { env, body: b } = c;
  const o = await loadOrder(env, id);
  const status = b.status ?? o.status;
  if (!["baru", "dikerjakan", "siap", "selesai", "batal"].includes(status)) throw new ApiError("Status tidak valid");
  const stmts = [];
  let total = o.total;
  if (Array.isArray(b.items)) {
    // EDIT INVOICE: ganti isi item, pelanggan, tipe, diskon
    if (o.status === "batal") throw new ApiError("Order yang dibatalkan tidak bisa diedit");
    if (!b.items.length) throw new ApiError("Invoice harus punya minimal 1 produk");
    const s = await getSettings(env);
    const newType = String(b.type || o.type);
    const { lines, subtotal, dpTarget } = await buildLines(env, b.items, newType, o.items);
    const discount = Math.min(Math.max(0, toInt(b.discount)), subtotal);
    const taxable = subtotal - discount, tax = Math.round(taxable * (parseFloat(s.tax_percent) || 0) / 100);
    total = taxable + tax;
    if (total < o.paid_amount) throw new ApiError(`Total baru (${total}) lebih kecil dari yang sudah dibayar (${o.paid_amount}). Hapus/ubah pembayaran dulu.`);
    let custId = b.customer_id || null, custName = o.customer_name;
    if (custId) { const cu = await one(env, "SELECT name FROM customers WHERE id=?", custId); if (cu) custName = cu.name; else custId = null; }
    if (!custId) { custName = String(b.customer_name || "").trim() || "Umum"; custId = await ensureCustomer(env, custName); }
    const full = total > 0 && o.paid_amount >= total ? 1 : (total === 0 ? 1 : 0);
    stmts.push(...restoreStmts(env, o.items, o.number, "edit invoice"));
    stmts.push(st(env, "DELETE FROM order_items WHERE order_id=?", id));
    for (const l of lines) stmts.push(...itemStmts(env, l, "?", id, o.number));
    stmts.push(st(env, "UPDATE orders SET customer_id=?,customer_name=?,type=?,subtotal=?,discount=?,tax=?,total=?,dp_target=?,paid=?,paid_at=CASE WHEN ?=1 AND paid_at IS NULL THEN ? WHEN ?=0 THEN NULL ELSE paid_at END WHERE id=?",
      custId, custName, newType, subtotal, discount, tax, total, dpTarget, full, full, nowIso(), full, id));
  }
  if (b.pay_amount !== undefined && b.pay_amount !== null || b.paid) {
    if (o.status === "batal") throw new ApiError("Order sudah dibatalkan");
    const remaining = total - o.paid_amount;
    if (remaining <= 0) throw new ApiError("Order sudah lunas");
    const amount = b.pay_amount !== undefined && b.pay_amount !== null ? toInt(b.pay_amount) : remaining;
    stmts.push(...paymentStmts(env, id, total, o.paid_amount, amount, String(b.method || "Tunai"), toInt(b.cash_received), c.user.name, stampFor(b.pay_date)));
  }
  if (status === "batal" && o.status !== "batal") stmts.push(...restoreStmts(env, o.items, o.number, "order dibatalkan"));
  if (b.order_date && String(b.order_date).slice(0, 10) !== o.created_at.slice(0, 10)) {
    // pindahkan tanggal invoice; pembayaran & pelunasan yang tanggalnya sama dengan invoice ikut pindah
    const ns = stampFor(b.order_date), od = o.created_at.slice(0, 10);
    stmts.push(st(env, "UPDATE orders SET created_at=?, paid_at=CASE WHEN paid_at IS NOT NULL AND date(paid_at)=? THEN ? ELSE paid_at END WHERE id=?", ns, od, ns, id));
    stmts.push(st(env, "UPDATE payments SET created_at=? WHERE order_id=? AND date(created_at)=?", ns, id, od));
  }
  const note = "note" in b ? String(b.note).trim() : o.note;
  const tracking = "tracking" in b ? String(b.tracking || "").trim().slice(0, 120) : o.tracking;
  stmts.push(st(env, "UPDATE orders SET status=?,note=?,tracking=?,done_at=CASE WHEN ?='selesai' THEN COALESCE(done_at,?) ELSE NULL END WHERE id=?", status, note, tracking, status, nowIso(), id));
  await env.DB.batch(stmts);
  return loadOrder(env, id);
}
const hOrderDelete = async (c, id) => { const o = await loadOrder(c.env, id); await c.env.DB.batch([...(o.status !== "batal" ? restoreStmts(c.env, o.items, o.number, "invoice dihapus") : []), st(c.env, "DELETE FROM payments WHERE order_id=?", id), st(c.env, "DELETE FROM order_items WHERE order_id=?", id), st(c.env, "DELETE FROM orders WHERE id=?", id)]); return { ok: true }; };

/* ---------- pengeluaran ---------- */
async function hExpensesList(c) {
  const d1 = c.query.get("from") || "", d2 = c.query.get("to") || "";
  return d1 && d2 ? all(c.env, "SELECT * FROM expenses WHERE date BETWEEN ? AND ? ORDER BY date DESC, id DESC LIMIT 1000", d1, d2) : all(c.env, "SELECT * FROM expenses ORDER BY date DESC, id DESC LIMIT 1000");
}
async function hExpenseCreate(c) {
  const b = c.body, amount = toInt(b.amount);
  if (amount <= 0) throw new ApiError("Nominal harus lebih dari 0");
  const r = await run(c.env, "INSERT INTO expenses(date,category,description,amount,cashier) VALUES(?,?,?,?,?)", String(b.date || todayWib()), String(b.category || "Operasional"), String(b.description || "").trim(), amount, c.user.name);
  return await one(c.env, "SELECT * FROM expenses WHERE id=?", r.meta.last_row_id);
}
const hExpenseDelete = async (c, id) => { await run(c.env, "DELETE FROM expenses WHERE id=?", id); return { ok: true }; };

/* ---------- keuangan (admin): kas, laba, gaji, modal ---------- */
async function financeData(env, year) {
  const s = await getSettings(env);
  const people = (Array.isArray(s.pay_people) ? s.pay_people : []).map(p => ({ name: String(p.name), pct: Number(p.pct) || 0 }));
  const capPct = Number(s.capital_pct) || 0;
  const mapBy = rows => Object.fromEntries(rows.map(r => [r.m, r]));
  const gate = await one(env, "SELECT value FROM settings WHERE key='gate_id'");
  const G = gate ? +JSON.parse(gate.value) || 0 : 0;
  // laba diakui kalau order LUNAS dan sudah SELESAI (diterima customer); order lama (id <= G) cukup lunas
  const REC = `(o.paid=1 AND (o.id<=${G} OR o.status='selesai'))`;
  const RM = `CASE WHEN o.id<=${G} THEN COALESCE(o.paid_at,o.created_at) ELSE MAX(COALESCE(o.paid_at,o.created_at),COALESCE(o.done_at,'')) END`;
  const sales = mapBy(await all(env, `SELECT substr(${RM},1,7) m, COUNT(*) n, COALESCE(SUM(o.total-o.refund),0) rev, COALESCE(SUM(c.hpp),0) hpp FROM orders o LEFT JOIN (SELECT order_id, SUM(cost*qty) hpp FROM order_items GROUP BY order_id) c ON c.order_id=o.id WHERE o.status!='batal' AND ${REC} GROUP BY m`));
  const cash = mapBy(await all(env, `SELECT substr(p.created_at,1,7) m, COALESCE(SUM(p.amount),0) amt FROM payments p JOIN orders o ON o.id=p.order_id WHERE o.status!='batal' GROUP BY m`));
  const ops = mapBy(await all(env, "SELECT substr(date,1,7) m, COALESCE(SUM(amount),0) amt FROM expenses GROUP BY m"));
  const allMonths = [...new Set([...Object.keys(sales), ...Object.keys(ops)])];
  const netOf = m => (sales[m]?.rev || 0) - (sales[m]?.hpp || 0) - (ops[m]?.amt || 0);
  const cumNet = allMonths.reduce((a, m) => a + netOf(m), 0);
  const months = [];
  for (let i = 1; i <= 12; i++) {
    const m = `${year}-${String(i).padStart(2, "0")}`, rev = sales[m]?.rev || 0, hpp = sales[m]?.hpp || 0, op = ops[m]?.amt || 0, net = rev - hpp - op;
    months.push({ m, orders: sales[m]?.n || 0, cash_in: cash[m]?.amt || 0, rev, hpp, gross: rev - hpp, ops: op, net, shares: people.map(p => Math.round(net * (100 - capPct) / 100 * p.pct / 100)), capital_add: Math.round(Math.max(0, net) * capPct / 100) });
  }
  const capRows = await all(env, "SELECT * FROM capital ORDER BY date DESC, id DESC");
  const payRows = await all(env, "SELECT * FROM payroll ORDER BY date DESC, id DESC");
  const setoran = capRows.reduce((a, r) => a + r.amount, 0);
  const tambahModal = Math.round(Math.max(0, cumNet) * capPct / 100);
  const pool = Math.max(0, cumNet) - tambahModal;
  const payroll = people.map(p => { const hak = Math.round(pool * p.pct / 100), paid = payRows.filter(r => r.person === p.name).reduce((a, r) => a + r.amount, 0); return { ...p, hak, paid, sisa: hak - paid }; });
  const gajiDibayar = payRows.reduce((a, r) => a + r.amount, 0);
  const stok = (await one(env, "SELECT COALESCE(SUM(qty*cost),0) v FROM inventory WHERE active=1")).v;
  const open = await one(env, `SELECT COALESCE(SUM(o.paid_amount),0) dp, COALESCE(SUM(o.total-o.paid_amount),0) piutang, COUNT(*) n, COALESCE(SUM(CASE WHEN o.paid=1 THEN 1 ELSE 0 END),0) held_n, COALESCE(SUM(CASE WHEN o.paid=1 THEN o.total-o.refund ELSE 0 END),0) held FROM orders o WHERE o.status!='batal' AND NOT ${REC}`);
  const hppOpen = (await one(env, `SELECT COALESCE(SUM(oi.cost*oi.qty),0) v FROM order_items oi JOIN orders o ON o.id=oi.order_id WHERE o.status!='batal' AND NOT ${REC}`)).v;
  const noCost = (await one(env, "SELECT COUNT(*) n FROM order_items oi JOIN orders o ON o.id=oi.order_id WHERE o.status!='batal' AND oi.cost=0")).n;
  const kasLaba = cumNet - tambahModal - gajiDibayar;
  const modalTersedia = setoran + tambahModal - stok - hppOpen + open.dp + Math.min(0, kasLaba);
  const Y = `substr(${RM},1,4)=? AND o.status!='batal' AND ${REC}`;
  const by_country = await all(env, `SELECT CASE WHEN oi.country='' THEN '-' ELSE oi.country END country, SUM(oi.qty) qty, SUM(oi.price*oi.qty) revenue FROM order_items oi JOIN orders o ON o.id=oi.order_id WHERE ${Y} GROUP BY 1 ORDER BY revenue DESC`, String(year));
  const top = await all(env, `SELECT oi.code, oi.name, SUM(oi.qty) qty, SUM(oi.price*oi.qty) revenue FROM order_items oi JOIN orders o ON o.id=oi.order_id WHERE ${Y} GROUP BY oi.code, lower(oi.name) ORDER BY qty DESC LIMIT 8`, String(year));
  const inc = await one(env, "SELECT COUNT(DISTINCT incident_id) n, COALESCE(SUM(amount),0) total FROM expenses WHERE incident_id IS NOT NULL AND substr(date,1,4)=?", String(year));
  const years = [...new Set([String(year), ...allMonths.map(m => m.slice(0, 4))])].sort();
  return {
    year, years, people, capital_pct: capPct, months, by_country, top, capital: capRows, payments: payRows, payroll,
    pot: { setoran, tambah_modal: tambahModal, stok, hpp_open: hppOpen, dp_tertahan: open.dp, piutang: open.piutang, open_orders: open.n, held_orders: open.held_n, held_total: open.held, cum_net: cumNet, kas_laba: kasLaba, gaji_dibayar: gajiDibayar, modal_tersedia: modalTersedia, total_kas: modalTersedia + Math.max(0, kasLaba) },
    incidents: { count: inc.n, total: inc.total },
    warn: { no_cost: noCost },
  };
}
const hFinance = c => financeData(c.env, parseInt(c.query.get("year")) || parseInt(todayWib().slice(0, 4)));
async function hCapitalCreate(c) {
  const b = c.body, amount = toInt(b.amount); if (!amount) throw new ApiError("Nominal modal wajib diisi (boleh minus untuk penarikan)");
  await run(c.env, "INSERT INTO capital(date,party,amount,note) VALUES(?,?,?,?)", String(b.date || todayWib()), String(b.party || "").trim(), amount, String(b.note || "").trim());
  return { ok: true };
}
const hCapitalDelete = async (c, id) => { await run(c.env, "DELETE FROM capital WHERE id=?", id); return { ok: true }; };
async function hPayrollCreate(c) {
  const b = c.body, amount = toInt(b.amount); if (amount <= 0) throw new ApiError("Nominal gaji harus lebih dari 0");
  const person = String(b.person || "").trim(); if (!person) throw new ApiError("Pilih siapa yang menerima");
  await run(c.env, "INSERT INTO payroll(date,person,amount,note) VALUES(?,?,?,?)", String(b.date || todayWib()), person, amount, String(b.note || "").trim());
  return { ok: true };
}
const hPayrollDelete = async (c, id) => { await run(c.env, "DELETE FROM payroll WHERE id=?", id); return { ok: true }; };
// rekap order berbentuk tabel (satu baris per produk)
async function hOrderRows(c) {
  const t = todayWib(), d1 = c.query.get("from") || t.slice(0, 8) + "01", d2 = c.query.get("to") || t;
  const rows = await all(c.env, "SELECT o.id,o.number,o.created_at,o.customer_name,o.type,o.status,o.paid,o.paid_amount,o.total,oi.name,oi.code,oi.country,oi.qty,oi.price,oi.dp,oi.cost FROM orders o JOIN order_items oi ON oi.order_id=o.id WHERE date(o.created_at) BETWEEN ? AND ? ORDER BY o.id DESC, oi.id LIMIT 5000", d1, d2);
  return rows;
}

/* ---------- laporan ---------- */
async function reportData(env, d1, d2) {
  const P = "status!='batal' AND date(created_at) BETWEEN ? AND ?";
  const tot = await one(env, `SELECT COUNT(*) orders, COALESCE(SUM(total),0) revenue, COALESCE(SUM(paid_amount),0) paid_total, COALESCE(SUM(total-paid_amount),0) unpaid_total, COALESCE(SUM(CASE WHEN paid=0 AND paid_amount>0 THEN paid_amount ELSE 0 END),0) dp_total, COALESCE(SUM(discount),0) discount, COALESCE(SUM(tax),0) tax FROM orders WHERE ${P}`, d1, d2);
  const J2 = "FROM order_items oi JOIN orders o ON o.id=oi.order_id WHERE o.status!='batal' AND date(o.created_at) BETWEEN ? AND ?";
  const [cogsR, expR, daily, top, byCountry, methods, cashiers] = await Promise.all([
    one(env, `SELECT COALESCE(SUM(oi.cost*oi.qty),0) v ${J2}`, d1, d2),
    one(env, "SELECT COALESCE(SUM(amount),0) v FROM expenses WHERE date BETWEEN ? AND ?", d1, d2),
    all(env, `SELECT date(created_at) d, COUNT(*) orders, SUM(total) revenue FROM orders WHERE ${P} GROUP BY date(created_at) ORDER BY d`, d1, d2),
    all(env, `SELECT oi.code, oi.name, SUM(oi.qty) qty, SUM(oi.qty*oi.price) revenue ${J2} GROUP BY oi.code, lower(oi.name) ORDER BY qty DESC LIMIT 10`, d1, d2),
    all(env, `SELECT CASE WHEN oi.country='' THEN 'Tanpa negara' ELSE oi.country END country, COUNT(DISTINCT o.id) orders, SUM(oi.qty) qty, SUM(oi.qty*oi.price) revenue, SUM(oi.qty*oi.dp) dp, SUM(oi.qty*(oi.price-oi.cost)) margin ${J2} GROUP BY 1 ORDER BY revenue DESC`, d1, d2),
    all(env, "SELECT p.method, COUNT(*) orders, SUM(p.amount) total FROM payments p JOIN orders o ON o.id=p.order_id WHERE o.status!='batal' AND date(o.created_at) BETWEEN ? AND ? GROUP BY p.method", d1, d2),
    all(env, `SELECT cashier, COUNT(*) orders, SUM(total) total FROM orders WHERE ${P} GROUP BY cashier ORDER BY total DESC`, d1, d2),
  ]);
  const cogs = cogsR.v, exp = expR.v;
  return { from: d1, to: d2, orders: tot.orders, revenue: tot.revenue, paid_total: tot.paid_total, unpaid_total: tot.unpaid_total, dp_total: tot.dp_total, discount: tot.discount, tax: tot.tax, cogs, expenses: exp, gross_profit: tot.revenue - cogs, net_profit: tot.paid_total - cogs - exp, daily, top_products: top, by_country: byCountry, methods, cashiers };
}
async function hReport(c) { const t = todayWib(); return reportData(c.env, c.query.get("from") || t, c.query.get("to") || t); }
async function hDashboard(c) {
  const t = todayWib(), w = addDays(t, -6);
  const [today, week, low, pending] = await Promise.all([
    reportData(c.env, t, t), reportData(c.env, w, t),
    all(c.env, "SELECT name,qty AS stock FROM inventory WHERE active=1 AND qty<=3 ORDER BY qty LIMIT 8"),
    one(c.env, "SELECT COUNT(*) n FROM orders WHERE status IN ('baru','dikerjakan','siap')"),
  ]);
  return { today, week, low_stock: low, pending: pending.n };
}
const csvCell = v => { v = String(v ?? ""); return /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v; };
async function hExportCsv(c) {
  const t = todayWib(), d1 = c.query.get("from") || t, d2 = c.query.get("to") || t;
  const orders = await all(c.env, "SELECT * FROM orders WHERE date(created_at) BETWEEN ? AND ? ORDER BY id", d1, d2);
  const items = await all(c.env, "SELECT * FROM order_items WHERE order_id IN (SELECT id FROM orders WHERE date(created_at) BETWEEN ? AND ?)", d1, d2);
  const lines = [["No Invoice", "Tanggal", "Pelanggan", "Tipe", "Status", "Lunas", "Metode", "Subtotal", "Diskon", "Pajak", "Total", "Dibayar", "Sisa", "Kasir", "Item"]];
  for (const o of orders) {
    const its = items.filter(i => i.order_id === o.id).map(i => `${i.country ? i.country + " " : ""}${i.name} x${i.qty}`).join("; ");
    lines.push([o.number, o.created_at, o.customer_name, o.type, o.status, o.paid ? "Ya" : "Belum", o.method, o.subtotal, o.discount, o.tax, o.total, o.paid_amount, o.total - o.paid_amount, o.cashier, its]);
  }
  return new Response("﻿" + lines.map(r => r.map(csvCell).join(",")).join("\r\n"), { headers: { "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": `attachment; filename="laporan-${d1}-sd-${d2}.csv"`, "Cache-Control": "no-store" } });
}

/* ---------- pengaturan, akun, backup ---------- */
async function hSettingsUpdate(c) {
  const stmts = Object.entries(c.body).filter(([k]) => k in DEFAULT_SETTINGS).map(([k, v]) => st(c.env, "INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", k, JSON.stringify(v)));
  if (stmts.length) await c.env.DB.batch(stmts);
  return getSettings(c.env);
}
const hUsersList = c => all(c.env, "SELECT id,username,name,role,active FROM users ORDER BY id");
async function hUserCreate(c) {
  const b = c.body, username = String(b.username || "").trim().toLowerCase(), pw = String(b.password || "");
  if (!/^[a-z0-9_.-]{3,30}$/.test(username)) throw new ApiError("Username 3-30 karakter (huruf kecil/angka/_ . -)");
  if (pw.length < 6) throw new ApiError("Password minimal 6 karakter");
  if (await one(c.env, "SELECT id FROM users WHERE username=?", username)) throw new ApiError("Username sudah dipakai");
  const r = await run(c.env, "INSERT INTO users(username,name,password,role,must_change) VALUES(?,?,?,?,1)", username, String(b.name || username).trim(), await hashPw(pw), b.role === "admin" ? "admin" : "kasir");
  return { id: r.meta.last_row_id };
}
async function hUserUpdate(c, uid) {
  const b = c.body, u = await one(c.env, "SELECT * FROM users WHERE id=?", uid);
  if (!u) throw new ApiError("User tidak ditemukan", 404);
  const name = String(b.name ?? u.name).trim() || u.name, role = (b.role ?? u.role) === "admin" ? "admin" : "kasir", active = (b.active ?? u.active) ? 1 : 0;
  if (uid === c.user.id && (role !== "admin" || !active)) throw new ApiError("Tidak bisa menurunkan/menonaktifkan akun sendiri");
  let pw = u.password, must = u.must_change;
  if (b.password) { if (String(b.password).length < 6) throw new ApiError("Password minimal 6 karakter"); pw = await hashPw(String(b.password)); must = 1; }
  await run(c.env, "UPDATE users SET name=?,role=?,active=?,password=?,must_change=? WHERE id=?", name, role, active, pw, must, uid);
  if (name !== u.name) await c.env.DB.batch([st(c.env, "UPDATE orders SET cashier=? WHERE cashier=?", name, u.name), st(c.env, "UPDATE payments SET cashier=? WHERE cashier=?", name, u.name), st(c.env, "UPDATE expenses SET cashier=? WHERE cashier=?", name, u.name)]);
  if (!active || b.password) await run(c.env, "DELETE FROM sessions WHERE user_id=?", uid);
  return { ok: true };
}
async function hChangePassword(c) {
  const b = c.body, u = await one(c.env, "SELECT * FROM users WHERE id=?", c.user.id);
  if (!(await checkPw(String(b.old || ""), u.password))) throw new ApiError("Password lama salah");
  if (String(b.new || "").length < 6) throw new ApiError("Password baru minimal 6 karakter");
  if (String(b.new) === String(b.old)) throw new ApiError("Password baru harus berbeda dari yang lama");
  await run(c.env, "UPDATE users SET password=?, must_change=0 WHERE id=?", await hashPw(String(b.new)), u.id);
  return { ok: true };
}
async function hBackup(c) {
  const data = { app: "herstoodio-kasir", exported_at: nowIso() };
  await run(c.env, "INSERT OR REPLACE INTO settings(key,value) VALUES('last_backup',?)", JSON.stringify(nowIso()));
  for (const t of ["settings", "products", "customers", "orders", "order_items", "payments", "expenses", "inventory", "inv_moves", "capital", "payroll", "activity"]) data[t] = await all(c.env, `SELECT * FROM ${t}`);
  data.users = await all(c.env, "SELECT id,username,name,role,active FROM users");
  return new Response(JSON.stringify(data), { headers: { "Content-Type": "application/json", "Content-Disposition": `attachment; filename="backup-kasir-${todayWib()}.json"`, "Cache-Control": "no-store" } });
}

/* ---------- halaman pelacakan publik (tanpa login, tanpa harga) ---------- */
async function hTrack(c) {
  const s = await getSettings(c.env);
  if (+s.track_enabled === 0) throw new ApiError("Halaman pelacakan sedang dinonaktifkan", 403);
  const q = String(c.query.get("q") || "").trim().slice(0, 60), month = String(c.query.get("month") || "");
  if (month && !/^\d{4}-\d{2}$/.test(month)) throw new ApiError("Bulan tidak valid");
  if (q && q.length < 3) throw new ApiError("Ketik minimal 3 huruf nama / no invoice");
  if (!q && !month) return { rows: [], brand: s.store_name, hint: true };
  const like = "%" + q.replace(/[\\%_]/g, m => "\\" + m) + "%";
  const where = [], args = [];
  if (month) { where.push("substr(o.created_at,1,7)=?"); args.push(month); }
  if (q) { where.push("(o.number LIKE ? ESCAPE '\\' OR o.customer_name LIKE ? ESCAPE '\\')"); args.push(like, like); }
  const orders = await all(c.env, `SELECT o.id,o.number,o.created_at,o.customer_name,o.status,o.tracking FROM orders o WHERE ${where.join(" AND ")} ORDER BY o.id DESC LIMIT 80`, ...args);
  const items = orders.length ? await all(c.env, `SELECT order_id,country,code,name,qty FROM order_items WHERE order_id IN (${orders.map(() => "?").join(",")}) ORDER BY id`, ...orders.map(o => o.id)) : [];
  return { brand: s.store_name, rows: orders.map(o => ({ number: o.number, date: o.created_at.slice(0, 10), customer: o.customer_name, status: o.status, tracking: o.tracking || "", items: items.filter(i => i.order_id === o.id).map(i => ({ country: i.country, code: i.code, name: i.name, qty: i.qty })) })) };
}

/* ---------- notifikasi (lonceng): order baru, order mirip/duplikat, stok menipis ---------- */
async function hNotif(c) {
  const recent = await all(c.env, "SELECT id,number,customer_name,type,status,total,cashier,created_at FROM orders WHERE created_at>=? ORDER BY id DESC LIMIT 20", new Date(Date.now() + WIB - 3 * 864e5).toISOString().slice(0, 10));
  const cutoff = new Date(Date.now() + WIB - 60 * 864e5).toISOString().slice(0, 10);
  const os = await all(c.env, "SELECT id,number,customer_name,total,paid,paid_amount,cashier,created_at,status FROM orders WHERE status!='batal' AND lower(customer_name)<>'umum' AND created_at>=? ORDER BY id", cutoff);
  const its = os.length ? await all(c.env, "SELECT order_id,code,name,qty FROM order_items WHERE order_id IN (SELECT id FROM orders WHERE status!='batal' AND lower(customer_name)<>'umum' AND created_at>=?) ORDER BY id", cutoff) : [];
  const byOrder = new Map(); for (const i of its) (byOrder.get(i.order_id) || byOrder.set(i.order_id, []).get(i.order_id)).push(i);
  const groups = new Map();
  for (const o of os) {
    const li = byOrder.get(o.id); if (!li) continue;
    const sig = o.customer_name.trim().toLowerCase() + "#" + li.map(i => `${String(i.code || "").toUpperCase()}|${i.name.trim().toLowerCase()}|${i.qty}`).sort().join(";");
    (groups.get(sig) || groups.set(sig, []).get(sig)).push({ ...o, items: li });
  }
  const ok = new Set((await all(c.env, "SELECT key FROM dup_ok")).map(r => r.key));
  const dups = [];
  for (const g of groups.values()) {
    if (g.length < 2) continue;
    const key = g.map(o => o.id).join(",");
    if (ok.has(key)) continue;
    dups.push({ key, customer: g[0].customer_name, items: g[0].items.map(i => ({ code: i.code, name: i.name, qty: i.qty })), orders: g.map(o => ({ id: o.id, number: o.number, date: o.created_at.slice(0, 16), total: o.total, paid: o.paid, paid_amount: o.paid_amount, cashier: o.cashier })) });
  }
  const low = await all(c.env, "SELECT code,name,qty FROM inventory WHERE active=1 AND qty<=3 ORDER BY qty, name LIMIT 20");
  // barang sudah sampai di Indonesia (status Siap Dikirim) tapi belum lunas -> waktunya ditagih
  const bill = await all(c.env, "SELECT id,number,customer_name customer,total-paid_amount sisa FROM orders WHERE status='siap' AND paid=0 ORDER BY id LIMIT 30");
  const resend = (await all(c.env, "SELECT i.id,i.order_id,i.kind,i.resend,o.number,o.customer_name customer FROM incidents i JOIN orders o ON o.id=i.order_id WHERE i.status='open' AND o.status!='batal' ORDER BY i.id LIMIT 30")).map(r => ({ id: r.id, order_id: r.order_id, number: r.number, customer: r.customer, kind: INC_KINDS[r.kind] || r.kind, items: JSON.parse(r.resend || "[]") }));
  let backup_days = null;
  if (c.user.role === "admin") { const lb = await one(c.env, "SELECT value FROM settings WHERE key='last_backup'"); const last = lb ? JSON.parse(lb.value) : null; backup_days = last ? Math.floor((Date.now() - Date.parse(last.replace(" ", "T") + "Z") + WIB) / 864e5) : -1; }
  return { recent: recent.map(o => ({ id: o.id, number: o.number, customer: o.customer_name, type: o.type, status: o.status, cashier: o.cashier, at: o.created_at })), max_id: recent.length ? recent[0].id : 0, dups, low, bill, resend, backup_days };
}
async function hDupOk(c) {
  const key = String(c.body.key || "");
  if (!/^\d+(,\d+)+$/.test(key)) throw new ApiError("Data tidak valid");
  await run(c.env, "INSERT OR IGNORE INTO dup_ok(key,created_at) VALUES(?,?)", key, nowIso());
  return { ok: true };
}

/* ---------- kesalahan kirim / barang kurang / rusak / hilang ---------- */
const INC_KINDS = { salah_kirim: "Salah kirim", kurang: "Barang kurang", rusak: "Barang rusak", hilang: "Barang hilang" };
const incView = (r, admin) => { const o = { ...r, resend: JSON.parse(r.resend || "[]"), wrong: JSON.parse(r.wrong || "[]"), kind_label: INC_KINDS[r.kind] || r.kind }; if (!admin) { delete o.loss; o.wrong = o.wrong.map(({ cost, ...x }) => x); } return o; };
async function hIncidentCreate(c, id) {
  const o = await loadOrder(c.env, id), b = c.body;
  if (o.status === "batal") throw new ApiError("Order sudah dibatalkan");
  const kind = String(b.kind || ""); if (!INC_KINDS[kind]) throw new ApiError("Pilih jenis kesalahan");
  const clean = a => (Array.isArray(a) ? a : []).map(x => ({ name: String(x.name || "").trim().slice(0, 120), code: String(x.code || "").trim().toUpperCase().slice(0, 40), qty: Math.max(1, toInt(x.qty) || 1), source: x.source === "order" ? "order" : "master" })).filter(x => x.name);
  const resend = clean(b.resend), wrong = clean(b.wrong), ship = Math.max(0, toInt(b.ship));
  if (!resend.length && !wrong.length && !ship) throw new ApiError("Isi barang yang dikirim ulang, barang rugi, atau ongkir");
  let loss = 0, noCost = 0; const stmts = [], names = [];
  for (const x of wrong) {
    let cost = 0;
    if (x.source === "order") cost = (o.items.find(i => i.name.toLowerCase() === x.name.toLowerCase() && (i.code || "") === x.code) || o.items.find(i => i.name.toLowerCase() === x.name.toLowerCase()) || {}).cost || 0;
    if (!cost) cost = (await one(c.env, "SELECT cost FROM products WHERE lower(name)=lower(?) AND code=? AND cost>0 LIMIT 1", x.name, x.code))?.cost || (await one(c.env, "SELECT cost FROM inventory WHERE lower(name)=lower(?) AND code=? AND cost>0 AND active=1 LIMIT 1", x.name, x.code))?.cost || 0;
    if (!cost) noCost++;
    x.cost = cost; loss += cost * x.qty; names.push(`${x.name} ×${x.qty}`);
  }
  if (toInt(b.loss_manual) > 0) loss = toInt(b.loss_manual);
  const note = String(b.note || "").trim().slice(0, 200), t = nowIso(), d = todayWib();
  const ins = await run(c.env, "INSERT INTO incidents(order_id,kind,resend,wrong,ship,loss,note,status,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?,?)", id, kind, JSON.stringify(resend), JSON.stringify(wrong), ship, loss, note, resend.length ? "open" : "done", t, c.user.name);
  const iid = ins.meta.last_row_id;
  if (!resend.length) stmts.push(st(c.env, "UPDATE incidents SET done_at=? WHERE id=?", t, iid));
  if (ship > 0) stmts.push(st(c.env, "INSERT INTO expenses(date,category,description,amount,cashier,incident_id) VALUES(?,?,?,?,?,?)", d, "Kerugian & kirim ulang", `Ongkir kirim ulang ${o.number}`, ship, c.user.name, iid));
  if (loss > 0) stmts.push(st(c.env, "INSERT INTO expenses(date,category,description,amount,cashier,incident_id) VALUES(?,?,?,?,?,?)", d, "Kerugian & kirim ulang", `${INC_KINDS[kind]} ${o.number}: ${names.join(", ")}`.slice(0, 200), loss, c.user.name, iid));
  const adjusted = [];
  if (b.deduct_stock) for (const x of wrong) {
    const inv = await one(c.env, "SELECT id,qty FROM inventory WHERE active=1 AND lower(name)=lower(?) AND code=? LIMIT 1", x.name, x.code);
    if (inv && inv.qty >= x.qty) { stmts.push(st(c.env, "UPDATE inventory SET qty=qty-? WHERE id=?", x.qty, inv.id), st(c.env, "INSERT INTO inv_moves(inv_id,delta,reason,ref,created_at) VALUES(?,?,?,?,?)", inv.id, -x.qty, `${INC_KINDS[kind].toLowerCase()} ${o.number}`, c.user.name, t)); adjusted.push(x.name); }
  }
  if (stmts.length) await c.env.DB.batch(stmts);
  return { id: iid, loss, no_cost: noCost, stock_adjusted: adjusted };
}
async function hIncidentDone(c, id) { await run(c.env, "UPDATE incidents SET status='done', done_at=? WHERE id=?", nowIso(), id); return { ok: true }; }

/* ---------- refund, modal massal, log aktivitas ---------- */
async function hRefund(c, id) {
  const o = await loadOrder(c.env, id), amount = toInt(c.body.amount);
  if (o.status === "batal") throw new ApiError("Order sudah dibatalkan, tidak perlu refund");
  if (amount <= 0) throw new ApiError("Nominal refund harus lebih dari 0");
  if (amount > o.paid_amount - (o.refund || 0)) throw new ApiError("Refund melebihi uang yang sudah diterima dari order ini");
  const note = String(c.body.note || "").trim().slice(0, 120);
  await c.env.DB.batch([
    st(c.env, "INSERT INTO payments(order_id,amount,method,kind,cash_received,cashier,created_at) VALUES(?,?,?,?,0,?,?)", id, -amount, note ? "Refund: " + note : "Refund", "refund", c.user.name, nowIso()),
    st(c.env, "UPDATE orders SET refund=refund+? WHERE id=?", amount, id),
  ]);
  return loadOrder(c.env, id);
}
async function hApplyMasterCost(c) {
  const r = await c.env.DB.prepare("UPDATE order_items SET cost=(SELECT p.cost FROM products p WHERE lower(p.name)=lower(order_items.name) AND p.code=order_items.code AND p.cost>0 ORDER BY p.id LIMIT 1) WHERE cost=0 AND EXISTS (SELECT 1 FROM products p WHERE lower(p.name)=lower(order_items.name) AND p.code=order_items.code AND p.cost>0)").run();
  const left = (await one(c.env, "SELECT COUNT(*) n FROM order_items oi JOIN orders o ON o.id=oi.order_id WHERE o.status!='batal' AND oi.cost=0")).n;
  return { updated: r.meta?.changes || 0, left };
}
const hActivity = c => all(c.env, "SELECT * FROM activity ORDER BY id DESC LIMIT 300");
const ACT = [
  ["POST", /^\/api\/orders$/, () => "Membuat order baru"],
  ["PUT", /^\/api\/orders\/(\d+)$/, (b, r) => Array.isArray(b.items) ? `Edit invoice ${r}` : b.pay_amount != null || b.paid ? `Catat pembayaran ${r}${b.pay_amount ? " Rp " + toInt(b.pay_amount) : ""}` : b.status ? `Ubah status ${r} → ${b.status}` : `Ubah data ${r}`],
  ["DELETE", /^\/api\/orders\/(\d+)$/, (b, r) => `Hapus invoice ${r}`],
  ["POST", /^\/api\/orders\/(\d+)\/refund$/, (b, r) => `Refund ${r} Rp ${toInt(b.amount)}`],
  ["POST", /^\/api\/orders\/(\d+)\/incident$/, (b, r) => `Catat ${INC_KINDS[b.kind] || "kesalahan"} ${r}`], ["POST", /^\/api\/incidents\/(\d+)\/done$/, () => "Tandai kirim ulang selesai"],
  ["POST", /^\/api\/products$/, b => `Tambah master produk ${b.name || ""}`], ["PUT", /^\/api\/products\/(\d+)$/, b => `Ubah master produk ${b.name || ""}`], ["DELETE", /^\/api\/products\/(\d+)$/, () => "Hapus master produk"],
  ["POST", /^\/api\/inventory$/, b => `Tambah inventory ${b.name || ""}`], ["PUT", /^\/api\/inventory\/(\d+)$/, b => `Ubah inventory ${b.name || ""}`], ["DELETE", /^\/api\/inventory\/(\d+)$/, () => "Hapus inventory"],
  ["POST", /^\/api\/inventory\/(\d+)\/stock$/, b => `Ubah stok inventory (${toInt(b.delta) > 0 ? "+" : ""}${toInt(b.delta)})`], ["POST", /^\/api\/inventory\/(\d+)\/link-old$/, () => "Tarik order lama ke inventory"],
  ["POST", /^\/api\/expenses$/, b => `Catat pengeluaran Rp ${toInt(b.amount)}`], ["DELETE", /^\/api\/expenses\/(\d+)$/, () => "Hapus pengeluaran"],
  ["POST", /^\/api\/capital$/, b => `Catat modal Rp ${toInt(b.amount)} (${b.party || "-"})`], ["DELETE", /^\/api\/capital\/(\d+)$/, () => "Hapus setoran modal"],
  ["POST", /^\/api\/payroll$/, b => `Bayar gaji ${b.person || ""} Rp ${toInt(b.amount)}`], ["DELETE", /^\/api\/payroll\/(\d+)$/, () => "Hapus pembayaran gaji"],
  ["PUT", /^\/api\/settings$/, () => "Ubah pengaturan"], ["POST", /^\/api\/users$/, b => `Tambah akun ${b.name || ""}`], ["PUT", /^\/api\/users\/(\d+)$/, b => "Ubah akun" + (b.name ? " → " + b.name : "")],
  ["POST", /^\/api\/finance\/apply-master-cost$/, () => "Terapkan modal Master ke order lama"],
];
async function logAct(env, user, method, path, body, preNo = "") {
  const a = ACT.find(([m, rx]) => m === method && rx.test(path)); if (!a) return;
  const mt = a[1].exec(path); let ref = mt && mt[1] ? "#" + mt[1] : "";
  if (preNo) ref = preNo;
  await run(env, "INSERT INTO activity(at,user,action,detail) VALUES(?,?,?,?)", nowIso(), user.name, a[2](body || {}, ref), "");
  await run(env, "DELETE FROM activity WHERE id < (SELECT MAX(id) FROM activity) - 3000");
}

/* ---------- routing ---------- */
const ROUTES = [
  ["GET", /^\/api\/inventory\/legacy$/, hInvLegacy, "user"], ["POST", /^\/api\/inventory\/(\d+)\/link-old$/, hInvLinkOld, "user"],
  ["GET", /^\/api\/finance$/, hFinance, "admin"], ["POST", /^\/api\/capital$/, hCapitalCreate, "admin"], ["DELETE", /^\/api\/capital\/(\d+)$/, hCapitalDelete, "admin"],
  ["POST", /^\/api\/payroll$/, hPayrollCreate, "admin"], ["DELETE", /^\/api\/payroll\/(\d+)$/, hPayrollDelete, "admin"], ["GET", /^\/api\/order-rows$/, hOrderRows, "user"],
  ["GET", /^\/api\/inventory$/, hInvList, "user"], ["POST", /^\/api\/inventory$/, hInvCreate, "user"], ["PUT", /^\/api\/inventory\/(\d+)$/, hInvUpdate, "user"],
  ["POST", /^\/api\/inventory\/(\d+)\/stock$/, hInvStock, "user"], ["DELETE", /^\/api\/inventory\/(\d+)$/, hInvDelete, "user"], ["GET", /^\/api\/inventory\/(\d+)\/moves$/, hInvMoves, "user"],
  ["POST", /^\/api\/login$/, hLogin, null], ["GET", /^\/api\/public-settings$/, hPublicSettings, null], ["GET", /^\/api\/track$/, hTrack, null], ["GET", /^\/api\/notifications$/, hNotif, "user"], ["POST", /^\/api\/orders\/(\d+)\/refund$/, hRefund, "user"], ["POST", /^\/api\/orders\/(\d+)\/incident$/, hIncidentCreate, "user"], ["POST", /^\/api\/incidents\/(\d+)\/done$/, hIncidentDone, "user"], ["POST", /^\/api\/finance\/apply-master-cost$/, hApplyMasterCost, "admin"], ["GET", /^\/api\/activity$/, hActivity, "admin"], ["POST", /^\/api\/notifications\/dup-ok$/, hDupOk, "user"],
  ["POST", /^\/api\/logout$/, hLogout, "user"], ["GET", /^\/api\/bootstrap$/, hBootstrap, "user"],
  ["GET", /^\/api\/products$/, hProductsList, "user"], ["POST", /^\/api\/products$/, hProductCreate, "user"],
  ["PUT", /^\/api\/products\/(\d+)$/, hProductUpdate, "user"], ["DELETE", /^\/api\/products\/(\d+)$/, hProductDelete, "user"],
  ["GET", /^\/api\/customers$/, hCustomersList, "user"], ["POST", /^\/api\/customers$/, hCustomerCreate, "user"],
  ["PUT", /^\/api\/customers\/(\d+)$/, hCustomerUpdate, "user"], ["DELETE", /^\/api\/customers\/(\d+)$/, hCustomerDelete, "user"],
  ["GET", /^\/api\/orders$/, hOrdersList, "user"], ["POST", /^\/api\/orders$/, hOrderCreate, "user"],
  ["GET", /^\/api\/orders\/(\d+)$/, hOrderGet, "user"], ["PUT", /^\/api\/orders\/(\d+)$/, hOrderUpdate, "user"], ["DELETE", /^\/api\/orders\/(\d+)$/, hOrderDelete, "user"], ["POST", /^\/api\/products\/dedupe$/, hProductDedupe, "user"], ["POST", /^\/api\/customers\/sync$/, hCustomersSync, "user"],
  ["GET", /^\/api\/expenses$/, hExpensesList, "admin"], ["POST", /^\/api\/expenses$/, hExpenseCreate, "admin"], ["DELETE", /^\/api\/expenses\/(\d+)$/, hExpenseDelete, "admin"],
  ["GET", /^\/api\/dashboard$/, hDashboard, "user"], ["GET", /^\/api\/report$/, hReport, "admin"], ["GET", /^\/api\/export\.csv$/, hExportCsv, "admin"],
  ["PUT", /^\/api\/settings$/, hSettingsUpdate, "admin"], ["GET", /^\/api\/users$/, hUsersList, "admin"], ["POST", /^\/api\/users$/, hUserCreate, "admin"],
  ["PUT", /^\/api\/users\/(\d+)$/, hUserUpdate, "admin"], ["POST", /^\/api\/change-password$/, hChangePassword, "user"], ["GET", /^\/api\/backup$/, hBackup, "admin"],
];

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(req);
    try {
      await ensureInit(env);
      for (const [m, rx, fn, auth] of ROUTES) {
        if (m !== req.method) continue;
        const mt = rx.exec(url.pathname);
        if (!mt) continue;
        const h = req.headers.get("Authorization") || "";
        const token = h.startsWith("Bearer ") ? h.slice(7) : "";
        let user = null;
        if (auth) {
          user = await authUser(env, token);
          if (!user) throw new ApiError("Sesi habis, silakan login lagi", 401);
          if (auth === "admin" && user.role !== "admin") throw new ApiError("Hanya admin yang boleh melakukan ini", 403);
        }
        let body = {};
        if (m === "POST" || m === "PUT") { try { body = (await req.json()) || {}; } catch { body = {}; } }
        const ctx = { env, user, token, body, query: url.searchParams, ip: req.headers.get("CF-Connecting-IP") || "" };
        let preNo = ""; const om = user && m !== "GET" ? /^\/api\/orders\/(\d+)/.exec(url.pathname) : null;
        if (om) { const o0 = await one(env, "SELECT number FROM orders WHERE id=?", +om[1]); if (o0) preNo = o0.number; }
        const res = await fn(ctx, ...mt.slice(1).map(Number));
        if (user && m !== "GET") { try { await logAct(env, user, m, url.pathname, body, preNo); } catch (e) { console.error("log", e); } }
        return res instanceof Response ? res : J(res);
      }
      throw new ApiError("Endpoint tidak ditemukan", 404);
    } catch (e) {
      if (e instanceof ApiError) return J({ error: e.message }, e.code);
      console.error(e);
      return J({ error: "Kesalahan server: " + (e && e.message || e) }, 500);
    }
  },
};

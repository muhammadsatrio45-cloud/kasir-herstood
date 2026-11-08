import { SCHEMA, DEFAULT_SETTINGS } from "./schema.js";

/* ---------- util ---------- */
class ApiError extends Error { constructor(msg, code = 400) { super(msg); this.code = code; } }
const toInt = (v, d = 0) => { const n = Math.round(parseFloat(v)); return Number.isFinite(n) ? n : d; };
const J = (o, status = 200, extra = {}) => new Response(JSON.stringify(o), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...extra } });
const WIB = 7 * 3600e3; // semua tanggal memakai WIB
const nowIso = () => new Date(Date.now() + WIB).toISOString().slice(0, 19).replace("T", " ");
const todayWib = () => nowIso().slice(0, 10);
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
const hPublicSettings = async c => getSettings(c.env);
const hBootstrap = async c => ({
  user: c.user, poll: 30, settings: await getSettings(c.env),
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
async function hProductCreate(c) {
  const r = await run(c.env, "INSERT INTO products(name,category,price,cost,dp,stock,active,country,code) VALUES(?,?,?,?,?,?,?,?,?)", ...productPayload(c.body));
  return await one(c.env, "SELECT * FROM products WHERE id=?", r.meta.last_row_id);
}
async function hProductUpdate(c, id) {
  await run(c.env, "UPDATE products SET name=?,category=?,price=?,cost=?,dp=?,stock=?,active=?,country=?,code=? WHERE id=?", ...productPayload(c.body), id);
  const r = await one(c.env, "SELECT * FROM products WHERE id=?", id);
  if (!r) throw new ApiError("Produk tidak ditemukan", 404);
  return r;
}
const hProductDelete = async (c, id) => { await run(c.env, "DELETE FROM products WHERE id=?", id); return { ok: true }; };

/* ---------- pelanggan ---------- */
const hCustomersList = c => all(c.env, `SELECT cu.*, COALESCE(s.cnt,0) AS orders, COALESCE(s.total,0) AS spent FROM customers cu LEFT JOIN (SELECT customer_id, COUNT(*) cnt, SUM(total) total FROM orders GROUP BY customer_id) s ON s.customer_id=cu.id ORDER BY cu.name`);
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

/* ---------- order ---------- */
async function loadOrder(env, id) {
  const o = await one(env, "SELECT * FROM orders WHERE id=?", id);
  if (!o) throw new ApiError("Order tidak ditemukan", 404);
  o.items = await all(env, "SELECT * FROM order_items WHERE order_id=? ORDER BY id", id);
  o.payments = await all(env, "SELECT * FROM payments WHERE order_id=? ORDER BY id", id);
  o.remaining = o.total - o.paid_amount;
  return o;
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
  o.settings = Object.fromEntries(Object.entries(s).filter(([k]) => k.startsWith("store_") || k.startsWith("invoice_") || k === "currency"));
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
const paymentStmts = (env, oid, total, paidAmount, amount, method, cash, cashier) => {
  const p = paymentPlan(total, paidAmount, amount, method, cash), t = nowIso();
  return [
    st(env, "INSERT INTO payments(order_id,amount,method,kind,cash_received,cashier,created_at) VALUES(?,?,?,?,?,?,?)", oid, amount, method, p.kind, method === "Tunai" ? cash : 0, cashier, t),
    st(env, "UPDATE orders SET paid_amount=?, paid=?, method=?, paid_at=CASE WHEN ?=1 THEN ? ELSE paid_at END WHERE id=?", p.newPaid, p.full, method, p.full, t, oid),
  ];
};
async function nextNumber(env, prefix) {
  const year = todayWib().slice(0, 4);
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
  let subtotal = 0, dpTarget = 0; const lines = [];
  for (const it of items) {
    const name = String(it.name || "").split(/\s+/).filter(Boolean).join(" ");
    if (!name) throw new ApiError("Nama produk wajib diisi");
    const qty = Math.max(1, toInt(it.qty, 1)), price = Math.max(0, toInt(it.price)), dp = Math.max(0, toInt(it.dp)), cost = Math.max(0, toInt(it.cost));
    if (dp > price) throw new ApiError(`DP untuk ${name} tidak boleh lebih besar dari harganya`);
    lines.push({ name, price, dp, cost, qty, note: String(it.note || "").trim(), country: String(it.country || "").trim().slice(0, 30), code: String(it.code || "").trim().toUpperCase().slice(0, 30) });
    subtotal += price * qty; dpTarget += dp * qty;
  }
  const discount = Math.min(Math.max(0, toInt(b.discount)), subtotal);
  const taxable = subtotal - discount, tax = Math.round(taxable * (parseFloat(s.tax_percent) || 0) / 100), total = taxable + tax;
  let paidFull = !!b.paid, dp = paidFull ? 0 : Math.max(0, toInt(b.dp));
  if (dp > 0 && dp >= total) { paidFull = true; dp = 0; }
  const method = String(b.method || "Tunai"), cash = toInt(b.cash_received);
  let custId = b.customer_id || null, custName = "Umum";
  if (custId) { const cu = await one(env, "SELECT name FROM customers WHERE id=?", custId); if (cu) custName = cu.name; else custId = null; }
  if (b.customer_name && !custId) custName = String(b.customer_name).trim() || "Umum";
  const type = String(b.type || "Pre-Order"), note = String(b.note || "").trim(), cashier = c.user.name;
  for (let attempt = 0; attempt < 4; attempt++) {
    const number = await nextNumber(env, s.invoice_prefix || "INV");
    const oidSql = "(SELECT id FROM orders WHERE number=?)";
    const stmts = [st(env, "INSERT INTO orders(number,customer_id,customer_name,type,status,paid,method,subtotal,discount,tax,total,cash_received,note,cashier,created_at,paid_at,dp_target) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
      number, custId, custName, type, "baru", 0, "", subtotal, discount, tax, total, 0, note, cashier, nowIso(), null, dpTarget)];
    for (const l of lines) {
      // produk master: ketik manual -> otomatis jadi master, harga/DP terakhir jadi default
      stmts.push(st(env, "UPDATE products SET price=?,dp=?,cost=?,active=1,country=?,code=? WHERE lower(name)=lower(?)", l.price, l.dp, l.cost, l.country, l.code, l.name));
      stmts.push(st(env, "INSERT INTO products(name,category,price,cost,dp,stock,active,country,code) SELECT ?,'Umum',?,?,?,NULL,1,?,? WHERE NOT EXISTS(SELECT 1 FROM products WHERE lower(name)=lower(?))", l.name, l.price, l.cost, l.dp, l.country, l.code, l.name));
      stmts.push(st(env, `INSERT INTO order_items(order_id,product_id,name,price,dp,cost,qty,note,country,code) VALUES(${oidSql},(SELECT id FROM products WHERE lower(name)=lower(?) LIMIT 1),?,?,?,?,?,?,?,?)`, number, l.name, l.name, l.price, l.dp, l.cost, l.qty, l.note, l.country, l.code));
    }
    try { await env.DB.batch(stmts); } catch (e) { if (/UNIQUE/i.test(String(e)) && attempt < 3) continue; throw e; }
    const oid = (await one(env, "SELECT id FROM orders WHERE number=?", number)).id;
    if (paidFull) {
      if (total > 0) await env.DB.batch(paymentStmts(env, oid, total, 0, total, method, cash, cashier));
      else await run(env, "UPDATE orders SET paid=1, paid_at=? WHERE id=?", nowIso(), oid);
    } else if (dp > 0) await env.DB.batch(paymentStmts(env, oid, total, 0, dp, method, cash, cashier));
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
  if (b.pay_amount !== undefined && b.pay_amount !== null || b.paid) {
    if (o.status === "batal") throw new ApiError("Order sudah dibatalkan");
    const remaining = o.total - o.paid_amount;
    if (remaining <= 0) throw new ApiError("Order sudah lunas");
    const amount = b.pay_amount !== undefined && b.pay_amount !== null ? toInt(b.pay_amount) : remaining;
    stmts.push(...paymentStmts(env, id, o.total, o.paid_amount, amount, String(b.method || "Tunai"), toInt(b.cash_received), c.user.name));
  }
  const note = "note" in b ? String(b.note).trim() : o.note;
  stmts.push(st(env, "UPDATE orders SET status=?,note=? WHERE id=?", status, note, id));
  await env.DB.batch(stmts);
  return loadOrder(env, id);
}
const hOrderDelete = async (c, id) => { await c.env.DB.batch([st(c.env, "DELETE FROM payments WHERE order_id=?", id), st(c.env, "DELETE FROM order_items WHERE order_id=?", id), st(c.env, "DELETE FROM orders WHERE id=?", id)]); return { ok: true }; };

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

/* ---------- laporan ---------- */
async function reportData(env, d1, d2) {
  const P = "status!='batal' AND date(created_at) BETWEEN ? AND ?";
  const tot = await one(env, `SELECT COUNT(*) orders, COALESCE(SUM(total),0) revenue, COALESCE(SUM(paid_amount),0) paid_total, COALESCE(SUM(total-paid_amount),0) unpaid_total, COALESCE(SUM(CASE WHEN paid=0 AND paid_amount>0 THEN paid_amount ELSE 0 END),0) dp_total, COALESCE(SUM(discount),0) discount, COALESCE(SUM(tax),0) tax FROM orders WHERE ${P}`, d1, d2);
  const J2 = "FROM order_items oi JOIN orders o ON o.id=oi.order_id WHERE o.status!='batal' AND date(o.created_at) BETWEEN ? AND ?";
  const [cogsR, expR, daily, top, byCountry, methods, cashiers] = await Promise.all([
    one(env, `SELECT COALESCE(SUM(oi.cost*oi.qty),0) v ${J2}`, d1, d2),
    one(env, "SELECT COALESCE(SUM(amount),0) v FROM expenses WHERE date BETWEEN ? AND ?", d1, d2),
    all(env, `SELECT date(created_at) d, COUNT(*) orders, SUM(total) revenue FROM orders WHERE ${P} GROUP BY date(created_at) ORDER BY d`, d1, d2),
    all(env, `SELECT oi.name, SUM(oi.qty) qty, SUM(oi.qty*oi.price) revenue ${J2} GROUP BY oi.name ORDER BY qty DESC LIMIT 10`, d1, d2),
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
    all(c.env, "SELECT name,stock FROM products WHERE active=1 AND stock IS NOT NULL AND stock<=10 ORDER BY stock LIMIT 8"),
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
  for (const t of ["settings", "products", "customers", "orders", "order_items", "payments", "expenses"]) data[t] = await all(c.env, `SELECT * FROM ${t}`);
  data.users = await all(c.env, "SELECT id,username,name,role,active FROM users");
  return new Response(JSON.stringify(data), { headers: { "Content-Type": "application/json", "Content-Disposition": `attachment; filename="backup-kasir-${todayWib()}.json"`, "Cache-Control": "no-store" } });
}

/* ---------- routing ---------- */
const ROUTES = [
  ["POST", /^\/api\/login$/, hLogin, null], ["GET", /^\/api\/public-settings$/, hPublicSettings, null],
  ["POST", /^\/api\/logout$/, hLogout, "user"], ["GET", /^\/api\/bootstrap$/, hBootstrap, "user"],
  ["GET", /^\/api\/products$/, hProductsList, "user"], ["POST", /^\/api\/products$/, hProductCreate, "admin"],
  ["PUT", /^\/api\/products\/(\d+)$/, hProductUpdate, "admin"], ["DELETE", /^\/api\/products\/(\d+)$/, hProductDelete, "admin"],
  ["GET", /^\/api\/customers$/, hCustomersList, "user"], ["POST", /^\/api\/customers$/, hCustomerCreate, "user"],
  ["PUT", /^\/api\/customers\/(\d+)$/, hCustomerUpdate, "user"], ["DELETE", /^\/api\/customers\/(\d+)$/, hCustomerDelete, "admin"],
  ["GET", /^\/api\/orders$/, hOrdersList, "user"], ["POST", /^\/api\/orders$/, hOrderCreate, "user"],
  ["GET", /^\/api\/orders\/(\d+)$/, hOrderGet, "user"], ["PUT", /^\/api\/orders\/(\d+)$/, hOrderUpdate, "user"], ["DELETE", /^\/api\/orders\/(\d+)$/, hOrderDelete, "admin"],
  ["GET", /^\/api\/expenses$/, hExpensesList, "user"], ["POST", /^\/api\/expenses$/, hExpenseCreate, "user"], ["DELETE", /^\/api\/expenses\/(\d+)$/, hExpenseDelete, "admin"],
  ["GET", /^\/api\/dashboard$/, hDashboard, "user"], ["GET", /^\/api\/report$/, hReport, "user"], ["GET", /^\/api\/export\.csv$/, hExportCsv, "admin"],
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
        const res = await fn(ctx, ...mt.slice(1).map(Number));
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

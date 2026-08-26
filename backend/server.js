const crypto = require('node:crypto');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const required = ['DATABASE_URL', 'JWT_SECRET'];
for (const name of required) if (!process.env[name]) throw new Error(`${name} must be configured`);
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false });
const app = express();
app.use(helmet());
app.use(cors({ origin: process.env.ADMIN_PANEL_ORIGIN || false }));
app.use(express.json({ limit: '1mb' }));
app.use(rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false }));
const authLimit = rateLimit({ windowMs: 15 * 60_000, limit: 10, message: { error: 'تعداد تلاش‌های ورود بیش از حد مجاز است.' }, standardHeaders: true, legacyHeaders: false });
const asyncRoute = handler => (request, response, next) => Promise.resolve(handler(request, response, next)).catch(next);
const tokenHash = token => crypto.createHash('sha256').update(token).digest('hex');
const validEmail = value => typeof value === 'string' && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value);
const requiredString = (body, name, max = 500) => typeof body[name] === 'string' && body[name].trim().length > 0 && body[name].length <= max;

async function auth(request, response, next) {
  try {
    const raw = request.headers.authorization?.replace(/^Bearer\s+/i, '');
    if (!raw) return response.status(401).json({ error: 'ورود لازم است.' });
    const claims = jwt.verify(raw, process.env.JWT_SECRET);
    const result = await pool.query('SELECT u.id, u.full_name, u.is_active, COALESCE(a.role, \'user\') AS role FROM sessions s JOIN users u ON u.id = s.user_id LEFT JOIN admin_users a ON a.user_id = u.id WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > NOW()', [tokenHash(raw)]);
    if (!result.rowCount || !result.rows[0].is_active || result.rows[0].id !== claims.sub) return response.status(401).json({ error: 'نشست معتبر نیست.' });
    request.user = result.rows[0];
    request.token = raw;
    next();
  } catch (_) { response.status(401).json({ error: 'نشست معتبر نیست.' }); }
}
const adminOnly = (request, response, next) => request.user?.role === 'admin' ? next() : response.status(403).json({ error: 'دسترسی مدیر لازم است.' });
async function audit(client, userId, action, entityType, entityId, metadata = {}) {
  await client.query('INSERT INTO audit_logs (id, admin_user_id, action, entity_type, entity_id, metadata) SELECT gen_random_uuid(), id, $2, $3, $4, $5 FROM admin_users WHERE user_id = $1', [userId, action, entityType, entityId || null, metadata]);
}
function issueSession(userId, role) {
  const token = jwt.sign({ sub: userId, role }, process.env.JWT_SECRET, { expiresIn: '15m' });
  return { token, hash: tokenHash(token), expiresAt: new Date(Date.now() + 15 * 60_000) };
}

app.post('/api/auth/register', authLimit, asyncRoute(async (request, response) => {
  const { fullName, email, password } = request.body;
  if (!requiredString(request.body, 'fullName', 120) || !validEmail(email) || typeof password !== 'string' || password.length < 8 || password.length > 128) return response.status(400).json({ error: 'اطلاعات ثبت‌نام معتبر نیست.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const user = await client.query('INSERT INTO users (id, full_name, email, password_hash) VALUES (gen_random_uuid(), $1, lower($2), $3) RETURNING id, full_name', [fullName.trim(), email, await bcrypt.hash(password, 12)]);
    const session = issueSession(user.rows[0].id, 'user');
    await client.query('INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES (gen_random_uuid(), $1, $2, $3)', [user.rows[0].id, session.hash, session.expiresAt]);
    await client.query('COMMIT');
    response.status(201).json({ accessToken: session.token, user: { fullName: user.rows[0].full_name, role: 'user' } });
  } catch (error) { await client.query('ROLLBACK'); if (error.code === '23505') return response.status(409).json({ error: 'این ایمیل قبلاً ثبت شده است.' }); throw error; } finally { client.release(); }
}));

app.post('/api/auth/login', authLimit, asyncRoute(async (request, response) => {
  const { email, password } = request.body;
  if (!validEmail(email) || typeof password !== 'string') return response.status(400).json({ error: 'اطلاعات ورود معتبر نیست.' });
  const result = await pool.query('SELECT u.id, u.full_name, u.password_hash, u.is_active, COALESCE(a.role, \'user\') AS role FROM users u LEFT JOIN admin_users a ON a.user_id = u.id WHERE u.email = lower($1)', [email]);
  const user = result.rows[0];
  if (!user || user.role !== 'user' || !user.is_active || !(await bcrypt.compare(password, user.password_hash))) return response.status(401).json({ error: 'ایمیل یا رمز عبور نادرست است.' });
  const session = issueSession(user.id, user.role);
  await pool.query('INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES (gen_random_uuid(), $1, $2, $3)', [user.id, session.hash, session.expiresAt]);
  response.json({ accessToken: session.token, user: { fullName: user.full_name, role: user.role } });
}));
app.post('/api/auth/admin/login', authLimit, asyncRoute(async (request, response) => {
  const { email, password } = request.body;
  if (!validEmail(email) || typeof password !== 'string') return response.status(400).json({ error: 'اطلاعات ورود معتبر نیست.' });
  const result = await pool.query('SELECT u.id, u.full_name, u.password_hash, u.is_active, a.role FROM users u JOIN admin_users a ON a.user_id = u.id WHERE u.email = lower($1)', [email]);
  const user = result.rows[0];
  if (!user || user.role !== 'admin' || !user.is_active || !(await bcrypt.compare(password, user.password_hash))) return response.status(401).json({ error: 'اطلاعات مدیر نادرست است.' });
  const session = issueSession(user.id, 'admin');
  await pool.query('INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES (gen_random_uuid(), $1, $2, $3)', [user.id, session.hash, session.expiresAt]);
  response.json({ accessToken: session.token, user: { fullName: user.full_name, role: 'admin' } });
}));
app.post('/api/auth/logout', auth, asyncRoute(async (request, response) => { await pool.query('UPDATE sessions SET revoked_at = NOW() WHERE token_hash = $1', [tokenHash(request.token)]); response.status(204).end(); }));

app.get('/api/products', asyncRoute(async (request, response) => { const q = typeof request.query.q === 'string' ? `%${request.query.q}%` : '%'; const result = await pool.query('SELECT p.*, c.name AS "categoryName" FROM products p LEFT JOIN categories c ON c.id = p.category_id WHERE p.is_active AND (p.name ILIKE $1 OR p.description ILIKE $1) ORDER BY p.created_at DESC', [q]); response.json({ data: result.rows }); }));
app.get('/api/categories', asyncRoute(async (_, response) => response.json({ data: (await pool.query('SELECT * FROM categories WHERE is_active ORDER BY name')).rows })));
app.get('/api/profile', auth, asyncRoute(async (request, response) => response.json({ data: request.user })));
app.patch('/api/profile', auth, asyncRoute(async (request, response) => { if (!requiredString(request.body, 'fullName', 120)) return response.status(400).json({ error: 'نام معتبر نیست.' }); const result = await pool.query('UPDATE users SET full_name = $1 WHERE id = $2 RETURNING id, full_name, email, is_active', [request.body.fullName.trim(), request.user.id]); response.json({ data: result.rows[0] }); }));
app.get('/api/orders', auth, asyncRoute(async (request, response) => response.json({ data: (await pool.query('SELECT * FROM orders WHERE user_id = $1 ORDER BY created_at DESC', [request.user.id])).rows })));
app.post('/api/orders', auth, asyncRoute(async (request, response) => { const items = request.body.items; if (!Array.isArray(items) || !items.length || items.some(item => !item.productId || !Number.isInteger(item.quantity) || item.quantity < 1 || item.quantity > 99)) return response.status(400).json({ error: 'اقلام سفارش معتبر نیستند.' }); const client = await pool.connect(); try { await client.query('BEGIN'); const ids = items.map(item => item.productId); const products = await client.query('SELECT id, price FROM products WHERE id = ANY($1) AND is_active', [ids]); if (products.rowCount !== ids.length) return response.status(400).json({ error: 'محصولی نامعتبر است.' }); const prices = new Map(products.rows.map(product => [product.id, Number(product.price)])); const total = items.reduce((sum, item) => sum + prices.get(item.productId) * item.quantity, 0); const order = await client.query('INSERT INTO orders (id, user_id, total_price) VALUES (gen_random_uuid(), $1, $2) RETURNING *', [request.user.id, total]); for (const item of items) await client.query('INSERT INTO order_items (id, order_id, product_id, quantity, unit_price) VALUES (gen_random_uuid(), $1, $2, $3, $4)', [order.rows[0].id, item.productId, item.quantity, prices.get(item.productId)]); await client.query('COMMIT'); response.status(201).json({ data: order.rows[0] }); } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); } }));
app.get('/api/orders/:id/items', auth, asyncRoute(async (request, response) => response.json({ data: (await pool.query('SELECT oi.* FROM order_items oi JOIN orders o ON o.id = oi.order_id WHERE oi.order_id = $1 AND o.user_id = $2', [request.params.id, request.user.id])).rows })));

app.get('/api/admin/products', auth, adminOnly, asyncRoute(async (_, response) => response.json({ data: (await pool.query('SELECT * FROM products ORDER BY created_at DESC')).rows })));
app.post('/api/admin/products', auth, adminOnly, asyncRoute(async (request, response) => { const { name, description = '', price, categoryId, imageUrl } = request.body; if (!requiredString(request.body, 'name', 180) || !Number.isInteger(price) || price < 0) return response.status(400).json({ error: 'اطلاعات محصول معتبر نیست.' }); const client = await pool.connect(); try { await client.query('BEGIN'); const result = await client.query('INSERT INTO products (id, name, description, price, category_id, image_url) VALUES (gen_random_uuid(), $1, $2, $3, $4, $5) RETURNING *', [name.trim(), description, price, categoryId || null, imageUrl || null]); await audit(client, request.user.id, 'create', 'product', result.rows[0].id, { name }); await client.query('COMMIT'); response.status(201).json({ data: result.rows[0] }); } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); } }));
app.patch('/api/admin/products/:id', auth, adminOnly, asyncRoute(async (request, response) => { const { name, description, price, categoryId, imageUrl, isActive } = request.body; if (name !== undefined && !requiredString(request.body, 'name', 180)) return response.status(400).json({ error: 'نام محصول معتبر نیست.' }); if (price !== undefined && (!Number.isInteger(price) || price < 0)) return response.status(400).json({ error: 'قیمت محصول معتبر نیست.' }); const result = await pool.query('UPDATE products SET name = COALESCE($1, name), description = COALESCE($2, description), price = COALESCE($3, price), category_id = COALESCE($4, category_id), image_url = COALESCE($5, image_url), is_active = COALESCE($6, is_active), updated_at = NOW() WHERE id = $7 RETURNING *', [name?.trim(), description, price, categoryId, imageUrl, isActive, request.params.id]); if (!result.rowCount) return response.status(404).json({ error: 'محصول پیدا نشد.' }); await pool.query('INSERT INTO audit_logs (id, admin_user_id, action, entity_type, entity_id) SELECT gen_random_uuid(), id, $1, $2, $3 FROM admin_users WHERE user_id = $4', ['update', 'product', request.params.id, request.user.id]); response.json({ data: result.rows[0] }); }));
app.delete('/api/admin/products/:id', auth, adminOnly, asyncRoute(async (request, response) => { const result = await pool.query('UPDATE products SET is_active = FALSE, updated_at = NOW() WHERE id = $1 RETURNING id', [request.params.id]); if (!result.rowCount) return response.status(404).json({ error: 'محصول پیدا نشد.' }); await pool.query('INSERT INTO audit_logs (id, admin_user_id, action, entity_type, entity_id) SELECT gen_random_uuid(), id, $1, $2, $3 FROM admin_users WHERE user_id = $4', ['deactivate', 'product', request.params.id, request.user.id]); response.status(204).end(); }));
app.patch('/api/admin/orders/:id', auth, adminOnly, asyncRoute(async (request, response) => { const statuses = ['new', 'reviewing', 'shipping', 'completed', 'cancelled']; if (!statuses.includes(request.body.status)) return response.status(400).json({ error: 'وضعیت نامعتبر است.' }); const client = await pool.connect(); try { await client.query('BEGIN'); const result = await client.query('UPDATE orders SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING *', [request.body.status, request.params.id]); if (!result.rowCount) return response.status(404).json({ error: 'سفارش پیدا نشد.' }); await audit(client, request.user.id, 'update_status', 'order', request.params.id, { status: request.body.status }); await client.query('COMMIT'); response.json({ data: result.rows[0] }); } catch (error) { await client.query('ROLLBACK'); throw error; } finally { client.release(); } }));
app.get('/api/admin/categories', auth, adminOnly, asyncRoute(async (_, response) => response.json({ data: (await pool.query('SELECT * FROM categories ORDER BY created_at DESC')).rows })));
app.post('/api/admin/categories', auth, adminOnly, asyncRoute(async (request, response) => { if (!requiredString(request.body, 'name', 120)) return response.status(400).json({ error: 'نام دسته‌بندی معتبر نیست.' }); const result = await pool.query('INSERT INTO categories (id, name, image_url) VALUES (gen_random_uuid(), $1, $2) RETURNING *', [request.body.name.trim(), request.body.imageUrl || null]); await pool.query('INSERT INTO audit_logs (id, admin_user_id, action, entity_type, entity_id) SELECT gen_random_uuid(), id, $1, $2, $3 FROM admin_users WHERE user_id = $4', ['create', 'category', result.rows[0].id, request.user.id]); response.status(201).json({ data: result.rows[0] }); }));
app.patch('/api/admin/categories/:id', auth, adminOnly, asyncRoute(async (request, response) => { if (!requiredString(request.body, 'name', 120)) return response.status(400).json({ error: 'نام دسته‌بندی معتبر نیست.' }); const result = await pool.query('UPDATE categories SET name = $1, image_url = COALESCE($2, image_url) WHERE id = $3 RETURNING *', [request.body.name.trim(), request.body.imageUrl, request.params.id]); if (!result.rowCount) return response.status(404).json({ error: 'دسته‌بندی پیدا نشد.' }); await audit(pool, request.user.id, 'update', 'category', request.params.id); response.json({ data: result.rows[0] }); }));
app.delete('/api/admin/categories/:id', auth, adminOnly, asyncRoute(async (request, response) => { const result = await pool.query('UPDATE categories SET is_active = FALSE WHERE id = $1 RETURNING id', [request.params.id]); if (!result.rowCount) return response.status(404).json({ error: 'دسته‌بندی پیدا نشد.' }); await audit(pool, request.user.id, 'deactivate', 'category', request.params.id); response.status(204).end(); }));
app.get('/api/admin/orders', auth, adminOnly, asyncRoute(async (_, response) => response.json({ data: (await pool.query('SELECT o.*, u.full_name, u.email FROM orders o JOIN users u ON u.id = o.user_id ORDER BY o.created_at DESC')).rows })));
app.get('/api/admin/orders/:id/items', auth, adminOnly, asyncRoute(async (request, response) => response.json({ data: (await pool.query('SELECT * FROM order_items WHERE order_id = $1', [request.params.id])).rows })));
app.get('/api/admin/users', auth, adminOnly, asyncRoute(async (_, response) => response.json({ data: (await pool.query('SELECT id, full_name, email, is_active, created_at FROM users ORDER BY created_at DESC')).rows })));
app.patch('/api/admin/users/:id/status', auth, adminOnly, asyncRoute(async (request, response) => { if (typeof request.body.isActive !== 'boolean') return response.status(400).json({ error: 'وضعیت حساب معتبر نیست.' }); const result = await pool.query('UPDATE users SET is_active = $1 WHERE id = $2 RETURNING id, full_name, email, is_active', [request.body.isActive, request.params.id]); if (!result.rowCount) return response.status(404).json({ error: 'کاربر پیدا نشد.' }); await audit(pool, request.user.id, request.body.isActive ? 'activate' : 'deactivate', 'user', request.params.id); response.json({ data: result.rows[0] }); }));
app.use((error, _, response, __) => { console.error(error); response.status(500).json({ error: 'خطای داخلی سرور.' }); });
app.listen(Number(process.env.PORT || 8080), () => console.log(`Sekkechi API listening on port ${process.env.PORT || 8080}`));

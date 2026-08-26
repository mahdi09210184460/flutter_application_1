const { Pool } = require('pg');

const expected = ['users', 'admin_users', 'sessions', 'products', 'categories', 'orders', 'order_items', 'news', 'banners', 'app_settings', 'audit_logs'];
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL must be configured');
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
pool.query("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_name = ANY($1)", [expected]).then(({ rows }) => {
  const found = new Set(rows.map(row => row.table_name));
  const missing = expected.filter(table => !found.has(table));
  if (missing.length) throw new Error(`Missing tables: ${missing.join(', ')}`);
  console.log(`Verified ${expected.length} required tables.`);
}).catch(error => { console.error(error.message); process.exitCode = 1; }).finally(() => pool.end());
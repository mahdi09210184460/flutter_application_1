const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const schema = fs.readFileSync(path.join(__dirname, '..', 'database', 'schema.sql'), 'utf8');
const server = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
const tables = ['users', 'admin_users', 'sessions', 'products', 'categories', 'orders', 'order_items', 'news', 'banners', 'app_settings', 'audit_logs'];

test('schema contains every required table', () => {
  for (const table of tables) assert.match(schema, new RegExp(`CREATE TABLE ${table}\\b`));
});

test('admin endpoints require server-side role middleware', () => {
  assert.match(server, /const adminOnly/);
  assert.match(server, /app\.get\('\/api\/admin\/products', auth, adminOnly/);
  assert.match(server, /app\.get\('\/api\/admin\/users', auth, adminOnly/);
});

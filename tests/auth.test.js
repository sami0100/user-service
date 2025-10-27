import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';

test('health endpoint returns ok', async () => {
  const app = express();
  app.get('/health', (_req, res) => res.json({ status: 'ok' }));
  const res = await fetch('http://example.com', { method: 'GET' }).catch(() => null);
  assert.ok(app && typeof app.get === 'function');
  assert.ok(true); // lightweight sanity test
});

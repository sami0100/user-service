import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import mysql from 'mysql2/promise';

const PORT = process.env.PORT || 3001;
const DB_HOST = process.env.DB_HOST || 'localhost';
const DB_PORT = process.env.DB_PORT || 3306;
const DB_NAME = process.env.DB_NAME || 'usersdb';
const DB_USER = process.env.DB_USER || 'root';
const DB_PASSWORD = process.env.DB_PASSWORD || 'password';
const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';

const app = express();
app.use(express.json());

let pool;
async function getPool() {
  if (!pool) {
    pool = mysql.createPool({
      host: DB_HOST,
      port: DB_PORT,
      user: DB_USER,
      password: DB_PASSWORD,
      database: DB_NAME,
      waitForConnections: true,
      connectionLimit: 10
    });
  }
  return pool;
}

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'user-service' });
});

app.post('/signup', async (req, res) => {
  const { email, password, name } = req.body || {};
  if (!email || !password || !name) return res.status(400).json({ error: 'email, password, name required' });
  const hash = await bcrypt.hash(password, 10);
  const conn = await (await getPool()).getConnection();
  try {
    await conn.execute('INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)', [email, hash, name]);
    res.status(201).json({ message: 'user created' });
  } catch (e) {
    if (e && e.code === 'ER_DUP_ENTRY') {
      res.status(409).json({ error: 'email already exists' });
    } else {
      res.status(500).json({ error: 'internal error' });
    }
  } finally {
    conn.release();
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email, password required' });
  const conn = await (await getPool()).getConnection();
  try {
    const [rows] = await conn.execute('SELECT id, email, password_hash, name FROM users WHERE email = ?', [email]);
    if (!Array.isArray(rows) || rows.length === 0) return res.status(401).json({ error: 'invalid credentials' });
    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });
    const token = jwt.sign({ sub: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (e) {
    res.status(500).json({ error: 'internal error' });
  } finally {
    conn.release();
  }
});

function auth(req, res, next) {
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'missing token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'invalid token' });
  }
}

app.get('/me', auth, (req, res) => {
  res.json({ id: req.user.sub, email: req.user.email, name: req.user.name });
});



app.post('/reset-password', async (req, res) => {
  const { email, newPassword } = req.body || {};
  if (!email || !newPassword) return res.status(400).json({ error: 'email, newPassword required' });
  const hash = await bcrypt.hash(newPassword, 10);
  const conn = await (await getPool()).getConnection();
  try {
    const [result] = await conn.execute('UPDATE users SET password_hash = ? WHERE email = ?', [hash, email]);
    if (result.affectedRows === 0) return res.status(404).json({ error: 'user not found' });
    res.json({ message: 'password updated' });
  } catch (e) {
    res.status(500).json({ error: 'internal error' });
  } finally {
    conn.release();
  }
});

app.put('/profile', auth, async (req, res) => {
  const { name } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name required' });
  const conn = await (await getPool()).getConnection();
  try {
    const [result] = await conn.execute('UPDATE users SET name = ? WHERE id = ?', [name, req.user.sub]);
    if (result.affectedRows === 0) return res.status(404).json({ error: 'user not found' });
    res.json({ message: 'profile updated', name });
  } catch (e) {
    res.status(500).json({ error: 'internal error' });
  } finally {
    conn.release();
  }
});

app.listen(PORT, () => {
  console.log(`user-service listening on :${PORT}`);
});

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const pool = require('./db');
const authenticateToken = require('./authJWT');

const app = express();
app.set('trust proxy', 1);
app.use(express.json());

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 10,
  message: { error: 'Too many attempts, try again later.' },
});

// ---------- SIGNUP ----------
app.post('/signup', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password || password.length < 8) {
      return res.status(400).json({ error: 'Invalid username or password (min 8 chars)' });
    }

    console.log("Attempting to connect CloudSQL");
    const existing = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'Username already taken' });
    }
    console.log("Username is unique");

    const hashedPassword = await bcrypt.hash(password, 12);
    console.log("Hashgin password");

    const result = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id',
      [username, hashedPassword]
    );
    console.log("Username created");

    const userId = result.rows[0].id;
    const token = jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '7d' });
    console.log("Assisgning new JWT to user");

    res.status(201).json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- LOGIN ----------
app.post('/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;

    const result = await pool.query('SELECT id, password_hash FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ---------- PROTECTED EXAMPLE ----------
app.get('/profile', authenticateToken, async (req, res) => {
  const result = await pool.query('SELECT id, username FROM users WHERE id = $1', [req.user.userId]);
  res.json(result.rows[0]);
});

app.get('/users', authLimiter, async(req, res) => {
    const userList = await pool.query("SELECT username from users");
    userarr = [];
    for (i=0; i<userList.rowCount; i++) { userarr.push(userList.rows[i].username); }
    res.status(200).json({users:userarr});
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

import express from "express";
import mysql from "mysql2";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import cors from "cors";
import dotenv from "dotenv";
dotenv.config();

const app = express();
const SECRET_KEY_BASE64 = process.env.SECRET_KEY_BASE64;
const SECRET_KEY = Buffer.from(SECRET_KEY_BASE64, "base64").toString("utf-8");

// Middleware
app.use(cors());
app.use(express.json());

// MySQL Pool Connection
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Helper untuk encoding Base64URL
function base64UrlEncode(str) {
  return Buffer.from(str)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

// Helper untuk membuat JWT
function createJWT(header, payload) {
  const headerEncoded = base64UrlEncode(JSON.stringify(header));
  const payloadEncoded = base64UrlEncode(JSON.stringify(payload));
  const data = `${headerEncoded}.${payloadEncoded}`;

  const signature = crypto
    .createHmac("sha256", SECRET_KEY)
    .update(data)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  return `${data}.${signature}`;
}

// JWT Authentication Middleware
function authenticateToken(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });

  const [headerEncoded, payloadEncoded, signature] = token.split(".");
  const data = `${headerEncoded}.${payloadEncoded}`;
  const expectedSignature = crypto
    .createHmac("sha256", SECRET_KEY)
    .update(data)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  if (signature !== expectedSignature) {
    return res.status(403).json({ error: "Invalid token" });
  }

  const payload = JSON.parse(Buffer.from(payloadEncoded, "base64").toString("utf8"));
  req.user = payload;

  next();
}

// Endpoint Register
app.post("/api/auth/register", async (req, res) => {
  const { fullname, nickname, password, email } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    pool.query(
      "INSERT INTO users (fullname, nickname, password, email, created_at, updated_at) VALUES (?, ?, ?, ?, NOW(), NOW())",
      [fullname, nickname, hashedPassword, email],
      (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "User registered successfully!" });
      }
    );
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Endpoint Login
app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body;

  pool.query("SELECT * FROM users WHERE email = ?", [email], async (err, users) => {
    if (err) return res.status(500).json({ error: err.message });
    if (users.length === 0) return res.status(400).json({ error: "Email not found" });

    const user = users[0];
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) return res.status(400).json({ error: "Invalid password" });

    // Create token manually with HS256 algorithm
    const header = { alg: "HS256", typ: "JWT" };
    const payload = { id: user.id, fullname: user.fullname, email: user.email, exp: Math.floor(Date.now() / 1000) + 86400 };

    const token = createJWT(header, payload);

    pool.query("SELECT * FROM sessions WHERE user_id = ?", [user.id], (err, sessions) => {
      if (err) return res.status(500).json({ error: err.message });

      if (sessions.length > 0) {
        pool.query(
          "UPDATE sessions SET token = ?, expires_at = DATE_ADD(NOW(), INTERVAL 1 DAY) WHERE user_id = ?",
          [token, user.id],
          (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ token });
          }
        );
      } else {
        pool.query(
          "INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 1 DAY))",
          [user.id, token],
          (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ token });
          }
        );
      }
    });
  });
});

// Endpoint Logout
app.post("/api/auth/logout", authenticateToken, (req, res) => {
  const token = req.headers["authorization"]?.split(" ")[1];

  pool.query("DELETE FROM sessions WHERE token = ?", [token], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: "Logout successful" });
  });
});

// Endpoint Add Transaction (with authentication)
app.post("/api/transactions", authenticateToken, (req, res) => {
  const { type, category, description, amount } = req.body;
  const userId = req.user.id;

  pool.query(
    "INSERT INTO transactions (user_id, type, category, description, amount) VALUES (?, ?, ?, ?, ?)",
    [userId, type, category, description, amount],
    (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "Transaction added successfully" });
    }
  );
});

// Endpoint Get Transactions (only for logged-in users)
app.get("/api/transactions", authenticateToken, (req, res) => {
  const userId = req.user.id;

  pool.query("SELECT * FROM transactions WHERE user_id = ?", [userId], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

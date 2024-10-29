import express from "express";
import mysql from "mysql2";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";
dotenv.config();

const app = express();
const SECRET_KEY = process.env.SECRET_KEY;

// Middleware
app.use(
  cors({
    origin: process.env.CLIENT_URL,
  })
);
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

// JWT Authentication Middleware
function authenticateToken(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);

    // Check token in sessions table
    pool.query(
      "SELECT * FROM sessions WHERE token = ?",
      [token],
      (err, results) => {
        if (err)
          return res.status(500).json({ error: err.message, code: err.code });
        if (results.length === 0) return res.sendStatus(403); // Token not found

        req.user = user;
        next();
      }
    );
  });
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
        if (err) {
          const statusCode = err.statusCode || 500;
          return res
            .status(statusCode)
            .json({ error: err.message, code: statusCode });
        }
        res.json({ message: "User registered successfully!" });
      }
    );
  } catch (error) {
    return res.status(500).json({ error: error.message, code: 500 });
  }
});

// Endpoint Login
app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body;

  pool.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, users) => {
      if (err)
        return res.status(500).json({ error: err.message, code: err.code });
      if (users.length === 0)
        return res.status(400).json({ error: "Email not found" });

      const user = users[0];
      const isValidPassword = await bcrypt.compare(password, user.password);

      if (!isValidPassword)
        return res.status(400).json({ error: "Invalid password" });

      const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY);

      // Cek apakah pengguna sudah memiliki sesi
      pool.query(
        "SELECT * FROM sessions WHERE user_id = ?",
        [user.id],
        (err, sessions) => {
          if (err) return res.status(500).json({ error: err.message });

          if (sessions.length > 0) {
            // Jika sesi ada, perbarui token
            pool.query(
              "UPDATE sessions SET token = ?, expires_at = DATE_ADD(NOW(), INTERVAL 1 DAY) WHERE user_id = ?",
              [token, user.id],
              (err) => {
                if (err) return res.status(500).json({ error: err.message });
                return res.json({ token });
              }
            );
          } else {
            // Jika tidak ada sesi, buat sesi baru
            pool.query(
              "INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 1 DAY))",
              [user.id, token],
              (err) => {
                if (err) return res.status(500).json({ error: err.message });
                return res.json({ token });
              }
            );
          }
        }
      );
    }
  );
});

// Endpoint Logout
app.post("/api/auth/logout", authenticateToken, (req, res) => {
  const token = req.headers["authorization"]?.split(" ")[1];

  pool.query("DELETE FROM sessions WHERE token = ?", [token], (err) => {
    if (err)
      return res.status(500).json({ error: err.message, code: err.code });
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
    (err, result) => {
      if (err)
        return res.status(500).json({ error: err.message, code: err.code });
      res.json({ message: "Transaction added successfully" });
    }
  );
});

// Endpoint Get Transactions (only for logged-in users)
app.get("/api/transactions", authenticateToken, (req, res) => {
  const userId = req.user.id;

  pool.query(
    "SELECT * FROM transactions WHERE user_id = ?",
    [userId],
    (err, rows) => {
      if (err)
        return res.status(500).json({ error: err.message, code: err.code });
      res.json(rows);
    }
  );
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

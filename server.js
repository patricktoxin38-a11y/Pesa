import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import bcrypt from "bcryptjs";
import cookieSession from "cookie-session";
import Database from "better-sqlite3";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// =========================
// DATABASE
// =========================

const db = new Database(
  path.join(__dirname, "data.db")
);

db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  balance INTEGER NOT NULL DEFAULT 0,
  role TEXT NOT NULL DEFAULT 'user',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  reward INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  proof TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS withdrawals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  amount INTEGER NOT NULL,
  phone TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

// =========================
// ADMIN ACCOUNT
// =========================

const adminEmail =
  process.env.ADMIN_EMAIL ||
  "admin@taskhub.local";

const adminPassword =
  process.env.ADMIN_PASSWORD ||
  "ChangeMe123!";

const existingAdmin = db
  .prepare(
    "SELECT id FROM users WHERE email = ?"
  )
  .get(adminEmail);

if (!existingAdmin) {
  const hash = bcrypt.hashSync(
    adminPassword,
    10
  );

  db.prepare(`
    INSERT INTO users
    (name, email, password_hash, role)
    VALUES (?, ?, ?, 'admin')
  `).run(
    "Administrator",
    adminEmail,
    hash
  );

  console.log(
    "Admin account created:",
    adminEmail
  );
}

// =========================
// EXAMPLE TASKS
// =========================

const taskCount = db
  .prepare(
    "SELECT COUNT(*) AS count FROM tasks"
  )
  .get().count;

if (taskCount === 0) {
  const addTask = db.prepare(`
    INSERT INTO tasks
    (title, description, reward)
    VALUES (?, ?, ?)
  `);

  addTask.run(
    "Example survey task",
    "Replace this with a genuine client-funded task.",
    50
  );

  addTask.run(
    "Example online task",
    "Replace this with real instructions before publishing.",
    30
  );
}

// =========================
// MIDDLEWARE
// =========================

app.use(
  express.urlencoded({
    extended: true
  })
);

app.use(express.json());

app.use(
  cookieSession({
    name: "session",

    keys: [
      process.env.SESSION_SECRET ||
        "change-this-secret-in-production"
    ],

    httpOnly: true,
    sameSite: "lax",

    secure:
      process.env.NODE_ENV === "production",

    maxAge:
      1000 *
      60 *
      60 *
      24 *
      7
  })
);

// =========================
// STATIC FRONTEND
// =========================

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);

// =========================
// SESSION HELPER
// =========================

function currentUser(req) {
  return req.session?.user || null;
}

// =========================
// LOGIN REQUIRED
// =========================

function requireLogin(
  req,
  res,
  next
) {
  if (!currentUser(req)) {
    return res.status(401).json({
      error: "Please login first."
    });
  }

  next();
}

// =========================
// ADMIN REQUIRED
// =========================

function requireAdmin(
  req,
  res,
  next
) {
  const user = currentUser(req);

  if (!user) {
    return res.status(401).json({
      error: "Please login first."
    });
  }

  if (user.role !== "admin") {
    return res.status(403).json({
      error: "Admin access required."
    });
  }

  next();
}

// =========================
// HOME
// =========================

app.get("/", (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "index.html"
    )
  );
});

// =========================
// REGISTER
// =========================

app.post(
  "/api/register",
  async (req, res) => {
    try {
      const name =
        String(
          req.body.name || ""
        ).trim();

      const email =
        String(
          req.body.email || ""
        )
          .trim()
          .toLowerCase();

      const password =
        String(
          req.body.password || ""
        );

      if (!name) {
        return res.status(400).json({
          error: "Name is required."
        });
      }

      if (!email) {
        return res.status(400).json({
          error: "Email is required."
        });
      }

      if (!password) {
        return res.status(400).json({
          error: "Password is required."
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          error:
            "Password must be at least 6 characters."
        });
      }

      const existingUser = db
        .prepare(
          "SELECT id FROM users WHERE email = ?"
        )
        .get(email);

      if (existingUser) {
        return res.status(409).json({
          error:
            "An account with that email already exists."
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          10
        );

      const result = db
        .prepare(`
          INSERT INTO users
          (name, email, password_hash)
          VALUES (?, ?, ?)
        `)
        .run(
          name,
          email,
          passwordHash
        );

      const user = db
        .prepare(`
          SELECT
            id,
            name,
            email,
            balance,
            role,
            created_at
          FROM users
          WHERE id = ?
        `)
        .get(result.lastInsertRowid);

      req.session.user = user;

      return res.status(201).json({
        success: true,
        message:
          "Account created successfully.",
        user
      });

    } catch (error) {
      console.error(
        "REGISTER ERROR:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to create account."
      });
    }
  }
);

// =========================
// LOGIN
// =========================

app.post(
  "/api/login",
  async (req, res) => {
    try {
      const email =
        String(
          req.body.email || ""
        )
          .trim()
          .toLowerCase();

      const password =
        String(
          req.body.password || ""
        );

      if (!email || !password) {
        return res.status(400).json({
          error:
            "Email and password are required."
        });
      }

      const user = db
        .prepare(
          "SELECT * FROM users WHERE email = ?"
        )
        .get(email);

      if (!user) {
        return res.status(401).json({
          error:
            "Invalid email or password."
        });
      }

      const valid =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!valid) {
        return res.status(401).json({
          error:
            "Invalid email or password."
        });
      }

      req.session.user = {
        id: user.id,
        name: user.name,
        email: user.email,
        balance: user.balance,
        role: user.role
      };

      return res.json({
        success: true,
        message: "Login successful.",
        user: req.session.user
      });

    } catch (error) {
      console.error(
        "LOGIN ERROR:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to login."
      });
    }
  }
);

// =========================
// LOGOUT
// =========================

app.post(
  "/api/logout",
  (req, res) => {
    req.session = null;

    res.json({
      success: true,
      message:
        "Logged out successfully."
    });
  }
);

// =========================
// CURRENT USER
// =========================

app.get(
  "/api/me",
  requireLogin,
  (req, res) => {
    const user = db
      .prepare(`
        SELECT
          id,
          name,
          email,
          balance,
          role,
          created_at
        FROM users
        WHERE id = ?
      `)
      .get(
        req.session.user.id
      );

    if (!user) {
      req.session = null;

      return res.status(401).json({
        error:
          "User account not found."
      });
    }

    req.session.user = user;

    res.json({
      success: true,
      user
    });
  }
);

// =========================
// GET TASKS
// =========================

app.get(
  "/api/tasks",
  (req, res) => {
    try {
      const tasks = db
        .prepare(`
          SELECT *
          FROM tasks
          WHERE status = 'active'
          ORDER BY id DESC
        `)
        .all();

      res.json({
        success: true,
        tasks
      });

    } catch (error) {
      console.error(
        "TASKS ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load tasks."
      });
    }
  }
);

// =========================
// GET SINGLE TASK
// =========================

app.get(
  "/api/tasks/:id",
  (req, res) => {
    try {
      const taskId =
        Number(req.params.id);

      if (!Number.isInteger(taskId)) {
        return res.status(400).json({
          error: "Invalid task ID."
        });
      }

      const task = db
        .prepare(`
          SELECT *
          FROM tasks
          WHERE id = ?
        `)
        .get(taskId);

      if (!task) {
        return res.status(404).json({
          error: "Task not found."
        });
      }

      res.json({
        success: true,
        task
      });

    } catch (error) {
      console.error(
        "TASK ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Unable to load task."
      });
    }
  }
);

// =========================
// SUBMIT TASK
// =========================

app.post(
  "/api/submissions",
  requireLogin,
  (req, res) => {
    try {
      const taskId =
        Number(req.body.task_id);

      const proof =
        String(
          req.body.proof || ""
        ).trim();

      if (!Number.isInteger(taskId)) {
        return res.status(400).json({
          error:
            "Valid task ID is required."
        });
      }

      if (!proof) {
        return res.status(400).json({
          error:
            "Proof is required."
        });
      }

      const task = db
        .prepare(`
          SELECT *
          FROM tasks
          WHERE id = ?
          AND status = 'active'

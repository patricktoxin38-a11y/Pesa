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

const db = new Database(path.join(__dirname, "data.db"));

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
  process.env.ADMIN_EMAIL || "admin@taskhub.local";

const adminPassword =
  process.env.ADMIN_PASSWORD || "ChangeMe123!";

const existingAdmin = db
  .prepare("SELECT id FROM users WHERE email = ?")
  .get(adminEmail);

if (!existingAdmin) {
  const hash = bcrypt.hashSync(adminPassword, 10);

  db.prepare(`
    INSERT INTO users
    (name, email, password_hash, role)
    VALUES (?, ?, ?, 'admin')
  `).run(
    "Administrator",
    adminEmail,
    hash
  );
}

// =========================
// EXAMPLE TASKS
// =========================

const taskCount = db
  .prepare("SELECT COUNT(*) AS count FROM tasks")
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

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  cookieSession({
    name: "session",
    keys: [
      process.env.SESSION_SECRET ||
      "replace-this-secret-in-production"
    ],
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 24 * 7
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
// HOME PAGE
// =========================

app.get("/", (req, res) => {
  res.sendFile(
    path.join(__dirname, "index.html")
  );
});

// =========================
// SESSION HELPER
// =========================

function currentUser(req) {
  return req.session?.user || null;
}

// =========================
// LOGIN REQUIRED
// =========================

function requireLogin(req, res, next) {
  if (!currentUser(req)) {
    return res.status(401).json({
      error: "Please log in first."
    });
  }

  next();
}

// =========================
// ADMIN REQUIRED
// =========================

function requireAdmin(req, res, next) {
  const u = currentUser(req);

  if (!u || u.role !== "admin") {
    return res.status(403).json({
      error: "Admin access required."
    });
  }

  next();
}

// =========================
// REGISTER
// =========================

app.post("/api/register", (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();
    const password = String(req.body.password || "");

    if (!name || !email || !password) {
      return res.status(400).json({
        error: "Name, email and password are required."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Password must be at least 6 characters."
      });
    }

    const existing = db
      .prepare("SELECT id FROM users WHERE email = ?")
      .get(email);

    if (existing) {
      return res.status(409).json({
        error: "An account with that email already exists."
      });
    }

    const passwordHash = bcrypt.hashSync(password, 10);

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

    const newUser = db
      .prepare(`
        SELECT id, name, email, balance, role
        FROM users
        WHERE id = ?
      `)
      .get(result.lastInsertRowid);

    req.session.user = newUser;

    return res.status(201).json({
      success: true,
      message: "Account created successfully.",
      user: newUser
    });

  } catch (error) {
    console.error("REGISTER ERROR:", error);

    return res.status(500).json({
      error: "Unable to create account."
    });
  }
});

// =========================
// LOGIN
// =========================

app.post("/api/login", (req, res) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();

    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required."
      });
    }

    const found = db
      .prepare(`
        SELECT *
        FROM users
        WHERE email = ?
      `)
      .get(email);

    if (!found) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const valid = bcrypt.compareSync(
      password,
      found.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const loggedUser = {
      id: found.id,
      name: found.name,
      email: found.email,
      balance: found.balance,
      role: found.role
    };

    req.session.user = loggedUser;

    return res.json({
      success: true,
      message: "Login successful.",
      user: loggedUser
    });

  } catch (error) {
    console.error("LOGIN ERROR:", error);

    return res.status(500).json({
      error: "Unable to log in."
    });
  }
});

// =========================
// LOGOUT
// =========================

app.post("/api/logout", (req, res) => {
  req.session = null;

  res.json({
    success: true,
    message: "Logged out successfully."
  });
});

// =========================
// CURRENT USER
// =========================

app.get("/api/me", requireLogin, (req, res) => {
  const u = currentUser(req);

  const freshUser = db
    .prepare(`
      SELECT id, name, email, balance, role, created_at
      FROM users
      WHERE id = ?
    `)
    .get(u.id);

  if (!freshUser) {
    req.session = null;

    return res.status(401).json({
      error: "User account not found."
    });
  }

  req.session.user = {
    id: freshUser.id,
    name: freshUser.name,
    email: freshUser.email,
    balance: freshUser.balance,
    role: freshUser.role
  };

  res.json({
    user: freshUser
  });
});

// =========================
// GET TASKS
// =========================

app.get("/api/tasks", (req, res) => {
  const tasks = db
    .prepare(`
      SELECT
        id,
        title,
        description,
        reward,
        status,
        created_at
      FROM tasks
      WHERE status = 'active'
      ORDER BY id DESC
    `)
    .all();

  res.json(tasks);
});

// =========================
// GET ONE TASK
// =========================

app.get("/api/tasks/:id", (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id)) {
    return res.status(400).json({
      error: "Invalid task ID."
    });
  }

  const task = db
    .prepare(`
      SELECT
        id,
        title,
        description,
        reward,
        status,
        created_at
      FROM tasks
      WHERE id = ?
    `)
    .get(id);

  if (!task) {
    return res.status(404).json({
      error: "Task not found."
    });
  }

  res.json(task);
});

// =========================
// SUBMIT TASK
// =========================

app.post(
  "/api/tasks/:id/submit",
  requireLogin,
  (req, res) => {
    try {
      const taskId = Number(req.params.id);
      const proof = String(req.body.proof || "").trim();

      if (!Number.isInteger(taskId)) {
        return res.status(400).json({
          error: "Invalid task ID."
        });
      }

      if (!proof) {
        return res.status(400).json({
          error: "Please provide proof."
        });
      }

      const task = db
        .prepare(`
          SELECT *
          FROM tasks
          WHERE id = ?
          AND status = 'active'
        `)
        .get(taskId);

      if (!task) {
        return res.status(404).json({
          error: "Task not found or inactive."
        });
      }

      const u = currentUser(req);

      const alreadySubmitted = db
        .prepare(`
          SELECT id
          FROM submissions
          WHERE task_id = ?
          AND user_id = ?
          AND status = 'pending'
        `)
        .get(taskId, u.id);

      if (alreadySubmitted) {
        return res.status(409).json({
          error: "You already submitted this task."
        });
      }

      const result = db
        .prepare(`
          INSERT INTO submissions
          (task_id, user_id, proof)
          VALUES (?, ?, ?)
        `)
        .run(
          taskId,
          u.id,
          proof
        );

      res.status(201).json({
        success: true,
        message: "Task submitted for review.",
        submissionId: result.lastInsertRowid
      });

    } catch (error) {
      console.error("SUBMISSION ERROR:", error);

      res.status(500).json({
        error: "Unable to submit task."
      });
    }
  }
);

// =========================
// MY SUBMISSIONS
// =========================

app.get(
  "/api/my-submissions",
  requireLogin,
  (req, res) => {
    const u = currentUser(req);

    const submissions = db
      .prepare(`
        SELECT
          submissions.id,
          submissions.task_id,
          submissions.proof,
          submissions.status,
          submissions.created_at,
          tasks.title,
          tasks.reward
        FROM submissions
        JOIN tasks
          ON tasks.id = submissions.task_id
        WHERE submissions.user_id = ?
        ORDER BY submissions.id DESC
      `)
      .all(u.id);

    res.json(submissions);
  }
);

// =========================
// WITHDRAW
// =========================

app.post(
  "/api/withdraw",
  requireLogin,
  (req, res) => {
    try {
      const amount = Number(req.body.amount);
      const phone = String(req.body.phone || "").trim();

      if (!Number.isInteger(amount) || amount <= 0) {
        return res.status(400).json({
          error: "Enter a valid withdrawal amount."
        });
      }

      if (!phone) {
        return res.status(400).json({
          error: "Phone number is required."
        });
      }

      const u = currentUser(req);

      const account = db
        .prepare(`
          SELECT balance
          FROM users
          WHERE id = ?
        `)
        .get(u.id);

      if (!account) {
        return res.status(404).json({
          error: "User account not found."
        });
      }

      if (amount > account.balance) {
        return res.status(400).json({
          error: "Insufficient balance."
        });
      }

      const transaction = db.transaction(() => {

        db.prepare(`
          UPDATE users
          SET balance = balance - ?
          WHERE id = ?
        `).run(
          amount,
          u.id
        );

        db.prepare(`
          INSERT INTO withdrawals
          (user_id, amount, phone)
          VALUES (?, ?, ?)
        `).run(
          u.id,
          amount,
          phone
        );
      });

      transaction();

      req.session.user = {
        ...u,
        balance: account.balance - amount
      };

      res.status(201).json({
        success: true,
        message: "Withdrawal request submitted."
      });

    } catch (error) {
      console.error("WITHDRAW ERROR:", error);

      res.status(500).json({
        error: "Unable to process withdrawal."
      });
    }
  }
);

// =========================
// MY WITHDRAWALS
// =========================

app.get(
  "/api/my-withdrawals",
  requireLogin,
  (req, res) => {

    const u = currentUser(req);

    const withdrawals = db
      .prepare(`
        SELECT
          id,
          amount,
          phone,
          status,
          created_at
        FROM withdrawals
        WHERE user_id = ?
        ORDER BY id DESC
      `)
      .all(u.id);

    res.json(withdrawals);
  }
);

// =========================
// ADMIN - USERS
// =========================

app.get(
  "/api/admin/users",
  requireAdmin,
  (req, res) => {

    const users = db
      .prepare(`
        SELECT
          id,
          name,
          email,
          balance,
          role,
          created_at
        FROM users
        ORDER BY id DESC
      `)
      .all();

    res.json(users);
  }
);

// =========================
// ADMIN - TASKS
// =========================

app.get(
  "/api/admin/tasks",
  requireAdmin,
  (req, res) => {

    const tasks = db
      .prepare(`
        SELECT *
        FROM tasks
        ORDER BY id DESC
      `)
      .all();

    res.json(tasks);
  }
);

// =========================
// ADMIN - CREATE TASK
// =========================

app.post(
  "/api/admin/tasks",
  requireAdmin,
  (req, res) => {
    try {
      const title = String(req.body.title || "").trim();
      const description =
        String(req.body.description || "").trim();
      const reward = Number(req.body.reward);

      if (!title || !description) {
        return res.status(400).json({
          error: "Title and description are required."
        });
      }

      if (!Number.isInteger(reward) || reward <= 0) {
        return res.status(400).json({
          error: "Reward must be a positive number."
        });
      }

      const result = db
        .prepare(`
          INSERT INTO tasks
          (title, description, reward)
          VALUES (?, ?, ?)
        `)
        .run(
          title,
          description,
          reward
        );

      res.status(201).json({
        success: true,
        taskId: result.lastInsertRowid
      });

    } catch (error) {
      console.error("CREATE TASK ERROR:", error);

      res.status(500).json({
        error: "Unable to create task."
      });
    }
  }
);

// =========================
// ADMIN - SUBMISSIONS
// =========================

app.get(
  "/api/admin/submissions",
  requireAdmin,
  (req, res) => {

    const submissions = db
      .prepare(`
        SELECT
          submissions.id,
          submissions.task_id,
          submissions.user_id,
          submissions.proof,
          submissions.status,
          submissions.created_at,
          users.name AS user_name,
          users.email AS user_email,
          tasks.title AS task_title,
          tasks.reward AS reward
        FROM submissions
        JOIN users
          ON users.id = submissions.user_id
        JOIN tasks
          ON tasks.id = submissions.task_id
        ORDER BY submissions.id DESC
      `)
      .all();

    res.json(submissions);
  }
);

// =========================
// ADMIN - REVIEW SUBMISSION
// =========================

app.post(
  "/api/admin/submissions/:id/review",
  requireAdmin,
  (req, res) => {

    try {
      const submissionId = Number(req.params.id);
      const status = String(req.body.status || "").trim();

      if (!["approved", "rejected"].includes(status)) {
        return res.status(400).json({
          error: "Status must be approved or rejected."
        });
      }

      const submission = db
        .prepare(`
          SELECT *
          FROM submissions
          WHERE id = ?
        `)
        .get(submissionId);

      if (!submission) {
        return res.status(404).json({
          error: "Submission not found."
        });
      }

      if (submission.status !== "pending") {
        return res.status(400).json({
          error: "This submission has already been reviewed."
        });
      }

      const task = db
        .prepare(`
          SELECT reward
          FROM tasks
          WHERE id = ?
        `)
        .get(submission.task_id);

      const transaction = db.transaction(() => {

        db.prepare(`
          UPDATE submissions
          SET status = ?
          WHERE id = ?
        `).run(
          status,
          submissionId
        );

        if (status === "approved") {
          db.prepare(`
            UPDATE users
            SET balance = balance + ?
            WHERE id = ?
          `).run(
            task.reward,
            submission.user_id
          );
        }
      });

      transaction();

      res.json({
        success: true,
        message:
          status === "approved"
            ? "Submission approved and reward added."
            : "Submission rejected."
      });

    } catch (error) {
      console.error("REVIEW ERROR:", error);

      res.status(500).json({
        error: "Unable to review submission."
      });
    }
  }
);

// =========================
// ADMIN - WITHDRAWALS
// =========================

app.get(
  "/api/admin/withdrawals",
  requireAdmin,
  (req, res) => {

    const withdrawals = db
      .prepare(`
        SELECT
          withdrawals.id,
          withdrawals.user_id,
          withdrawals.amount,
          withdrawals.phone,
          withdrawals.status,
          withdrawals.created_at,
          users.name AS user_name,
          users.email AS user_email
        FROM withdrawals
        JOIN users
          ON users.id = withdrawals.user_id
        ORDER BY withdrawals.id DESC
      `)
      .all();

    res.json(withdrawals);
  }
);

// =========================
// ADMIN - REVIEW WITHDRAWAL
// =========================

app.post(
  "/api/admin/withdrawals/:id/review",
  requireAdmin,
  (req, res) => {

    try {
      const withdrawalId = Number(req.params.id);
      const status = String(req.body.status || "").trim();

      if (!["approved", "rejected"].includes(status)) {
        return res.status(400).json({
          error: "Status must be approved or rejected."
        });
      }

      const withdrawal = db
        .prepare(`
          SELECT *
          FROM withdrawals
          WHERE id = ?
        `)
        .get(withdrawalId);

      if (!withdrawal) {
        return res.status(404).json({
          error: "Withdrawal not found."
        });
      }

      if (withdrawal.status !== "pending") {
        return res.status(400).json({
          error: "This withdrawal has already been reviewed."
        });
      }

      const transaction = db.transaction(() => {

        db.prepare(`
          UPDATE withdrawals
          SET status = ?
          WHERE id = ?
        `).run(
          status,
          withdrawalId
        );

        // Return money if withdrawal is rejected.
        if (status === "rejected") {
          db.prepare(`
            UPDATE users
            SET balance = balance + ?
            WHERE id = ?
          `).run(
            withdrawal.amount,
            withdrawal.user_id
          );
        }
      });

      transaction();

      res.json({
        success: true,
        message:
          status === "approved"
            ? "Withdrawal approved."
            : "Withdrawal rejected and balance restored."
      });

    } catch (error) {
      console.error("WITHDRAWAL REVIEW ERROR:", error);

      res.status(500).json({
        error: "Unable to review withdrawal."
      });
    }
  }
);

// =========================
// HEALTH CHECK
// =========================

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "Pesa",
    time: new Date().toISOString()
  });
});

// =========================
// FRONTEND FALLBACK
// =========================
//
// IMPORTANT:
// API routes are defined above this.
// Unknown browser pages are sent to index.html.

app.get("*", (req, res) => {
  res.sendFile(
    path.join(__dirname, "index.html")
  );
});

// =========================
// ERROR HANDLER
// =========================

app.use(
  (err, req, res, next) => {
    console.error("SERVER ERROR:", err);

    res.status(500).json({
      error: "Internal server error."
    });
  }
);

// =========================
// START SERVER
// =========================

const PORT =
  process.env.PORT || 3000;

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `Pesa server running on port ${PORT}`
    );
  }
);

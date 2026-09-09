import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import bcrypt from "bcryptjs";
import cookieSession from "cookie-session";
import Database from "better-sqlite3";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const db = new Database(path.join(__dirname, "data.db"));

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 balance INTEGER NOT NULL DEFAULT 0,
 role TEXT NOT NULL DEFAULT 'user',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tasks(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 title TEXT NOT NULL,
 description TEXT NOT NULL,
 reward INTEGER NOT NULL,
 status TEXT NOT NULL DEFAULT 'active',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS submissions(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 task_id INTEGER NOT NULL,
 user_id INTEGER NOT NULL,
 proof TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS withdrawals(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 amount INTEGER NOT NULL,
 phone TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

const adminEmail =
  process.env.ADMIN_EMAIL || "admin@taskhub.local";

const adminPassword =
  process.env.ADMIN_PASSWORD || "ChangeMe123!";

const existingAdmin = db
  .prepare("SELECT id FROM users WHERE email=?")
  .get(adminEmail);

if (!existingAdmin) {
  const hash = bcrypt.hashSync(adminPassword, 10);

  db.prepare(`
    INSERT INTO users(name,email,password_hash,role)
    VALUES(?,?,?,'admin')
  `).run(
    "Administrator",
    adminEmail,
    hash
  );
}

if (db.prepare("SELECT COUNT(*) c FROM tasks").get().c === 0) {
  const add = db.prepare(`
    INSERT INTO tasks(title,description,reward)
    VALUES(?,?,?)
  `);

  add.run(
    "Example survey task",
    "Replace this example with a genuine client-funded task. Do not publish tasks until you have a verified paying client.",
    50
  );

  add.run(
    "Example social-media task",
    "Example only. Add real instructions and proof requirements before publishing.",
    30
  );
}

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

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);

app.get("/", (req, res) => {
  res.sendFile(
    path.join(__dirname, "index.html")
  );
});

function user(req) {
  return req.session?.user || null;
}

function requireLogin(req, res, next) {
  if (!user(req)) {
    return res.status(401).json({
      error: "Please log in first."
    });
  }

  next();
}

function requireAdmin(req, res, next) {
  if (!user(req) || user(req).role !== "admin") {
    return res.status(403).json({
      error: "Admin access required."
    });
  }

  next();
}

/* =========================
   REGISTER
========================= */

app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

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

    const normalizedEmail =
      email.trim().toLowerCase();

    const exists = db
      .prepare(
        "SELECT id FROM users WHERE email=?"
      )
      .get(normalizedEmail);

    if (exists) {
      return res.status(400).json({
        error: "An account with that email already exists."
      });
    }

    const passwordHash =
      await bcrypt.hash(password, 10);

    const result = db
      .prepare(`
        INSERT INTO users(
          name,
          email,
          password_hash
        )
        VALUES(?,?,?)
      `)
      .run(
        name.trim(),
        normalizedEmail,
        passwordHash
      );

    const newUser = db
      .prepare(`
        SELECT
          id,
          name,
          email,
          balance,
          role
        FROM users
        WHERE id=?
      `)
      .get(result.lastInsertRowid);

    req.session.user = newUser;

    res.json({
      success: true,
      message: "Account created successfully.",
      user: newUser
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Registration failed."
    });
  }
});

/* =========================
   LOGIN
========================= */

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required."
      });
    }

    const normalizedEmail =
      email.trim().toLowerCase();

    const found = db
      .prepare(
        "SELECT * FROM users WHERE email=?"
      )
      .get(normalizedEmail);

    if (!found) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const valid =
      await bcrypt.compare(
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

    res.json({
      success: true,
      message: "Login successful.",
      user: loggedUser
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Login failed."
    });
  }
});

/* =========================
   LOGOUT
========================= */

app.post("/api/logout", (req, res) => {
  req.session = null;

  res.json({
    success: true,
    message: "Logged out successfully."
  });
});

/* =========================
   CURRENT USER
========================= */

app.get("/api/me", requireLogin, (req, res) => {
  const current = db
    .prepare(`
      SELECT
        id,
        name,
        email,
        balance,
        role,
        created_at
      FROM users
      WHERE id=?
    `)
    .get(user(req).id);

  if (!current) {
    req.session = null;

    return res.status(401).json({
      error: "User not found."
    });
  }

  res.json(current);
});

/* =========================
   TASKS
========================= */

app.get("/api/tasks", requireLogin, (req, res) => {
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
      WHERE status='active'
      ORDER BY id DESC
    `)
    .all();

  res.json(tasks);
});

/* =========================
   SUBMIT TASK
========================= */

app.post(
  "/api/tasks/:id/submit",
  requireLogin,
  (req, res) => {
    try {
      const taskId =
        Number(req.params.id);

      const { proof } = req.body;

      if (!proof || !proof.trim()) {
        return res.status(400).json({
          error: "Please provide proof of completed work."
        });
      }

      const task = db
        .prepare(`
          SELECT *
          FROM tasks
          WHERE id=?
          AND status='active'
        `)
        .get(taskId);

      if (!task) {
        return res.status(404).json({
          error: "Task not found or no longer active."
        });
      }

      const alreadySubmitted = db
        .prepare(`
          SELECT id
          FROM submissions
          WHERE task_id=?
          AND user_id=?
          AND status IN ('pending','approved')
        `)
        .get(
          taskId,
          user(req).id
        );

      if (alreadySubmitted) {
        return res.status(400).json({
          error: "You have already submitted this task."
        });
      }

      const result = db
        .prepare(`
          INSERT INTO submissions(
            task_id,
            user_id,
            proof
          )
          VALUES(?,?,?)
        `)
        .run(
          taskId,
          user(req).id,
          proof.trim()
        );

      res.json({
        success: true,
        message: "Task submitted for review.",
        submissionId:
          result.lastInsertRowid
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Could not submit task."
      });
    }
  }
);

/* =========================
   USER SUBMISSIONS
========================= */

app.get(
  "/api/submissions",
  requireLogin,
  (req, res) => {
    const submissions = db
      .prepare(`
        SELECT
          submissions.id,
          submissions.task_id,
          tasks.title,
          tasks.reward,
          submissions.proof,
          submissions.status,
          submissions.created_at
        FROM submissions
        JOIN tasks
          ON tasks.id=submissions.task_id
        WHERE submissions.user_id=?
        ORDER BY submissions.id DESC
      `)
      .all(user(req).id);

    res.json(submissions);
  }
);

/* =========================
   WITHDRAWAL REQUEST
========================= */

app.post(
  "/api/withdraw",
  requireLogin,
  (req, res) => {
    try {
      const amount =
        Number(req.body.amount);

      const phone =
        String(
          req.body.phone || ""
        ).trim();

      if (
        !Number.isInteger(amount) ||
        amount <= 0
      ) {
        return res.status(400).json({
          error: "Enter a valid withdrawal amount."
        });
      }

      if (!phone) {
        return res.status(400).json({
          error: "Enter your M-Pesa phone number."
        });
      }

      const currentUser = db
        .prepare(`
          SELECT balance
          FROM users
          WHERE id=?
        `)
        .get(user(req).id);

      if (!currentUser) {
        return res.status(404).json({
          error: "User not found."
        });
      }

      if (
        amount > currentUser.balance
      ) {
        return res.status(400).json({
          error: "Insufficient balance."
        });
      }

      db.transaction(() => {

        db.prepare(`
          UPDATE users
          SET balance=balance-?
          WHERE id=?
        `).run(
          amount,
          user(req).id
        );

        db.prepare(`
          INSERT INTO withdrawals(
            user_id,
            amount,
            phone
          )
          VALUES(?,?,?)
        `).run(
          user(req).id,
          amount,
          phone
        );

      })();

      const updatedUser =
        db.prepare(`
          SELECT
            id,
            name,
            email,
            balance,
            role
          FROM users
          WHERE id=?
        `).get(user(req).id);

      req.session.user =
        updatedUser;

      res.json({
        success: true,
        message:
          "Withdrawal request submitted for review.",
        balance:
          updatedUser.balance
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Withdrawal request failed."
      });
    }
  }
);

/* =========================
   USER WITHDRAWALS
========================= */

app.get(
  "/api/withdrawals",
  requireLogin,
  (req, res) => {

    const withdrawals =
      db.prepare(`
        SELECT
          id,
          amount,
          phone,
          status,
          created_at
        FROM withdrawals
        WHERE user_id=?
        ORDER BY id DESC
      `).all(user(req).id);

    res.json(withdrawals);
  }
);

/* =========================
   ADMIN DASHBOARD
========================= */

app.get(
  "/api/admin/dashboard",
  requireAdmin,
  (req, res) => {

    const users =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM users
      `).get().count;

    const tasks =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM tasks
      `).get().count;

    const pendingSubmissions =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM submissions
        WHERE status='pending'
      `).get().count;

    const pendingWithdrawals =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM withdrawals
        WHERE status='pending'
      `).get().count;

    res.json({
      users,
      tasks,
      pendingSubmissions,
      pendingWithdrawals
    });
  }
);

/* =========================
   ADMIN TASKS
========================= */

app.get(
  "/api/admin/tasks",
  requireAdmin,
  (req, res) => {

    const tasks =
      db.prepare(`
        SELECT *
        FROM tasks
        ORDER BY id DESC
      `).all();

    res.json(tasks);
  }
);

app.post(
  "/api/admin/tasks",
  requireAdmin,
  (req, res) => {

    try {

      const {
        title,
        description,
        reward
      } = req.body;

      if (
        !title ||
        !description ||
        !reward
      ) {
        return res.status(400).json({
          error:
            "Title, description and reward are required."
        });
      }

      const rewardNumber =
        Number(reward);

      if (
        !Number.isInteger(
          rewardNumber
        ) ||
        rewardNumber <= 0
      ) {
        return res.status(400).json({
          error:
            "Reward must be a positive whole number."
        });
      }

      const result =
        db.prepare(`
          INSERT INTO tasks(
            title,
            description,
            reward
          )
          VALUES(?,?,?)
        `).run(
          title.trim(),
          description.trim(),
          rewardNumber
        );

      res.json({
        success: true,
        message:
          "Task created successfully.",
        taskId:
          result.lastInsertRowid
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not create task."
      });
    }
  }
);

/* =========================
   ADMIN CHANGE TASK STATUS
========================= */

app.patch(
  "/api/admin/tasks/:id",
  requireAdmin,
  (req, res) => {

    const taskId =
      Number(req.params.id);

    const { status } =
      req.body;

    if (
      !["active", "inactive"]
        .includes(status)
    ) {
      return res.status(400).json({
        error:
          "Invalid task status."
      });
    }

    const result =
      db.prepare(`
        UPDATE tasks
        SET status=?
        WHERE id=?
      `).run(
        status,
        taskId
      );

    if (result.changes === 0) {
      return res.status(404).json({
        error:
          "Task not found."
      });
    }

    res.json({
      success: true,
      message:
        "Task status updated."
    });
  }
);

/* =========================
   ADMIN SUBMISSIONS
========================= */

app.get(
  "/api/admin/submissions",
  requireAdmin,
  (req, res) => {

    const submissions =
      db.prepare(`
        SELECT
          submissions.id,
          submissions.task_id,
          submissions.user_id,
          users.name AS user_name,
          users.email,
          tasks.title,
          tasks.reward,
          submissions.proof,
          submissions.status,
          submissions.created_at
        FROM submissions
        JOIN users
          ON users.id=submissions.user_id
        JOIN tasks
          ON tasks.id=submissions.task_id
        ORDER BY submissions.id DESC
      `).all();

    res.json(submissions);
  }
);

/* =========================
   ADMIN REVIEW SUBMISSION
========================= */

app.patch(
  "/api/admin/submissions/:id",
  requireAdmin,
  (req, res) => {

    try {

      const submissionId =
        Number(req.params.id);

      const { status } =
        req.body;

      if (
        !["approved", "rejected"]
          .includes(status)
      ) {
        return res.status(400).json({
          error:
            "Status must be approved or rejected."
        });
      }

      const submission =
        db.prepare(`
          SELECT
            submissions.*,
            tasks.reward
          FROM submissions
          JOIN tasks
            ON tasks.id=submissions.task_id
          WHERE submissions.id=?
        `).get(submissionId);

      if (!submission) {
        return res.status(404).json({
          error:
            "Submission not found."
        });
      }

      if (
        submission.status !==
        "pending"
      ) {
        return res.status(400).json({
          error:
            "This submission has already been reviewed."
        });
      }

      db.transaction(() => {

        db.prepare(`
          UPDATE submissions
          SET status=?
          WHERE id=?
        `).run(
          status,
          submissionId
        );

        if (
          status === "approved"
        ) {

          db.prepare(`
            UPDATE users
            SET balance=balance+?
            WHERE id=?
          `).run(
            submission.reward,
            submission.user_id
          );
        }

      })();

      res.json({
        success: true,
        message:
          status === "approved"
            ? "Submission approved and reward added."
            : "Submission rejected."
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not review submission."
      });
    }
  }
);

/* =========================
   ADMIN WITHDRAWALS
========================= */

app.get(
  "/api/admin/withdrawals",
  requireAdmin,
  (req, res) => {

    const withdrawals =
      db.prepare(`
        SELECT
          withdrawals.id,
          withdrawals.user_id,
          users.name AS user_name,
          users.email,
          withdrawals.amount,
          withdrawals.phone,
          withdrawals.status,
          withdrawals.created_at
        FROM withdrawals
        JOIN users
          ON users.id=withdrawals.user_id
        ORDER BY withdrawals.id DESC
      `).all();

    res.json(withdrawals);
  }
);

/* =========================
   ADMIN REVIEW WITHDRAWAL
========================= */

app.patch(
  "/api/admin/withdrawals/:id",
  requireAdmin,
  (req, res) => {

    try {

      const withdrawalId =
        Number(req.params.id);

      const { status } =
        req.body;

      if (
        !["approved", "rejected"]
          .includes(status)
      ) {
        return res.status(400).json({
          error:
            "Status must be approved or rejected."
        });
      }

      const withdrawal =
        db.prepare(`
          SELECT *
          FROM withdrawals
          WHERE id=?
        `).get(withdrawalId);

      if (!withdrawal) {
        return res.status(404).json({
          error:
            "Withdrawal not found."
        });
      }

      if (
        withdrawal.status !==
        "pending"
      ) {
        return res.status(400).json({
          error:
            "This withdrawal has already been reviewed."
        });
      }

      db.transaction(() => {

        db.prepare(`
          UPDATE withdrawals
          SET status=?
          WHERE id=?
        `).run(
          status,
          withdrawalId
        );

        if (
          status === "rejected"
        ) {

          db.prepare(`
            UPDATE users
            SET balance=balance+?
            WHERE id=?
          `).run(
            withdrawal.amount,
            withdrawal.user_id
          );
        }

      })();

      res.json({
        success: true,
        message:
          status === "approved"
            ? "Withdrawal marked as approved."
            : "Withdrawal rejected and balance returned."
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        error:
          "Could not review withdrawal."
      });
    }
  }
);

/* =========================
   ADMIN USERS
========================= */

app.get(
  "/api/admin/users",
  requireAdmin,
  (req, res) => {

    const users =
      db.prepare(`
        SELECT
          id,
          name,
          email,
          balance,
          role,
          created_at
        FROM users
        ORDER BY id DESC
      `).all();

    res.json(users);
  }
);

/* =========================
   HEALTH CHECK
========================= */

app.get("/health", (req, res) => {

  res.json({
    status: "ok",
    service: "Pesa",
    time:
      new Date().toISOString()
  });
});

/* =========================
   FRONTEND FALLBACK
========================= */

app.get("*", (req, res) => {

  res.sendFile(
    path.join(
      __dirname,
      "index.html"
    )
  );
});

/* =========================
   ERROR HANDLER
========================= */

app.use(
  (err, req, res, next) => {

    console.error(err);

    res.status(500).json({
      error:
        "Internal server error."
    });
  }
);

/* =========================
   START SERVER
========================= */

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

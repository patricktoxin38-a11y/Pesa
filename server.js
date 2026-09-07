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

const adminEmail = process.env.ADMIN_EMAIL || "admin@taskhub.local";
const adminPassword = process.env.ADMIN_PASSWORD || "ChangeMe123!";
const existing = db.prepare("SELECT id FROM users WHERE email=?").get(adminEmail);
if (!existing) {
  const hash = bcrypt.hashSync(adminPassword, 10);
  db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'admin')")
    .run("Administrator", adminEmail, hash);
}

if (db.prepare("SELECT COUNT(*) c FROM tasks").get().c === 0) {
  const add = db.prepare("INSERT INTO tasks(title,description,reward) VALUES(?,?,?)");
  add.run("Example survey task","Replace this example with a genuine client-funded task. Do not publish tasks until you have a verified paying client.",50);
  add.run("Example social-media task","Example only. Add real instructions and proof requirements before publishing.",30);
}

app.use(express.urlencoded({extended:true}));
app.use(express.json());
app.use(cookieSession({
  name:"session",
  keys:[process.env.SESSION_SECRET || "replace-this-secret-in-production"],
  httpOnly:true,
  sameSite:"lax",
  secure:process.env.NODE_ENV==="production",
  maxAge:1000*60*60*24*7
}));
app.use(express.static(path.join(__dirname,"public")));

function user(req){ return req.session?.user || null; }
function requireLogin(req,res,next){ if(!user(req)) return res.redirect("/login.html"); next(); }
function requireAdmin(req,res,next){ if(!user(req) || user(req).role!=="admin") return res.status(403).send("Admin access required"); next(); }

app.post("/api/register",(req,res)=>{
  const {name,email,password}=req.body;
  if(!name || !email || !password || password.length<6) return res.status(400).json({error:"Name, email and a password of at least 6 characters are required."});
  try{
    const hash=bcrypt.hashSync(password,10);
    const info=db.prepare("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)").run(name.trim(),email.trim().toLowerCase(),hash);
    req.session.user={id:Number(info.lastInsertRowid),name:name.trim(),email:email.trim().toLowerCase(),role:"user"};
    res.json({ok:true});
  }catch(e){ res.status(400).json({error:"That email is already registered."}); }
});

app.post("/api/login",(req,res)=>{
  const u=db.prepare("SELECT * FROM users WHERE email=?").get((req.body.email||"").trim().toLowerCase());
  if(!u || !bcrypt.compareSync(req.body.password||"",u.password_hash)) return res.status(401).json({error:"Invalid email or password."});
  req.session.user={id:u.id,name:u.name,email:u.email,role:u.role};
  res.json({ok:true,role:u.role});
});

app.post("/api/logout",(req,res)=>{req.session=null;res.redirect("/");});

app.get("/api/me",requireLogin,(req,res)=>{
  const u=db.prepare("SELECT id,name,email,balance,role,created_at FROM users WHERE id=?").get(user(req).id);
  res.json(u);
});

app.get("/api/tasks",requireLogin,(req,res)=>{
  const rows=db.prepare(`
    SELECT t.*, s.id submission_id, s.status submission_status
    FROM tasks t LEFT JOIN submissions s ON s.task_id=t.id AND s.user_id=?
    WHERE t.status='active' ORDER BY t.id DESC
  `).all(user(req).id);
  res.json(rows);
});

app.post("/api/tasks/:id/submit",requireLogin,(req,res)=>{
  const t=db.prepare("SELECT * FROM tasks WHERE id=? AND status='active'").get(req.params.id);
  if(!t) return res.status(404).json({error:"Task not found."});
  if(!req.body.proof?.trim()) return res.status(400).json({error:"Proof is required."});
  const prior=db.prepare("SELECT id FROM submissions WHERE task_id=? AND user_id=?").get(t.id,user(req).id);
  if(prior) return res.status(400).json({error:"You already submitted this task."});
  db.prepare("INSERT INTO submissions(task_id,user_id,proof) VALUES(?,?,?)").run(t.id,user(req).id,req.body.proof.trim());
  res.json({ok:true});
});

app.post("/api/withdraw",requireLogin,(req,res)=>{
  const amount=Number(req.body.amount), phone=(req.body.phone||"").trim();
  if(!Number.isInteger(amount)||amount<100) return res.status(400).json({error:"Minimum withdrawal is KSh 100."});
  if(!/^254\d{9}$/.test(phone)) return res.status(400).json({error:"Use Kenyan format 2547XXXXXXXX."});
  const u=db.prepare("SELECT balance FROM users WHERE id=?").get(user(req).id);
  if(amount>u.balance) return res.status(400).json({error:"Insufficient balance."});
  const tx=db.transaction(()=>{
    db.prepare("UPDATE users SET balance=balance-? WHERE id=?").run(amount,user(req).id);
    db.prepare("INSERT INTO withdrawals(user_id,amount,phone) VALUES(?,?,?)").run(user(req).id,amount,phone);
  });
  tx(); res.json({ok:true,message:"Withdrawal request submitted for admin review."});
});

app.get("/api/admin/overview",requireAdmin,(req,res)=>{
  res.json({
    users:db.prepare("SELECT COUNT(*) c FROM users WHERE role='user'").get().c,
    tasks:db.prepare("SELECT COUNT(*) c FROM tasks").get().c,
    pendingSubmissions:db.prepare("SELECT COUNT(*) c FROM submissions WHERE status='pending'").get().c,
    pendingWithdrawals:db.prepare("SELECT COUNT(*) c FROM withdrawals WHERE status='pending'").get().c
  });
});
app.get("/api/admin/submissions",requireAdmin,(req,res)=>{
  res.json(db.prepare(`
    SELECT s.*,u.name,u.email,t.title,t.reward FROM submissions s
    JOIN users u ON u.id=s.user_id JOIN tasks t ON t.id=s.task_id
    ORDER BY s.id DESC
  `).all());
});
app.post("/api/admin/submissions/:id",requireAdmin,(req,res)=>{
  const action=req.body.action;
  const s=db.prepare("SELECT * FROM submissions WHERE id=?").get(req.params.id);
  if(!s || s.status!=="pending") return res.status(400).json({error:"Submission is not pending."});
  if(!["approve","reject"].includes(action)) return res.status(400).json({error:"Invalid action."});
  const tx=db.transaction(()=>{
    db.prepare("UPDATE submissions SET status=? WHERE id=?").run(action==="approve"?"approved":"rejected",s.id);
    if(action==="approve") db.prepare("UPDATE users SET balance=balance+(SELECT reward FROM tasks WHERE id=?) WHERE id=?").run(s.task_id,s.user_id);
  });
  tx(); res.json({ok:true});
});
app.post("/api/admin/tasks",requireAdmin,(req,res)=>{
  const {title,description,reward}=req.body;
  const r=Number(reward);
  if(!title||!description||!Number.isInteger(r)||r<=0) return res.status(400).json({error:"Enter title, description and a positive whole-number reward."});
  db.prepare("INSERT INTO tasks(title,description,reward) VALUES(?,?,?)").run(title,description,r);
  res.json({ok:true});
});
app.get("/api/admin/withdrawals",requireAdmin,(req,res)=>{
  res.json(db.prepare(`
    SELECT w.*,u.name,u.email FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY w.id DESC
  `).all());
});
app.post("/api/admin/withdrawals/:id",requireAdmin,(req,res)=>{
  const action=req.body.action;
  const w=db.prepare("SELECT * FROM withdrawals WHERE id=?").get(req.params.id);
  if(!w || w.status!=="pending") return res.status(400).json({error:"Withdrawal is not pending."});
  if(!["paid","rejected"].includes(action)) return res.status(400).json({error:"Invalid action."});
  const tx=db.transaction(()=>{
    if(action==="rejected") db.prepare("UPDATE users SET balance=balance+? WHERE id=?").run(w.amount,w.user_id);
    db.prepare("UPDATE withdrawals SET status=? WHERE id=?").run(action,w.id);
  });
  tx(); res.json({ok:true});
});

app.get("/api/admin/users",requireAdmin,(req,res)=>{
  res.json(db.prepare("SELECT id,name,email,balance,role,created_at FROM users ORDER BY id DESC").all());
});

app.listen(process.env.PORT||3000,()=>console.log("TaskHub KE running on http://localhost:"+ (process.env.PORT||3000)));

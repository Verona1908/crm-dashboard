const express = require("express");
const cors = require("cors");
const Database = require("better-sqlite3");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

app.use(express.json());
app.use(cors({ origin: "*" }));

const db = new Database("crm.db");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  password TEXT
);

CREATE TABLE IF NOT EXISTS trips (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  userId INTEGER,
  client TEXT,
  location TEXT,
  tripDate TEXT
);

CREATE TABLE IF NOT EXISTS items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tripId INTEGER,
  name TEXT,
  cost REAL,
  commissionExpected REAL,
  clientPayments TEXT,
  commissionPayments TEXT
);
`);

function auth(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: "No token" });

  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);

  try {
    db.prepare("INSERT INTO users (email, password) VALUES (?, ?)")
      .run(email, hash);
    res.json({ success: true });
  } catch {
    res.status(400).json({ error: "User exists" });
  }
});

app.post("/login", async (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE email=?")
    .get(req.body.email);

  if (!user) return res.status(401).json({ error: "No user" });

  const ok = await bcrypt.compare(req.body.password, user.password);
  if (!ok) return res.status(401).json({ error: "Wrong password" });

  const token = jwt.sign({ id: user.id }, SECRET);
  res.json({ token });
});

app.get("/trips", auth, (req, res) => {
  const rows = db.prepare("SELECT * FROM trips WHERE userId=?")
    .all(req.user.id);

  res.json(rows);
});

app.post("/trips", auth, (req, res) => {
  const info = db.prepare(
    "INSERT INTO trips (userId, client, location, tripDate) VALUES (?, ?, ?, ?)"
  ).run(req.user.id, req.body.client, req.body.location, req.body.tripDate);

  res.json({ id: info.lastInsertRowid });
});

app.delete("/trips/:id", auth, (req, res) => {
  db.prepare("DELETE FROM trips WHERE id=?").run(req.params.id);
  res.json({ success: true });
});

app.post("/items", auth, (req, res) => {
  const i = req.body;

  const info = db.prepare(`
    INSERT INTO items 
    (tripId, name, cost, commissionExpected, clientPayments, commissionPayments)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    i.tripId,
    i.name,
    i.cost,
    i.commissionExpected,
    JSON.stringify(i.clientPayments || []),
    JSON.stringify(i.commissionPayments || [])
  );

  res.json({ id: info.lastInsertRowid });
});

app.put("/items/:id", auth, (req, res) => {
  const i = req.body;

  db.prepare(`
    UPDATE items SET 
      name=?, cost=?, commissionExpected=?, clientPayments=?, commissionPayments=?
    WHERE id=?
  `).run(
    i.name,
    i.cost,
    i.commissionExpected,
    JSON.stringify(i.clientPayments || []),
    JSON.stringify(i.commissionPayments || []),
    req.params.id
  );

  res.json({ success: true });
});

app.delete("/items/:id", auth, (req, res) => {
  db.prepare("DELETE FROM items WHERE id=?").run(req.params.id);
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log("CRM SERVER RUNNING ON PORT", PORT);
});
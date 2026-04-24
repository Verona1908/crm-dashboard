const express = require("express");
const cors = require("cors");
const Database = require("better-sqlite3");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

// ================= CONFIG =================
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

app.use(express.json());
app.use(cors({ origin: "*" }));

// ================= DB =================
const db = new Database("crm.db");

// ================= INIT TABLES =================
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

// ================= AUTH MIDDLEWARE =================
function auth(req, res, next) {
  const token = req.headers.authorization;

  if (!token) return res.status(401).json({ error: "No token" });

  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

// ================= AUTH =================
app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  try {
    const hash = await bcrypt.hash(password, 10);

    db.prepare(
      "INSERT INTO users (email, password) VALUES (?, ?)"
    ).run(email, hash);

    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: "User exists or invalid" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = db.prepare("SELECT * FROM users WHERE email=?").get(email);

  if (!user) return res.status(401).json({ error: "User not found" });

  const ok = await bcrypt.compare(password, user.password);

  if (!ok) return res.status(401).json({ error: "Wrong password" });

  const token = jwt.sign({ id: user.id }, SECRET);

  res.json({ token });
});

// ================= TRIPS =================
app.get("/trips", auth, (req, res) => {
  const rows = db
    .prepare("SELECT * FROM trips WHERE userId=?")
    .all(req.user.id);

  res.json(rows);
});

app.post("/trips", auth, (req, res) => {
  const { client, location, tripDate } = req.body;

  const info = db
    .prepare(
      "INSERT INTO trips (userId, client, location, tripDate) VALUES (?, ?, ?, ?)"
    )
    .run(req.user.id, client, location, tripDate);

  res.json({ id: info.lastInsertRowid });
});

app.delete("/trips/:id", auth, (req, res) => {
  db.prepare("DELETE FROM trips WHERE id=?").run(req.params.id);
  res.json({ success: true });
});

// ================= ITEMS =================
app.post("/items", auth, (req, res) => {
  const i = req.body;

  const info = db
    .prepare(
      `INSERT INTO items 
      (tripId, name, cost, commissionExpected, clientPayments, commissionPayments)
      VALUES (?, ?, ?, ?, ?, ?)`
    )
    .run(
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

  db.prepare(
    `UPDATE items SET 
      name=?, cost=?, commissionExpected=?, clientPayments=?, commissionPayments=?
     WHERE id=?`
  ).run(
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

// ================= START =================
app.listen(PORT, () => {
  console.log("CRM SERVER RUNNING ON PORT", PORT);
});
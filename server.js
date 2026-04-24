const express = require("express");
const cors = require("cors");
const fs = require("fs");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || "dev_secret";

app.use(express.json());
app.use(cors({ origin: "*" }));

// ================= SIMPLE FILE DB =================
const DB_FILE = "./db.json";

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ users: [], trips: [], items: [] }, null, 2));
  }
  return JSON.parse(fs.readFileSync(DB_FILE));
}

function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// ================= AUTH =================
app.post("/register", async (req, res) => {
  const db = loadDB();
  const { email, password } = req.body;

  const exists = db.users.find(u => u.email === email);
  if (exists) return res.status(400).json({ error: "User exists" });

  const hash = await bcrypt.hash(password, 10);

  db.users.push({
    id: Date.now(),
    email,
    password: hash
  });

  saveDB(db);

  res.json({ success: true });
});

app.post("/login", async (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.email === req.body.email);

  if (!user) return res.status(401).json({ error: "User not found" });

  const ok = await bcrypt.compare(req.body.password, user.password);
  if (!ok) return res.status(401).json({ error: "Wrong password" });

  const token = jwt.sign({ id: user.id }, SECRET);
  res.json({ token });
});

// ================= AUTH MIDDLEWARE =================
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

// ================= TRIPS =================
app.get("/trips", auth, (req, res) => {
  const db = loadDB();
  const trips = db.trips.filter(t => t.userId === req.user.id);
  res.json(trips);
});

app.post("/trips", auth, (req, res) => {
  const db = loadDB();

  const trip = {
    id: Date.now(),
    userId: req.user.id,
    client: req.body.client,
    location: req.body.location,
    tripDate: req.body.tripDate
  };

  db.trips.push(trip);
  saveDB(db);

  res.json(trip);
});

app.delete("/trips/:id", auth, (req, res) => {
  const db = loadDB();
  db.trips = db.trips.filter(t => t.id != req.params.id);
  db.items = db.items.filter(i => i.tripId != req.params.id);
  saveDB(db);

  res.json({ success: true });
});

// ================= ITEMS =================
app.post("/items", auth, (req, res) => {
  const db = loadDB();

  const item = {
    id: Date.now(),
    tripId: req.body.tripId,
    name: req.body.name,
    cost: req.body.cost || 0,
    commissionExpected: req.body.commissionExpected || 0,
    clientPayments: req.body.clientPayments || [],
    commissionPayments: req.body.commissionPayments || []
  };

  db.items.push(item);
  saveDB(db);

  res.json(item);
});

app.put("/items/:id", auth, (req, res) => {
  const db = loadDB();

  const index = db.items.findIndex(i => i.id == req.params.id);
  if (index === -1) return res.status(404).json({ error: "Not found" });

  db.items[index] = {
    ...db.items[index],
    ...req.body
  };

  saveDB(db);

  res.json(db.items[index]);
});

app.delete("/items/:id", auth, (req, res) => {
  const db = loadDB();
  db.items = db.items.filter(i => i.id != req.params.id);
  saveDB(db);

  res.json({ success: true });
});

// ================= START =================
app.listen(PORT, () => {
  console.log("CRM SERVER RUNNING ON PORT", PORT);
});
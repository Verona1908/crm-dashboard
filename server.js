const express = require("express");
const cors = require("cors");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || "dev_secret";

app.use(express.json());
app.use(cors());

// ======================
// DB FILE (simple JSON storage)
// ======================
const DB_FILE = "./db.json";

function initDB() {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(
      DB_FILE,
      JSON.stringify({ trips: [], users: [] }, null, 2)
    );
  }
}

function readDB() {
  initDB();
  return JSON.parse(fs.readFileSync(DB_FILE));
}

function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// ======================
// HEALTH CHECK
// ======================
app.get("/", (req, res) => {
  res.send("CRM backend is running");
});

// ======================
// AUTH
// ======================
app.post("/register", async (req, res) => {
  const db = readDB();
  const { email, password } = req.body;

  if (db.users.find(u => u.email === email)) {
    return res.status(400).json({ error: "User exists" });
  }

  const hashed = await bcrypt.hash(password, 10);

  db.users.push({
    id: Date.now().toString(),
    email,
    password: hashed
  });

  writeDB(db);

  res.json({ success: true });
});

app.post("/login", async (req, res) => {
  const db = readDB();
  const { email, password } = req.body;

  const user = db.users.find(u => u.email === email);
  if (!user) return res.status(401).json({ error: "Invalid user" });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: "Wrong password" });

  const token = jwt.sign({ id: user.id }, SECRET);

  res.json({ token });
});

// ======================
// TRIPS
// ======================
app.get("/trips", (req, res) => {
  const db = readDB();
  res.json(db.trips);
});

app.post("/trips", (req, res) => {
  const db = readDB();

  const trip = {
    id: Date.now().toString(),
    clientName: req.body.clientName,
    location: req.body.location,
    startDate: req.body.startDate,
    endDate: req.body.endDate,
    notes: "",

    items: [],
    createdAt: new Date().toISOString()
  };

  db.trips.push(trip);
  writeDB(db);

  res.json(trip);
});

// ======================
// ITEMS
// ======================
app.post("/trips/:tripId/items", (req, res) => {
  const db = readDB();
  const trip = db.trips.find(t => t.id === req.params.tripId);

  if (!trip) return res.status(404).json({ error: "Trip not found" });

  const item = {
    id: Date.now().toString(),
    name: req.body.name,

    totalUSD: req.body.totalUSD,
    status: "unpaid",

    finalDueDate: req.body.finalDueDate || null,
    finalPaidDate: null,

    fxDisplay: {
      currency: req.body.currency || "",
      amount: req.body.originalAmount || ""
    },

    payments: [],
    commission: {
      expectedUSD: req.body.commission || 0,
      payments: []
    }
  };

  trip.items.push(item);
  writeDB(db);

  res.json(item);
});

// ======================
// PAYMENTS (DEPOSITS)
// ======================
app.post("/items/:itemId/payments", (req, res) => {
  const db = readDB();

  let foundItem;

  db.trips.forEach(t => {
    const item = t.items.find(i => i.id === req.params.itemId);
    if (item) foundItem = item;
  });

  if (!foundItem) return res.status(404).json({ error: "Item not found" });

  foundItem.payments.push({
    amountUSD: req.body.amountUSD,
    date: req.body.date
  });

  const totalPaid = foundItem.payments.reduce((a, p) => a + Number(p.amountUSD), 0);

  if (totalPaid >= foundItem.totalUSD) {
    foundItem.status = "paid";
    foundItem.finalPaidDate = new Date().toISOString();
  }

  writeDB(db);

  res.json(foundItem);
});

// ======================
// COMMISSION PAYMENTS
// ======================
app.post("/items/:itemId/commission", (req, res) => {
  const db = readDB();

  let foundItem;

  db.trips.forEach(t => {
    const item = t.items.find(i => i.id === req.params.itemId);
    if (item) foundItem = item;
  });

  if (!foundItem) return res.status(404).json({ error: "Item not found" });

  foundItem.commission.payments.push({
    amountUSD: req.body.amountUSD,
    date: req.body.date
  });

  writeDB(db);

  res.json(foundItem);
});

// ======================
// NOTES
// ======================
app.put("/trips/:tripId/notes", (req, res) => {
  const db = readDB();

  const trip = db.trips.find(t => t.id === req.params.tripId);
  if (!trip) return res.status(404).json({ error: "Trip not found" });

  trip.notes = req.body.notes;

  writeDB(db);

  res.json(trip);
});

// ======================
// START SERVER
// ======================
app.listen(PORT, () => {
  console.log("CRM SERVER RUNNING ON PORT", PORT);
});
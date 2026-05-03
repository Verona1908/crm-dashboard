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

// ===== SAFE ROOT ROUTE =====
app.get("/", (req, res) => {
  res.send("CRM backend is running");
});

// ===== SAFE DB =====
const DB_FILE = "./db.json";

function loadDB() {
  try {
    if (!fs.existsSync(DB_FILE)) {
      fs.writeFileSync(DB_FILE, JSON.stringify({ users: [], trips: [], items: [] }, null, 2));
    }
    return JSON.parse(fs.readFileSync(DB_FILE));
  } catch (err) {
    console.error("DB LOAD ERROR:", err);
    return { users: [], trips: [], items: [] };
  }
}

function saveDB(db) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
  } catch (err) {
    console.error("DB SAVE ERROR:", err);
  }
}

// ===== AUTH =====
app.post("/register", async (req, res) => {
  try {
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
  } catch (err) {
    console.error("REGISTER ERROR:", err);
    res.status(500).json({ error: "Register failed" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const db = loadDB();
    const user = db.users.find(u => u.email === req.body.email);

    if (!user) return res.status(401).json({ error: "User not found" });

    const ok = await bcrypt.compare(req.body.password, user.password);
    if (!ok) return res.status(401).json({ error: "Wrong password" });

    const token = jwt.sign({ id: user.id }, SECRET);
    res.json({ token });
  } catch (err) {
    console.error("LOGIN ERROR:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// ===== START SERVER SAFELY =====
try {
  app.listen(PORT, () => {
    console.log("CRM SERVER RUNNING ON PORT", PORT);
  });
} catch (err) {
  console.error("SERVER START ERROR:", err);
}
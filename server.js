const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const app = express();


const path = require("path");

app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});
// ================================
// URL SCANNER DETECTION DATA
// ================================

const suspiciousTLDs = [
  ".zip",".review",".country",".kim",".cricket",".science",
  ".work",".party",".gq",".tk",".ml",".ga",".cf"
];

const protectedBrands = [
  "google","facebook","amazon","paypal",
  "microsoft","apple","instagram","netflix",
  "bank","whatsapp"
];

const phishingKeywords = [
  "login",
  "verify",
  "secure",
  "account",
  "update",
  "alert",
  "bank",
  "signin"
];

const suspiciousKeywords = [
  "free","win","prize","gift","bonus",
  "reward","lottery","crypto","claim"
];

// Temporary OTP storage
const otpStore = {}; 

app.use(cors());
app.use(express.json());
const { Resend } = require("resend");
const resend = new Resend(process.env.RESEND_API_KEY);

/* -----------------------------
   MONGO CONNECTIONS (3 DBs)
   Using local MongoDB (Option A)
----------------------------- */
const baseURI = process.env.MONGO_URI;

const userDB = mongoose.createConnection(baseURI + "userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const scanDB = mongoose.createConnection(baseURI + "scanDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const reportDB = mongoose.createConnection(baseURI + "reportDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
/* Import models (factory functions) */
const User = require("./models/user")(userDB);
const UrlScan = require("./models/urlScan")(scanDB);
const ImageScan = require("./models/imageScan")(scanDB);
const DocumentScan = require("./models/documentScan")(scanDB);
const VideoScan = require("./models/videoScan")(scanDB);
const Report = require("./models/report")(reportDB);


/* ---------- USER ---------- */
// register
app.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const existing = await User.findOne({ username });
    if (existing) return res.json({ success: false, message: "Username already exists" });
    const user = await User.create({ username, email, password });
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// login
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username, password });
    if (!user) return res.json({ success: false, message: "Invalid credentials" });
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// send otp
app.post("/send-otp", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.json({ success: false, message: "Email required" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    otpStore[email] = {
      otp,
      expires: Date.now() + 60000
    };

    await resend.emails.send({
      from: "dsilvabosco3@gmail.com",
      to: email,
      subject: "re_bBGA2g3W_P3qAPyqfJEm1QHS76fxXn1KR",
      text: `Your OTP is ${otp}. It is valid for 1 minute.`
    });

    res.json({ success: true });

  } catch (err) {
    console.error("OTP ERROR:", err);
    res.json({ success: false, message: "Failed to send OTP" });
  }
});
//verify otp
app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  const record = otpStore[email];

  if (!record) {
    return res.json({ success: false, message: "No OTP found" });
  }

  if (Date.now() > record.expires) {
    delete otpStore[email];
    return res.json({ success: false, message: "OTP expired" });
  }

  if (record.otp === otp) {
    delete otpStore[email];
    return res.json({ success: true });
  }

  res.json({ success: false, message: "Invalid OTP" });
});


/* ---------- UPDATE USER ---------- */
app.put("/user/update/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { username, password } = req.body;

    if (!username && !password) {
      return res.json({ success: false, message: "Nothing to update" });
    }

    const updateFields = {};
    if (username) updateFields.username = username;
    if (password) updateFields.password = password;

    const updatedUser = await User.findByIdAndUpdate(
      id,
      { $set: updateFields },
      { new: true }
    );

    if (!updatedUser) {
      return res.json({ success: false, message: "User not found" });
    }

    res.json({ success: true, user: updatedUser });

  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ---------- SCANS ---------- */
// create scans
app.post("/scan/url", async (req, res) => {
  try {
    let { userId, username, type, target } = req.body;
let severity = "Safe"; // backend decides severity

    if (!userId || !target || !type) {
      return res.status(400).json({
        error: "Missing required fields"
      });
    }

// ✅ AUTO ADD https IF MISSING
if (!target.startsWith("http://") && !target.startsWith("https://")) {
  target = "https://" + target;
}

// ✅ BASIC FORMAT VALIDATION
let hostname;
try {
  const parsedUrl = new URL(target);
  hostname = parsedUrl.hostname;
} catch (err) {
  return res.status(400).json({
    error: "Invalid URL format"
  });
}


/* =====================================
   🚨 RISK DETECTION LOGIC (ADD HERE)
===================================== */

let riskScore = 0;
const domain = hostname.toLowerCase();

// 🚨 Suspicious TLD detection
suspiciousTLDs.forEach(tld => {
  if (domain.endsWith(tld)) {
    riskScore += 3;
  }
});

// ⚠ HTTP is less secure
if (target.startsWith("http://")) {
  riskScore += 1;
}

// replace common phishing number tricks
const normalizedDomain = domain
  .replace(/0/g, "o")
  .replace(/1/g, "l")
  .replace(/3/g, "e")
  .replace(/4/g, "a")
  .replace(/5/g, "s")
  .replace(/7/g, "t");

/* Suspicious keywords */
suspiciousKeywords.forEach(word => {
  if (target.toLowerCase().includes(word)) {
    riskScore += 2;
  }
});

/* ===============================
   🚨 FINAL LOOKALIKE DETECTION
================================ */

protectedBrands.forEach(brand => {

  const parts = normalizedDomain.split(".");

  const baseDomain = parts.length > 2 ? parts[parts.length - 2] : parts[0];

  const cleaned = baseDomain.replace(/-/g, "");

  const normalized = cleaned.replace(/(.)\1{2,}/g, "$1$1");

if (normalized === brand && baseDomain !== brand) {
  riskScore += 3;   // repeated-letter trick
}

else if (cleaned.includes(brand) && baseDomain !== brand) {
  riskScore += 2;   // brand inside domain
}

});

/* ===============================
   🚨 PHISHING KEYWORD DETECTION
================================ */

phishingKeywords.forEach(word => {
  if (target.toLowerCase().includes(word)) {
    riskScore += 1;
  }
});

/* Convert Score to Severity */
let autoSeverity = "Safe";

if (riskScore === 0) autoSeverity = "Safe";
else if (riskScore <= 2) autoSeverity = "Low";
else if (riskScore <= 4) autoSeverity = "Medium";
else autoSeverity = "High";

// Override frontend severity
severity = autoSeverity;


    // ✅ Save to DB
    const doc = await UrlScan.create({
      userId,
      username,
      target,
      type,
      severity,
      timestamp: new Date()
    });

    await Report.create({
      scanType: type,
      scanId: doc._id,
      reportData: {
        userId,
        username,
        target,
        severity
      }
    });

    res.json(doc);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


app.post("/scan/image", async (req, res) => {
  try {
    const { userId, username, target, type } = req.body;

    if (!userId || !target || !type) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    let riskScore = 0;
    const name = target.toLowerCase();

    // Suspicious image patterns
    if (name.includes("virus")) riskScore += 4;
    if (name.includes("malware")) riskScore += 4;
    if (name.includes("hack")) riskScore += 3;

    // Fake image trick
    if (name.match(/\.(jpg|png|gif)\.exe/)) riskScore += 5;

    let severity = "Safe";

    if (riskScore === 0) severity = "Safe";
    else if (riskScore <= 2) severity = "Low";
    else if (riskScore <= 4) severity = "Medium";
    else severity = "High";

    const doc = await ImageScan.create({
      userId,
      username,
      target,
      type,
      severity,
      timestamp: new Date()
    });

    await Report.create({
      scanType: type,
      scanId: doc._id,
      reportData: {
        userId,
        username,
        target,
        severity
      }
    });

    res.json(doc);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/scan/document", async (req, res) => {
  try {
    const { userId, username, target, type } = req.body;

    if (!userId || !target || !type) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    let riskScore = 0;
    const name = target.toLowerCase();

    // Suspicious document keywords
    if (name.includes("invoice")) riskScore += 1;
    if (name.includes("bank")) riskScore += 2;
    if (name.includes("password")) riskScore += 3;
    if (name.includes("crypto")) riskScore += 3;

    // Dangerous extensions
    if (name.endsWith(".exe")) riskScore += 5;
    if (name.match(/\.(pdf|docx)\.exe/)) riskScore += 5;

    let severity = "Safe";

    if (riskScore === 0) severity = "Safe";
    else if (riskScore <= 2) severity = "Low";
    else if (riskScore <= 4) severity = "Medium";
    else severity = "High";

    const doc = await DocumentScan.create({
      userId,
      username,
      target,
      type,
      severity,
      timestamp: new Date()
    });

    await Report.create({
      scanType: type,
      scanId: doc._id,
      reportData: {
        userId,
        username,
        target,
        severity
      }
    });

    res.json(doc);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/scan/video", async (req, res) => {
  try {
    const { userId, username, target, type } = req.body;

    if (!userId || !target || !type) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    let riskScore = 0;
    const name = target.toLowerCase();

    // Suspicious video patterns
    if (name.includes("free")) riskScore += 1;
    if (name.includes("crack")) riskScore += 3;
    if (name.includes("hack")) riskScore += 3;

    // Fake video trick
    if (name.match(/\.(mp4|avi|mkv)\.exe/)) riskScore += 5;

    let severity = "Safe";

    if (riskScore === 0) severity = "Safe";
    else if (riskScore <= 2) severity = "Low";
    else if (riskScore <= 4) severity = "Medium";
    else severity = "High";

    const doc = await VideoScan.create({
      userId,
      username,
      target,
      type,
      severity,
      timestamp: new Date()
    });

    await Report.create({
      scanType: type,
      scanId: doc._id,
      reportData: {
        userId,
        username,
        target,
        severity
      }
    });

    res.json(doc);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// fetch all scans (combined)
app.get("/scan/all", async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) return res.json([]);

    const url = await UrlScan.find({ userId }).lean();
    const img = await ImageScan.find({ userId }).lean();
    const doc = await DocumentScan.find({ userId }).lean();
    const vid = await VideoScan.find({ userId }).lean();

    const all = [...url, ...img, ...doc, ...vid]
      .sort((a,b) => new Date(b.timestamp) - new Date(a.timestamp));

    res.json(all);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ---------- DELETE SCAN ---------- */
app.delete("/scan/delete/:id", async (req, res) => {
  try {
    const { id } = req.params;

    // try deleting from all scan collections
    const deleted =
      (await UrlScan.findByIdAndDelete(id)) ||
      (await ImageScan.findByIdAndDelete(id)) ||
      (await DocumentScan.findByIdAndDelete(id)) ||
      (await VideoScan.findByIdAndDelete(id));

    if (!deleted) {
      return res.json({ success: false, message: "Scan not found" });
    }

    res.json({ success: true });
  } catch (err) {
    console.error("Delete error:", err);
    res.status(500).json({ success: false });
  }
});


/* ---------- REPORTS ---------- */
app.post("/report", async (req, res) => {
  try {
    const r = await Report.create(req.body);
    res.json(r);
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get("/report/all", async (req, res) => {
  try {
    const all = await Report.find().lean();
    res.json(all);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// =======================
// GET SCAN DATA FOR UI
// =======================

app.get("/api/url-scans", async (req, res) => {
  const scans = await UrlScan.find().sort({ timestamp: -1 });
  res.json(scans);
});

app.get("/api/image-scans", async (req, res) => {
  const scans = await ImageScan.find().sort({ timestamp: -1 });
  res.json(scans);
});

app.get("/api/document-scans", async (req, res) => {
  const scans = await DocumentScan.find().sort({ timestamp: -1 });
  res.json(scans);
});

app.get("/api/video-scans", async (req, res) => {
  const scans = await VideoScan.find().sort({ timestamp: -1 });
  res.json(scans);
});


/* Start server */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

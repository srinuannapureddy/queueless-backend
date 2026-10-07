require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const twilio = require("twilio");
const { Pool } = require("pg");

const app = express();
const PORT = Number(process.env.PORT || 4000);

if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
if (!process.env.JWT_SECRET) throw new Error("JWT_SECRET is required");
if (!process.env.TWILIO_ACCOUNT_SID || !process.env.TWILIO_AUTH_TOKEN ||
    !process.env.TWILIO_VERIFY_SERVICE_SID) {
  throw new Error("Twilio Verify environment variables are required");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
});

const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL
    ? process.env.FRONTEND_URL.split(",").map(x => x.trim())
    : true,
  credentials: false
}));
app.use(express.json({ limit: "100kb" }));

const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many OTP requests. Please wait and try again." }
});

const verifyLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many verification attempts. Please wait and try again." }
});

const staffLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many staff login attempts." }
});

const MOBILE = /^[6-9]\d{9}$/;

const DEPARTMENTS = {
  hospital: {
    name: "Hospital",
    prefix: "H",
    avg: 8,
    services: ["Neurologist","Cardiologist","Orthopaedic","General Physician","Paediatrician","Gynaecologist","Eye (Ophthalmologist)","Skin (Dermatologist)"]
  },
  rto: {
    name: "RTO",
    prefix: "R",
    avg: 8,
    services: ["Driving Licence","Learner Licence","Vehicle Registration","Fitness Certificate"]
  },
  tax: {
    name: "Municipal and Tax",
    prefix: "M",
    avg: 7,
    services: ["Property Tax","Birth Certificate","Death Certificate","Trade Licence"]
  },
  id: {
    name: "Aadhaar and ID",
    prefix: "A",
    avg: 5,
    services: ["New Aadhaar","Update Aadhaar","PAN Card","Voter ID"]
  },
  power: {
    name: "Electricity",
    prefix: "E",
    avg: 6,
    services: ["New Connection","Bill Payment","Complaint","Name Change"]
  },
  police: {
    name: "Police",
    prefix: "P",
    avg: 9,
    services: ["Passport Verification","Character Certificate","Complaint Help Desk","Lost Item Report"]
  }
};

const STATES = {
  "Andhra Pradesh":["Visakhapatnam","Vijayawada","Guntur"],
  "Arunachal Pradesh":["Itanagar","Tawang","Pasighat"],
  "Assam":["Guwahati","Dibrugarh","Silchar"],
  "Bihar":["Patna","Gaya","Muzaffarpur"],
  "Chhattisgarh":["Raipur","Bilaspur","Durg"],
  "Goa":["North Goa","South Goa"],
  "Gujarat":["Rajkot","Ahmedabad","Surat","Vadodara"],
  "Haryana":["Gurugram","Faridabad","Karnal"],
  "Himachal Pradesh":["Shimla","Kangra","Mandi"],
  "Jharkhand":["Ranchi","Dhanbad","East Singhbhum"],
  "Karnataka":["Bengaluru Urban","Mysuru","Dharwad"],
  "Kerala":["Thiruvananthapuram","Ernakulam","Kozhikode"],
  "Madhya Pradesh":["Bhopal","Indore","Jabalpur"],
  "Maharashtra":["Mumbai","Pune","Nagpur"],
  "Manipur":["Imphal West","Imphal East","Thoubal"],
  "Meghalaya":["East Khasi Hills","West Garo Hills","Ri-Bhoi"],
  "Mizoram":["Aizawl","Lunglei","Champhai"],
  "Nagaland":["Kohima","Dimapur","Mokokchung"],
  "Odisha":["Khordha","Cuttack","Puri"],
  "Punjab":["Ludhiana","Amritsar","Jalandhar"],
  "Rajasthan":["Jaipur","Jodhpur","Udaipur"],
  "Sikkim":["Gangtok","Namchi","Gyalshing"],
  "Tamil Nadu":["Chennai","Coimbatore","Madurai"],
  "Telangana":["Hyderabad","Warangal","Nizamabad"],
  "Tripura":["West Tripura","North Tripura","Dhalai"],
  "Uttar Pradesh":["Lucknow","Kanpur","Varanasi"],
  "Uttarakhand":["Dehradun","Haridwar","Nainital"],
  "West Bengal":["Kolkata","Howrah","Darjeeling"],
  "Andaman and Nicobar Islands":["South Andaman","North and Middle Andaman","Nicobar"],
  "Chandigarh":["Chandigarh"],
  "Dadra and Nagar Haveli and Daman and Diu":["Daman","Diu","Dadra and Nagar Haveli"],
  "Delhi":["New Delhi","South Delhi","North Delhi"],
  "Jammu and Kashmir":["Srinagar","Jammu","Anantnag"],
  "Ladakh":["Leh","Kargil"],
  "Lakshadweep":["Lakshadweep"],
  "Puducherry":["Puducherry","Karaikal","Mahe"]
};

function normalizeMobile(value) {
  const raw = String(value || "").trim().replace(/\s+/g, "");
  if (raw.startsWith("+91")) return raw.slice(3);
  if (raw.startsWith("91") && raw.length === 12) return raw.slice(2);
  return raw;
}

function phoneE164(mobile) {
  return `+91${mobile}`;
}

function signUser(user) {
  return jwt.sign(
    { sub: user.id, mobile: user.mobile, role: "customer" },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || "7d" }
  );
}

function signStaff(staff) {
  return jwt.sign(
    { sub: staff.id, username: staff.username, role: staff.role },
    process.env.JWT_SECRET,
    { expiresIn: "12h" }
  );
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Login required." });
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired login." });
  }
}

function staffAuth(req, res, next) {
  auth(req, res, () => {
    if (!["staff", "admin"].includes(req.user.role)) {
      return res.status(403).json({ error: "Staff access required." });
    }
    next();
  });
}

async function audit(mobile, action, status) {
  await pool.query(
    "INSERT INTO otp_audit (mobile, action, status) VALUES ($1,$2,$3)",
    [mobile, action, status]
  ).catch(() => {});
}

function departmentFromKey(key) {
  return DEPARTMENTS[key] || null;
}

function validateLocation(state, district) {
  return Boolean(STATES[state] && STATES[state].includes(district));
}

async function getQueue(client, state, district, departmentKey, service) {
  const d = departmentFromKey(departmentKey);
  if (!d) throw new Error("Unknown department.");
  if (!validateLocation(state, district)) throw new Error("Invalid state or district.");
  if (!d.services.includes(service)) throw new Error("Invalid service.");

  const result = await client.query(
    `INSERT INTO queues
      (state,district,department,service,prefix,avg_service_minutes)
     VALUES ($1,$2,$3,$4,$5,$6)
     ON CONFLICT (state,district,department,service)
     DO UPDATE SET avg_service_minutes = queues.avg_service_minutes
     RETURNING *`,
    [state, district, d.name, service, d.prefix, d.avg]
  );
  return result.rows[0];
}

async function queueView(client, queue) {
  const result = await client.query(
    `SELECT COUNT(*)::int AS waiting
     FROM tokens WHERE queue_id=$1 AND status='waiting'`,
    [queue.id]
  );
  const waiting = result.rows[0].waiting;
  const current = await client.query(
    `SELECT token_code FROM tokens
     WHERE queue_id=$1 AND status='serving'
     ORDER BY started_at DESC LIMIT 1`,
    [queue.id]
  );
  const estMin = Math.round(waiting * Number(queue.avg_service_minutes));
  const level = waiting < 20
    ? { cls: "g", label: "Normal" }
    : waiting < 30
      ? { cls: "y", label: "Busy" }
      : { cls: "r", label: "Very Busy" };

  return {
    state: queue.state,
    district: queue.district,
    department: queue.department,
    service: queue.service,
    serving: current.rows[0]?.token_code || null,
    waiting,
    estMin,
    avg: Number(queue.avg_service_minutes),
    ...level
  };
}

async function tokenView(client, tokenId) {
  const result = await client.query(
    `SELECT t.*, q.state, q.district, q.department, q.service,
            q.avg_service_minutes
     FROM tokens t JOIN queues q ON q.id=t.queue_id
     WHERE t.id=$1`,
    [tokenId]
  );
  if (!result.rows[0]) return null;
  const t = result.rows[0];

  const ahead = t.status === "waiting"
    ? (await client.query(
        `SELECT COUNT(*)::int AS n FROM tokens
         WHERE queue_id=$1 AND status='waiting' AND token_number < $2`,
        [t.queue_id, t.token_number]
      )).rows[0].n
    : 0;

  const current = await client.query(
    `SELECT token_code FROM tokens
     WHERE queue_id=$1 AND status='serving'
     ORDER BY started_at DESC LIMIT 1`,
    [t.queue_id]
  );

  return {
    id: t.id,
    code: t.token_code,
    no: t.token_number,
    state: t.state,
    district: t.district,
    dept: t.department,
    service: t.service,
    status: t.status,
    serving: current.rows[0]?.token_code || null,
    ahead,
    estMin: Math.round(ahead * Number(t.avg_service_minutes)),
    alert: t.status === "waiting" && ahead <= 2,
    createdAt: t.created_at
  };
}

app.get("/api/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, service: "QueueLess API" });
  } catch {
    res.status(503).json({ ok: false });
  }
});

app.get("/api/departments", (_req, res) => {
  res.json(Object.entries(DEPARTMENTS).map(([key, d]) => ({
    key, name: d.name, prefix: d.prefix, avg: d.avg, services: d.services
  })));
});

app.get("/api/locations", (req, res) => {
  const dept = req.query.dept;
  if (!dept) return res.json(STATES);
  const d = Object.values(DEPARTMENTS).find(x => x.name === dept);
  if (!d) return res.json(STATES);
  res.json(STATES);
});

/*
  REAL OTP:
  1. Browser calls /auth/send-code.
  2. Twilio Verify sends the SMS.
  3. Browser calls /auth/verify with the received code.
  4. Twilio confirms it.
  5. Only then is our JWT issued.
*/
app.post("/api/auth/send-code", otpLimiter, async (req, res) => {
  try {
    const mobile = normalizeMobile(req.body.mobile);
    if (!MOBILE.test(mobile)) {
      return res.status(400).json({ error: "Enter a valid Indian mobile number." });
    }

    await twilioClient.verify.v2
      .services(process.env.TWILIO_VERIFY_SERVICE_SID)
      .verifications
      .create({ to: phoneE164(mobile), channel: "sms" });

    await audit(mobile, "send", "sent");
    res.json({ ok: true, message: "OTP sent successfully." });
  } catch (err) {
    console.error("OTP SEND:", err.message);
    await audit(normalizeMobile(req.body.mobile), "send", "failed");
    res.status(502).json({ error: "Unable to send OTP right now. Please try again." });
  }
});

app.post("/api/auth/verify", verifyLimiter, async (req, res) => {
  try {
    const mobile = normalizeMobile(req.body.mobile);
    const code = String(req.body.code || "").trim();

    if (!MOBILE.test(mobile) || !/^\d{4,10}$/.test(code)) {
      return res.status(400).json({ error: "Invalid mobile number or OTP." });
    }

    const verification = await twilioClient.verify.v2
      .services(process.env.TWILIO_VERIFY_SERVICE_SID)
      .verificationChecks
      .create({ to: phoneE164(mobile), code });

    if (verification.status !== "approved") {
      await audit(mobile, "verify", verification.status || "rejected");
      return res.status(401).json({ error: "Invalid or expired OTP." });
    }

    const result = await pool.query(
      `INSERT INTO users (mobile, verified_at)
       VALUES ($1, NOW())
       ON CONFLICT (mobile)
       DO UPDATE SET verified_at=NOW()
       RETURNING id, mobile, name`,
      [mobile]
    );

    await audit(mobile, "verify", "approved");

    res.json({
      ok: true,
      token: signUser(result.rows[0]),
      user: result.rows[0]
    });
  } catch (err) {
    console.error("OTP VERIFY:", err.message);
    await audit(normalizeMobile(req.body.mobile), "verify", "failed");
    res.status(401).json({ error: "OTP verification failed." });
  }
});

app.get("/api/me", auth, async (req, res) => {
  const result = await pool.query(
    "SELECT id,mobile,name,verified_at FROM users WHERE id=$1",
    [req.user.sub]
  );
  if (!result.rows[0]) return res.status(404).json({ error: "User not found." });
  res.json(result.rows[0]);
});

app.patch("/api/me", auth, async (req, res) => {
  const name = String(req.body.name || "").trim().slice(0, 80);
  if (name.length < 2) return res.status(400).json({ error: "Enter your name." });

  const result = await pool.query(
    "UPDATE users SET name=$1 WHERE id=$2 RETURNING id,mobile,name,verified_at",
    [name, req.user.sub]
  );
  res.json(result.rows[0]);
});

app.get("/api/queue-status", async (req, res) => {
  const { state, district, dept, service } = req.query;
  try {
    const client = await pool.connect();
    try {
      const q = await getQueue(client, state, district, dept, service);
      res.json(await queueView(client, q));
    } finally {
      client.release();
    }
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/api/tokens", auth, async (req, res) => {
  const { state, district, dept, service } = req.body;
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const user = await client.query(
      "SELECT id,mobile,name FROM users WHERE id=$1",
      [req.user.sub]
    );
    if (!user.rows[0]) throw new Error("User not found.");

    const name = String(req.body.name || user.rows[0].name || "").trim().slice(0, 80);
    if (name.length < 2) throw new Error("Please enter your name.");

    await client.query(
      "UPDATE users SET name=$1 WHERE id=$2",
      [name, req.user.sub]
    );

    const q = await getQueue(client, state, district, dept, service);

    const duplicate = await client.query(
      `SELECT token_code FROM tokens
       WHERE user_id=$1 AND queue_id=$2
       AND status IN ('waiting','serving','hold')
       LIMIT 1`,
      [req.user.sub, q.id]
    );
    if (duplicate.rows[0]) {
      const e = new Error(`You already have token ${duplicate.rows[0].token_code} in this queue.`);
      e.status = 409;
      throw e;
    }

    const numberResult = await client.query(
      `UPDATE queues
       SET next_number=next_number+1
       WHERE id=$1
       RETURNING next_number-1 AS token_number`,
      [q.id]
    );
    const tokenNumber = numberResult.rows[0].token_number;
    const tokenCode = `${q.prefix}-${String(tokenNumber).padStart(3, "0")}`;

    const inserted = await client.query(
      `INSERT INTO tokens
       (queue_id,user_id,token_number,token_code,name,mobile)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING id`,
      [q.id, req.user.sub, tokenNumber, tokenCode, name, user.rows[0].mobile]
    );

    await client.query("COMMIT");

    const view = await tokenView(client, inserted.rows[0].id);
    res.status(201).json(view);
  } catch (err) {
    await client.query("ROLLBACK");
    res.status(err.status || 400).json({ error: err.message });
  } finally {
    client.release();
  }
});

app.get("/api/tokens/:id", async (req, res) => {
  const client = await pool.connect();
  try {
    const view = await tokenView(client, req.params.id);
    if (!view) return res.status(404).json({ error: "Token not found." });
    res.json(view);
  } finally {
    client.release();
  }
});

app.delete("/api/tokens/:id", auth, async (req, res) => {
  const client = await pool.connect();
  try {
    const check = await client.query(
      "SELECT id FROM tokens WHERE id=$1 AND user_id=$2",
      [req.params.id, req.user.sub]
    );
    if (!check.rows[0]) return res.status(404).json({ error: "Token not found." });

    const result = await client.query(
      `UPDATE tokens SET status='cancelled', ended_at=NOW()
       WHERE id=$1 AND status IN ('waiting','hold')
       RETURNING id`,
      [req.params.id]
    );
    if (!result.rows[0]) {
      return res.status(400).json({ error: "This token cannot be cancelled now." });
    }

    res.json(await tokenView(client, req.params.id));
  } finally {
    client.release();
  }
});

app.get("/api/my-tokens", auth, async (req, res) => {
  const result = await pool.query(
    `SELECT id FROM tokens
     WHERE user_id=$1 ORDER BY created_at DESC LIMIT 20`,
    [req.user.sub]
  );

  const client = await pool.connect();
  try {
    const out = [];
    for (const row of result.rows) out.push(await tokenView(client, row.id));
    res.json(out);
  } finally {
    client.release();
  }
});

/* Staff login is username/password, not a hard-coded demo PIN. */
app.post("/api/staff/login", staffLimiter, async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  const result = await pool.query(
    "SELECT id,username,password_hash,role FROM staff_users WHERE username=$1",
    [username]
  );
  const staff = result.rows[0];

  if (!staff || !(await bcrypt.compare(password, staff.password_hash))) {
    return res.status(401).json({ error: "Invalid staff credentials." });
  }

  res.json({
    ok: true,
    token: signStaff(staff),
    staff: { id: staff.id, username: staff.username, role: staff.role }
  });
});

app.get("/api/staff/queue", staffAuth, async (req, res) => {
  const { state, district, dept, service } = req.query;
  try {
    const client = await pool.connect();
    try {
      const q = await getQueue(client, state, district, dept, service);
      const waiting = await client.query(
        `SELECT id,token_code,name,status,created_at
         FROM tokens WHERE queue_id=$1 AND status IN ('waiting','serving','hold')
         ORDER BY token_number`,
        [q.id]
      );
      res.json({
        queue: await queueView(client, q),
        tokens: waiting.rows
      });
    } finally {
      client.release();
    }
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/api/staff/next", staffAuth, async (req, res) => {
  const { state, district, dept, service } = req.body;
  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    const q = await getQueue(client, state, district, dept, service);

    const current = await client.query(
      `SELECT id FROM tokens
       WHERE queue_id=$1 AND status='serving'
       ORDER BY started_at LIMIT 1`,
      [q.id]
    );
    if (current.rows[0]) {
      await client.query(
        "UPDATE tokens SET status='done', ended_at=NOW() WHERE id=$1",
        [current.rows[0].id]
      );
    }

    const next = await client.query(
      `SELECT id FROM tokens
       WHERE queue_id=$1 AND status='waiting'
       ORDER BY token_number LIMIT 1
       FOR UPDATE SKIP LOCKED`,
      [q.id]
    );

    if (!next.rows[0]) {
      await client.query("COMMIT");
      return res.json({ ok: true, current: null, message: "No one is waiting." });
    }

    await client.query(
      `UPDATE tokens SET status='serving', started_at=NOW()
       WHERE id=$1`,
      [next.rows[0].id]
    );

    await client.query("COMMIT");
    res.json({ ok: true, current: await tokenView(client, next.rows[0].id) });
  } catch (err) {
    await client.query("ROLLBACK");
    res.status(400).json({ error: err.message });
  } finally {
    client.release();
  }
});

app.post("/api/staff/skip", staffAuth, async (req, res) => {
  const { state, district, dept, service } = req.body;
  const client = await pool.connect();
  try {
    const q = await getQueue(client, state, district, dept, service);
    const current = await client.query(
      `SELECT id FROM tokens WHERE queue_id=$1 AND status='serving'
       ORDER BY started_at LIMIT 1`,
      [q.id]
    );
    if (!current.rows[0]) return res.status(400).json({ error: "No token is currently serving." });

    await client.query(
      "UPDATE tokens SET status='skipped', ended_at=NOW() WHERE id=$1",
      [current.rows[0].id]
    );
    res.json({ ok: true, queue: await queueView(client, q) });
  } finally {
    client.release();
  }
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: "Internal server error." });
});

app.listen(PORT, () => {
  console.log(`QueueLess API running on port ${PORT}`);
});

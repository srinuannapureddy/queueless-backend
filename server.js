require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const twilio = require("twilio");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const fs = require("fs");

const app = express();

const PORT = process.env.PORT || 4000;

const JWT_SECRET = process.env.JWT_SECRET;
const FRONTEND_URL =
  process.env.FRONTEND_URL || "http://localhost:5173";

const TWILIO_ACCOUNT_SID =
  process.env.TWILIO_ACCOUNT_SID;

const TWILIO_AUTH_TOKEN =
  process.env.TWILIO_AUTH_TOKEN;

const TWILIO_VERIFY_SERVICE_SID =
  process.env.TWILIO_VERIFY_SERVICE_SID;

/* =====================================================
   REQUIRED ENVIRONMENT VARIABLES
===================================================== */

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is required");
}

if (!TWILIO_ACCOUNT_SID) {
  throw new Error("TWILIO_ACCOUNT_SID is required");
}

if (!TWILIO_AUTH_TOKEN) {
  throw new Error("TWILIO_AUTH_TOKEN is required");
}

if (!TWILIO_VERIFY_SERVICE_SID) {
  throw new Error("TWILIO_VERIFY_SERVICE_SID is required");
}

/* =====================================================
   TWILIO
===================================================== */

const twilioClient = twilio(
  TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN
);

/* =====================================================
   SQLITE
===================================================== */

const dataDirectory = path.join(
  __dirname,
  "data"
);

if (!fs.existsSync(dataDirectory)) {
  fs.mkdirSync(dataDirectory, {
    recursive: true
  });
}

const databasePath = path.join(
  dataDirectory,
  "queueless.db"
);

const db = new sqlite3.Database(
  databasePath
);

db.configure("busyTimeout", 5000);

/* =====================================================
   DATABASE FUNCTIONS
===================================================== */

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (error) {
      if (error) {
        reject(error);
        return;
      }

      resolve({
        id: this.lastID,
        changes: this.changes
      });
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (error, row) => {
      if (error) {
        reject(error);
        return;
      }

      resolve(row);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (error, rows) => {
      if (error) {
        reject(error);
        return;
      }

      resolve(rows);
    });
  });
}

function exec(sql) {
  return new Promise((resolve, reject) => {
    db.exec(sql, error => {
      if (error) {
        reject(error);
        return;
      }

      resolve();
    });
  });
}

/* =====================================================
   DATABASE INITIALIZATION
===================================================== */

async function initializeDatabase() {
  await exec(`
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      phone TEXT UNIQUE NOT NULL,
      name TEXT DEFAULT '',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS staff_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      phone TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      pin_hash TEXT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS queues (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      state TEXT NOT NULL,
      district TEXT NOT NULL,
      department TEXT NOT NULL,
      service TEXT NOT NULL,
      next_number INTEGER NOT NULL DEFAULT 1,
      current_number INTEGER NOT NULL DEFAULT 0,
      UNIQUE(
        state,
        district,
        department,
        service
      )
    );

    CREATE TABLE IF NOT EXISTS tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      queue_id INTEGER NOT NULL,
      token_number INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'waiting',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      called_at TEXT,
      completed_at TEXT,

      FOREIGN KEY(user_id)
        REFERENCES users(id),

      FOREIGN KEY(queue_id)
        REFERENCES queues(id)
    );

    CREATE TABLE IF NOT EXISTS otp_audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      phone TEXT NOT NULL,
      action TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_tokens_user
      ON tokens(user_id);

    CREATE INDEX IF NOT EXISTS idx_tokens_queue
      ON tokens(queue_id);

    CREATE INDEX IF NOT EXISTS idx_tokens_status
      ON tokens(status);
  `);

  console.log(
    "SQLite database initialized:"
  );

  console.log(databasePath);
}

/* =====================================================
   UTILITY
===================================================== */

function normalizePhone(phone) {
  if (!phone) {
    return "";
  }

  return String(phone)
    .trim()
    .replace(/[()\s-]/g, "");
}

function createUserToken(userId) {
  return jwt.sign(
    {
      userId: userId,
      type: "user"
    },
    JWT_SECRET,
    {
      expiresIn:
        process.env.JWT_EXPIRES_IN || "7d"
    }
  );
}

function createStaffToken(staffId) {
  return jwt.sign(
    {
      staffId: staffId,
      type: "staff"
    },
    JWT_SECRET,
    {
      expiresIn:
        process.env.JWT_EXPIRES_IN || "7d"
    }
  );
}

/* =====================================================
   MIDDLEWARE
===================================================== */

function authenticateUser(
  req,
  res,
  next
) {
  const header =
    req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Authentication required"
    });
  }

  const token = header.substring(7);

  try {
    const payload = jwt.verify(
      token,
      JWT_SECRET
    );

    if (payload.type !== "user") {
      return res.status(401).json({
        error: "Invalid user token"
      });
    }

    req.userId = payload.userId;

    next();
  } catch (error) {
    return res.status(401).json({
      error: "Invalid or expired token"
    });
  }
}

function authenticateStaff(
  req,
  res,
  next
) {
  const header =
    req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      error:
        "Staff authentication required"
    });
  }

  const token = header.substring(7);

  try {
    const payload = jwt.verify(
      token,
      JWT_SECRET
    );

    if (payload.type !== "staff") {
      return res.status(401).json({
        error: "Invalid staff token"
      });
    }

    req.staffId = payload.staffId;

    next();
  } catch (error) {
    return res.status(401).json({
      error: "Invalid or expired token"
    });
  }
}

/* =====================================================
   EXPRESS
===================================================== */

app.use(
  helmet({
    crossOriginResourcePolicy: false
  })
);

app.use(
  cors({
    origin: [
      FRONTEND_URL,
      "http://localhost:5173",
      "http://localhost:3000"
    ],
    credentials: true
  })
);

app.use(express.json());

const authLimiter =
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false
  });

app.use(
  "/api/auth",
  authLimiter
);

/* =====================================================
   QUEUE HELPER
===================================================== */

async function getOrCreateQueue(
  state,
  district,
  department,
  service
) {
  let queue = await get(
    `
    SELECT *
    FROM queues
    WHERE state = ?
      AND district = ?
      AND department = ?
      AND service = ?
    `,
    [
      state,
      district,
      department,
      service
    ]
  );

  if (!queue) {
    const result = await run(
      `
      INSERT INTO queues
      (
        state,
        district,
        department,
        service,
        next_number,
        current_number
      )
      VALUES (?, ?, ?, ?, 1, 0)
      `,
      [
        state,
        district,
        department,
        service
      ]
    );

    queue = await get(
      `
      SELECT *
      FROM queues
      WHERE id = ?
      `,
      [result.id]
    );
  }

  return queue;
}

/* =====================================================
   HEALTH
===================================================== */

app.get(
  "/api/health",
  async (req, res) => {
    try {
      await get(
        "SELECT 1 AS ok"
      );

      res.json({
        ok: true,
        service:
          "queueless-backend",
        database: "sqlite",
        timestamp:
          new Date().toISOString()
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        ok: false,
        error:
          "Database unavailable"
      });
    }
  }
);

/* =====================================================
   DEPARTMENTS
===================================================== */

app.get(
  "/api/departments",
  (req, res) => {
    res.json([
      {
        id: "general",
        name: "General Services"
      },
      {
        id: "hospital",
        name: "Hospital"
      },
      {
        id: "bank",
        name: "Banking"
      },
      {
        id: "government",
        name:
          "Government Services"
      }
    ]);
  }
);

/* =====================================================
   LOCATIONS
===================================================== */

app.get(
  "/api/locations",
  (req, res) => {
    res.json([]);
  }
);

/* =====================================================
   SEND OTP
===================================================== */

app.post(
  "/api/auth/send-code",
  async (req, res) => {
    try {
      const phone =
        normalizePhone(
          req.body.phone
        );

      if (!phone) {
        return res.status(400).json({
          error:
            "Phone number is required"
        });
      }

      await twilioClient.verify.v2
        .services(
          TWILIO_VERIFY_SERVICE_SID
        )
        .verifications.create({
          to: phone,
          channel: "sms"
        });

      await run(
        `
        INSERT INTO otp_audit
        (
          phone,
          action
        )
        VALUES (?, ?)
        `,
        [
          phone,
          "send"
        ]
      );

      res.json({
        success: true,
        message:
          "Verification code sent"
      });
    } catch (error) {
      console.error(
        "SEND OTP ERROR:",
        error.message
      );

      res.status(400).json({
        error:
          error.message ||
          "Unable to send verification code"
      });
    }
  }
);

/* =====================================================
   VERIFY OTP
===================================================== */

app.post(
  "/api/auth/verify",
  async (req, res) => {
    try {
      const phone =
        normalizePhone(
          req.body.phone
        );

      const code =
        String(
          req.body.code || ""
        ).trim();

      if (!phone || !code) {
        return res.status(400).json({
          error:
            "Phone number and code are required"
        });
      }

      const verificationCheck =
        await twilioClient.verify.v2
          .services(
            TWILIO_VERIFY_SERVICE_SID
          )
          .verificationChecks.create({
            to: phone,
            code: code
          });

      if (
        verificationCheck.status !==
        "approved"
      ) {
        return res.status(401).json({
          error:
            "Invalid verification code"
        });
      }

      let user = await get(
        `
        SELECT *
        FROM users
        WHERE phone = ?
        `,
        [phone]
      );

      if (!user) {
        const result = await run(
          `
          INSERT INTO users
          (
            phone,
            name
          )
          VALUES (?, ?)
          `,
          [
            phone,
            ""
          ]
        );

        user = await get(
          `
          SELECT *
          FROM users
          WHERE id = ?
          `,
          [result.id]
        );
      }

      await run(
        `
        INSERT INTO otp_audit
        (
          phone,
          action
        )
        VALUES (?, ?)
        `,
        [
          phone,
          "verify"
        ]
      );

      const token =
        createUserToken(
          user.id
        );

      res.json({
        success: true,

        token,

        user: {
          id: user.id,
          phone: user.phone,
          name: user.name
        }
      });
    } catch (error) {
      console.error(
        "VERIFY OTP ERROR:",
        error.message
      );

      res.status(401).json({
        error:
          error.message ||
          "Verification failed"
      });
    }
  }
);

/* =====================================================
   GET CURRENT USER
===================================================== */

app.get(
  "/api/me",
  authenticateUser,
  async (req, res) => {
    try {
      const user = await get(
        `
        SELECT
          id,
          phone,
          name,
          created_at
        FROM users
        WHERE id = ?
        `,
        [req.userId]
      );

      if (!user) {
        return res.status(404).json({
          error:
            "User not found"
        });
      }

      res.json({
        user
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "Unable to load user"
      });
    }
  }
);

/* =====================================================
   UPDATE USER
===================================================== */

app.patch(
  "/api/me",
  authenticateUser,
  async (req, res) => {
    try {
      const name =
        String(
          req.body.name || ""
        ).trim();

      await run(
        `
        UPDATE users
        SET
          name = ?,
          updated_at =
            CURRENT_TIMESTAMP
        WHERE id = ?
        `,
        [
          name,
          req.userId
        ]
      );

      const user = await get(
        `
        SELECT
          id,
          phone,
          name,
          created_at
        FROM users
        WHERE id = ?
        `,
        [req.userId]
      );

      res.json({
        user
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "Unable to update profile"
      });
    }
  }
);

/* =====================================================
   QUEUE STATUS
===================================================== */

app.get(
  "/api/queue-status",
  async (req, res) => {
    try {
      const state =
        String(
          req.query.state || ""
        ).trim();

      const district =
        String(
          req.query.district || ""
        ).trim();

      const department =
        String(
          req.query.dept ||
            req.query.department ||
            ""
        ).trim();

      const service =
        String(
          req.query.service || ""
        ).trim();

      if (
        !state ||
        !district ||
        !department ||
        !service
      ) {
        return res.status(400).json({
          error:
            "state, district, dept and service are required"
        });
      }

      const queue =
        await getOrCreateQueue(
          state,
          district,
          department,
          service
        );

      const waiting =
        await get(
          `
          SELECT COUNT(*) AS count
          FROM tokens
          WHERE queue_id = ?
            AND status = 'waiting'
          `,
          [queue.id]
        );

      res.json({
        queue: {
          id: queue.id,
          state: queue.state,
          district:
            queue.district,
          department:
            queue.department,
          service:
            queue.service,
          current_number:
            queue.current_number,
          next_number:
            queue.next_number,
          waiting_count:
            waiting.count
        }
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "Unable to load queue status"
      });
    }
  }
);

/* =====================================================
   CREATE TOKEN
===================================================== */

app.post(
  "/api/tokens",
  authenticateUser,
  async (req, res) => {
    try {
      const state =
        String(
          req.body.state || ""
        ).trim();

      const district =
        String(
          req.body.district || ""
        ).trim();

      const department =
        String(
          req.body.dept ||
            req.body.department ||
            ""
        ).trim();

      const service =
        String(
          req.body.service || ""
        ).trim();

      if (
        !state ||
        !district ||
        !department ||
        !service
      ) {
        return res.status(400).json({
          error:
            "state, district, dept and service are required"
        });
      }

      const queue =
        await getOrCreateQueue(
          state,
          district,
          department,
          service
        );

      const tokenNumber =
        queue.next_number;

      await run(
        `
        UPDATE queues
        SET
          next_number =
            next_number + 1
        WHERE id = ?
        `,
        [queue.id]
      );

      const result =
        await run(
          `
          INSERT INTO tokens
          (
            user_id,
            queue_id,
            token_number,
            status
          )
          VALUES (?, ?, ?, 'waiting')
          `,
          [
            req.userId,
            queue.id,
            tokenNumber
          ]
        );

      const token =
        await get(
          `
          SELECT
            t.id,
            t.token_number,
            t.status,
            t.created_at,
            q.state,
            q.district,
            q.department,
            q.service,
            q.current_number
          FROM tokens t
          JOIN queues q
            ON q.id = t.queue_id
          WHERE t.id = ?
          `,
          [result.id]
        );

      res.status(201).json({
        success: true,
        token
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "Unable to create token"
      });
    }
  }
);

/* =====================================================
   GET TOKEN
===================================================== */

app.get(
  "/api/tokens/:id",
  authenticateUser,
  async (req, res) => {
    try {
      const token =
        await get(
          `
          SELECT
            t.id,
            t.token_number,
            t.status,
            t.created_at,
            t.called_at,
            t.completed_at,
            q.id AS queue_id,
            q.state,
            q.district,
            q.department,
            q.service,
            q.current_number
          FROM tokens t
          JOIN queues q
            ON q.id = t.queue_id
          WHERE
            t.id = ?
            AND t.user_id = ?
          `,
          [
            req.params.id,
            req.userId
          ]
        );

      if (!token) {
        return res.status(404).json({
          error:
            "Token not found"
        });
      }

      const ahead =
        await get(
          `
          SELECT COUNT(*) AS count
          FROM tokens
          WHERE
            queue_id = ?
            AND status = 'waiting'
            AND id < ?
          `,
          [
            token.queue_id,
            token.id
          ]
        );

      res.json({
        token,
        people_ahead:
          ahead.count
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "Unable to load token"
      });
    }
  }
);

/* =====================================================
   MY TOKENS
===================================================== */

app.get(
  "/api/my-tokens",
  authenticateUser,
  async (req, res) => {
    try {
      const tokens =
        await all(
          `
          SELECT
            t.id,
            t.token_number,
            t.status,
            t.created_at,
            t.called_at,
            t.completed_at,
            q.state,
            q.district,
            q.department,
            q.service,
            q.current_number
          FROM tokens t
          JOIN queues q
            ON q.id = t.queue_id
          WHERE t.user_id = ?
          ORDER BY t.id DESC
          `,
          [req.userId]
        );

      res.json({
        tokens
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "Unable to load tokens"
      });
    }
  }
);

/* =====================================================
   CANCEL TOKEN
===================================================== */

app.delete(
  "/api/tokens/:id",
  authenticateUser,
  async (req, res) => {
    try {
      const token =
        await get(
          `
          SELECT *
          FROM tokens
          WHERE
            id = ?
            AND user_id = ?
          `,
          [
            req.params.id,
            req.userId
          ]
        );

      if (!token) {
        return res.status(404).json({
          error:
            "Token not found"
        });
      }

      if (
        token.status !==
        "waiting"
      ) {
        return res.status(400).json({
          error:
            "Only waiting tokens can be cancelled"
        });
      }

      await run(
        `
        UPDATE tokens
        SET
          status = 'cancelled',
          completed_at =
            CURRENT_TIMESTAMP
        WHERE id = ?
        `,
        [token.id]
      );

      res.json({
        success: true,
        message:
          "Token cancelled"
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "Unable to cancel token"
      });
    }
  }
);

/* =====================================================
   STAFF LOGIN
===================================================== */

app.post(
  "/api/staff/login",
  async (req, res) => {
    try {
      const phone =
        normalizePhone(
          req.body.phone
        );

      const pin =
        String(
          req.body.pin || ""
        ).trim();

      if (!phone || !pin) {
        return res.status(400).json({
          error:
            "Phone and PIN are required"
        });
      }

      const staff =
        await get(
          `
          SELECT *
          FROM staff_users
          WHERE
            phone = ?
            AND active = 1
          `,
          [phone]
        );

      if (!staff) {
        return res.status(401).json({
          error:
            "Invalid staff credentials"
        });
      }

      const validPin =
        await bcrypt.compare(
          pin,
          staff.pin_hash
        );

      if (!validPin) {
        return res.status(401).json({
          error:
            "Invalid staff credentials"
        });
      }

      const token =
        createStaffToken(
          staff.id
        );

      res.json({
        success: true,

        token,

        staff: {
          id: staff.id,
          phone: staff.phone,
          name: staff.name
        }
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "Unable to login"
      });
    }
  }
);

/* =====================================================
   STAFF QUEUE
===================================================== */

app.get(
  "/api/staff/queue",
  authenticateStaff,
  async (req, res) => {
    try {
      const state =
        String(
          req.query.state || ""
        ).trim();

      const district =
        String(
          req.query.district || ""
        ).trim();

      const department =
        String(
          req.query.dept ||
            req.query.department ||
            ""
        ).trim();

      const service =
        String(
          req.query.service || ""
        ).trim();

      if (
        !state ||
        !district ||
        !department ||
        !service
      ) {
        return res.status(400).json({
          error:
            "state, district, dept and service are required"
        });
      }

      const queue =
        await getOrCreateQueue(
          state,
          district,
          department,
          service
        );

      const tokens =
        await all(
          `
          SELECT
            id,
            token_number,
            status,
            created_at,
            called_at,
            completed_at
          FROM tokens
          WHERE queue_id = ?
          ORDER BY token_number ASC
          `,
          [queue.id]
        );

      res.json({
        queue,
        tokens
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "Unable to load staff queue"
      });
    }
  }
);

/* =====================================================
   STAFF NEXT
===================================================== */

app.post(
  "/api/staff/next",
  authenticateStaff,
  async (req, res) => {
    try {
      const state =
        String(
          req.body.state || ""
        ).trim();

      const district =
        String(
          req.body.district || ""
        ).trim();

      const department =
        String(
          req.body.dept ||
            req.body.department ||
            ""
        ).trim();

      const service =
        String(
          req.body.service || ""
        ).trim();

      if (
        !state ||
        !district ||
        !department ||
        !service
      ) {
        return res.status(400).json({
          error:
            "state, district, dept and service are required"
        });
      }

      const queue =
        await getOrCreateQueue(
          state,
          district,
          department,
          service
        );

      const nextToken =
        await get(
          `
          SELECT *
          FROM tokens
          WHERE
            queue_id = ?
            AND status = 'waiting'
          ORDER BY token_number ASC
          LIMIT 1
          `,
          [queue.id]
        );

      if (!nextToken) {
        return res.json({
          success: false,
          message:
            "No waiting tokens"
        });
      }

      await run(
        `
        UPDATE tokens
        SET
          status = 'serving',
          called_at =
            CURRENT_TIMESTAMP
        WHERE id = ?
        `,
        [nextToken.id]
      );

      await run(
        `
        UPDATE queues
        SET
          current_number = ?
        WHERE id = ?
        `,
        [
          nextToken.token_number,
          queue.id
        ]
      );

      const updated =
        await get(
          `
          SELECT *
          FROM tokens
          WHERE id = ?
          `,
          [nextToken.id]
        );

      res.json({
        success: true,
        token: updated
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "Unable to call next token"
      });
    }
  }
);

/* =====================================================
   STAFF SKIP
===================================================== */

app.post(
  "/api/staff/skip",
  authenticateStaff,
  async (req, res) => {
    try {
      const state =
        String(
          req.body.state || ""
        ).trim();

      const district =
        String(
          req.body.district || ""
        ).trim();

      const department =
        String(
          req.body.dept ||
            req.body.department ||
            ""
        ).trim();

      const service =
        String(
          req.body.service || ""
        ).trim();

      if (
        !state ||
        !district ||
        !department ||
        !service
      ) {
        return res.status(400).json({
          error:
            "state, district, dept and service are required"
        });
      }

      const queue =
        await getOrCreateQueue(
          state,
          district,
          department,
          service
        );

      const current =
        await get(
          `
          SELECT *
          FROM tokens
          WHERE
            queue_id = ?
            AND status = 'serving'
          ORDER BY called_at DESC
          LIMIT 1
          `,
          [queue.id]
        );

      if (!current) {
        return res.json({
          success: false,
          message:
            "No serving token"
        });
      }

      await run(
        `
        UPDATE tokens
        SET
          status = 'skipped',
          completed_at =
            CURRENT_TIMESTAMP
        WHERE id = ?
        `,
        [current.id]
      );

      res.json({
        success: true,
        message:
          "Token skipped"
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "Unable to skip token"
      });
    }
  }
);

/* =====================================================
   CREATE STAFF FROM RENDER ENVIRONMENT
===================================================== */

async function createStaffFromEnvironment() {
  const phone =
    process.env.STAFF_PHONE;

  const name =
    process.env.STAFF_NAME;

  const pin =
    process.env.STAFF_PIN;

  if (!phone || !name || !pin) {
    console.log(
      "Staff environment variables not provided."
    );

    return;
  }

  const normalizedPhone =
    normalizePhone(phone);

  const existing =
    await get(
      `
      SELECT id
      FROM staff_users
      WHERE phone = ?
      `,
      [normalizedPhone]
    );

  if (existing) {
    console.log(
      "Staff account already exists."
    );

    return;
  }

  const pinHash =
    await bcrypt.hash(
      pin,
      12
    );

  await run(
    `
    INSERT INTO staff_users
    (
      phone,
      name,
      pin_hash,
      active
    )
    VALUES (?, ?, ?, 1)
    `,
    [
      normalizedPhone,
      name,
      pinHash
    ]
  );

  console.log(
    "Initial staff account created."
  );
}

/* =====================================================
   START SERVER
===================================================== */

async function startServer() {
  try {
    await initializeDatabase();

    await createStaffFromEnvironment();

    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `QueueLess backend running on port ${PORT}`
        );

        console.log(
          "Health endpoint: /api/health"
        );
      }
    );
  } catch (error) {
    console.error(
      "SERVER STARTUP ERROR:",
      error
    );

    process.exit(1);
  }
}

startServer();

/* =====================================================
   SHUTDOWN
===================================================== */

process.on(
  "SIGTERM",
  () => {
    db.close(() => {
      process.exit(0);
    });
  }
);

process.on(
  "SIGINT",
  () => {
    db.close(() => {
      process.exit(0);
    });
  }
);

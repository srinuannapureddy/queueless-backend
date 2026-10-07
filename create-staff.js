require("dotenv").config();
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const readline = require("readline");

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = q => new Promise(resolve => rl.question(q, resolve));

(async () => {
  try {
    const username = (await ask("Staff username: ")).trim();
    const password = await ask("Staff password: ");
    if (username.length < 3 || password.length < 8) {
      throw new Error("Username must be at least 3 characters and password at least 8 characters.");
    }

    const hash = await bcrypt.hash(password, 12);
    await pool.query(
      `INSERT INTO staff_users (username, password_hash)
       VALUES ($1, $2)
       ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash`,
      [username, hash]
    );
    console.log("Staff account created/updated.");
  } catch (err) {
    console.error(err.message);
    process.exitCode = 1;
  } finally {
    rl.close();
    await pool.end();
  }
})();

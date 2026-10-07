# QueueLess Real Backend

This backend replaces the frontend demo OTP (`1234`), demo staff PIN (`9999`), fake queue numbers, and browser-only token generation.

## Stack

- Node.js 20+
- Express
- PostgreSQL
- Twilio Verify v2 for real SMS OTP
- JWT
- bcrypt
- Helmet + CORS + rate limiting

Twilio Verify sends and checks the OTP. The backend does not generate/store a plaintext OTP.

## 1. Create PostgreSQL database

Create a database called `queueless`.

Example with PostgreSQL CLI:

```bash
createdb queueless
```

Or create it in pgAdmin.

## 2. Install

```bash
npm install
```

## 3. Configure

Copy `.env.example` to `.env` and fill:

```env
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@localhost:5432/queueless
JWT_SECRET=your-long-random-secret

TWILIO_ACCOUNT_SID=AC...
TWILIO_AUTH_TOKEN=...
TWILIO_VERIFY_SERVICE_SID=VA...

FRONTEND_URL=https://srinuannapureddy.github.io
```

## 4. Initialize database

```bash
npm run db:init
```

## 5. Create a real staff account

```bash
npm run staff:create
```

Do not use a hard-coded PIN in production.

## 6. Start

Development:

```bash
npm run dev
```

Production:

```bash
npm start
```

API:

```text
http://localhost:4000/api
```

## OTP flow

Send:

```http
POST /api/auth/send-code
Content-Type: application/json

{"mobile":"9876543210"}
```

Then verify:

```http
POST /api/auth/verify
Content-Type: application/json

{"mobile":"9876543210","code":"123456"}
```

The `123456` above is only an example. The actual code comes from Twilio SMS.

The response contains a JWT. Store that JWT in the browser and send it as:

```http
Authorization: Bearer YOUR_TOKEN
```

## Important

For a Twilio trial account, Twilio requires recipient phone numbers to be verified before trial SMS can be sent. For real public users, configure the Twilio account/compliance requirements and billing as required by Twilio.

Never put these values in your GitHub frontend:

- TWILIO_AUTH_TOKEN
- TWILIO_API_SECRET
- DATABASE_URL
- JWT_SECRET

Only the public API URL belongs in frontend JavaScript.

const express = require('express');
const cors = require('cors');
// const twilio = require('twilio'); // Uncomment after setting up Twilio

const app = express();
app.use(cors());
app.use(express.json());

// Replace these with your actual Twilio credentials
// const client = twilio('YOUR_TWILIO_ACCOUNT_SID', 'YOUR_TWILIO_AUTH_TOKEN');

// Temporary in-memory storage for OTPs (Use a real database like MongoDB for production)
const otpStorage = {};

// Route 1: Generate and Send OTP
app.post('/send-otp', async (req, res) => {
    const { phone } = req.body;

    if (!phone) {
        return res.status(400).json({ error: 'Phone number is required.' });
    }

    // Generate a 4-digit OTP
    const otpCode = Math.floor(1000 + Math.random() * 9000).toString();
    otpStorage[phone] = otpCode;

    try {
        /* TO SEND REAL SMS, UNCOMMENT THIS TWILIO BLOCK:
        await client.messages.create({
            body: `Your QueueLess login code is: ${otpCode}`,
            from: '+1234567890', // Your Twilio Phone Number
            to: phone
        });
        */
        
        console.log(`[DEBUG] OTP for ${phone} is ${otpCode}`);
        res.status(200).json({ success: true, message: 'OTP sent successfully.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to send SMS.' });
    }
});

// Route 2: Verify the OTP
app.post('/verify-otp', (req, res) => {
    const { phone, code } = req.body;

    if (otpStorage[phone] && otpStorage[phone] === code) {
        // Clear the OTP after successful use
        delete otpStorage[phone];
        res.status(200).json({ success: true, message: 'Login successful.' });
    } else {
        // Render 400 Bad Request for incorrect codes
        res.status(400).json({ error: 'Invalid or expired OTP.' });
    }
});

// Start the server (Render defaults to port 10000)
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log(`Backend server running on port ${PORT}`);
});

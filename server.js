const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// Temporary "Databases"
const otpStorage = {};
const ticketStorage = {}; // Stores users' active tickets

// 1. Send OTP (Demo version - hardcoded to 1234)
app.post('/send-otp', (req, res) => {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: 'Phone number required' });
    
    // For demo purposes, we will accept '1234' as the code
    otpStorage[phone] = '1234'; 
    console.log(`[DEBUG] OTP for ${phone} is 1234`);
    res.status(200).json({ success: true, message: 'OTP sent' });
});

// 2. Verify OTP
app.post('/verify-otp', (req, res) => {
    const { phone, code } = req.body;
    if (otpStorage[phone] && otpStorage[phone] === code) {
        delete otpStorage[phone];
        res.status(200).json({ success: true });
    } else {
        res.status(400).json({ error: 'Invalid OTP' });
    }
});

// 3. Save Ticket to Database
app.post('/save-token', (req, res) => {
    const { phone, tokenData } = req.body;
    if (!phone) return res.status(400).json({ error: 'Phone required' });
    
    ticketStorage[phone] = tokenData; // Save ticket
    res.status(200).json({ success: true });
});

// 4. Retrieve Ticket from Database
app.post('/get-token', (req, res) => {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: 'Phone required' });
    
    // Send ticket back to the browser if it exists
    res.status(200).json({ success: true, tokenData: ticketStorage[phone] || null });
});

// 5. Delete Ticket from Database
app.post('/cancel-token', (req, res) => {
    const { phone } = req.body;
    if (phone) delete ticketStorage[phone];
    res.status(200).json({ success: true });
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log(`Backend server running on port ${PORT}`);
});

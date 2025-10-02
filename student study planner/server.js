const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Serve static files (your HTML, CSS, JS)
app.use(express.static(path.join(__dirname)));

// Mock "database" for users
const users = {};
const SECRET = 'yourSuperSecretKey123!';

// --- Signup endpoint ---
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password)
        return res.status(400).json({ error: 'Missing username or password' });
    if (users[username])
        return res.status(409).json({ error: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    users[username] = hashedPassword;
    res.json({ success: true });
});

// --- Login endpoint ---
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = users[username];
    if (!hashedPassword || !(await bcrypt.compare(password, hashedPassword))) {
        return res.status(401).json({ error: 'Invalid username or password' });
    }

    const token = jwt.sign({ username }, SECRET, { expiresIn: '1h' });
    res.json({ token });
});

// --- Protected dashboard route ---
app.get('/dashboard', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader)
        return res.status(401).json({ error: 'Missing authorization header' });

    const token = authHeader.split(' ')[1];
    try {
        const payload = jwt.verify(token, SECRET);
        res.json({ welcome: `Welcome, ${payload.username}!` });
    } catch {
        res.status(401).json({ error: 'Invalid or expired token' });
    }
});

// --- Catch-all to serve HTML ---
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

// --- Start server ---
const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));

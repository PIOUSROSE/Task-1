require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

app.use(session({
    secret: 'secure_auth_encryption_key_999',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 2 * 60 * 60 * 1000 } // Session expires in 2 hours
}));

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB Secure Auth Database connected successfully!'))
    .catch(err => console.error('Database configuration error:', err));

// Modified Schema blueprint parameters incorporating the role attribute fields
const userProfileSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'User' } 
});

const SecureUser = mongoose.model('SecureUser', userProfileSchema);

app.get('/', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login.html');
    }
    res.redirect('/dashboard.html');
});

app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password, role } = req.body;

        const emailCheck = await SecureUser.findOne({ email });
        if (emailCheck) {
            return res.status(400).json({ error: 'This email is already registered' });
        }

        const secureHashedPassword = await bcrypt.hash(password, 10);

        const newAccount = new SecureUser({
            username,
            email,
            password: secureHashedPassword,
            role: role || 'User' // Mapping role profiles parameter logs inside schema properties
        });

        await newAccount.save();

        req.session.userId = newAccount._id;
        req.session.username = newAccount.username;
        req.session.role = newAccount.role;

        res.status(201).json({ message: 'User verification records created successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Internal system error logs detected' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const clientProfile = await SecureUser.findOne({ email });
        if (!clientProfile) {
            return res.status(400).json({ error: 'Invalid identification credentials' });
        }

        const identityMatch = await bcrypt.compare(password, clientProfile.password);
        if (!identityMatch) {
            return res.status(400).json({ error: 'Invalid identification credentials' });
        }

        req.session.userId = clientProfile._id;
        req.session.username = clientProfile.username;
        req.session.role = clientProfile.role; // Save role flag on token data structures maps

        res.json({ message: 'Identity authenticated safely' });
    } catch (err) {
        res.status(500).json({ error: 'Internal system error logs detected' });
    }
});

// Upgraded secure route engine to pipeline data mapping structures seamlessly
app.get('/api/auth/profile', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Access denied: Unauthorized identity logs' });
    }
    res.json({ username: req.session.username, role: req.session.role });
});

app.post('/api/auth/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) return res.status(500).json({ error: 'Failed to purge session tokens' });
        res.json({ message: 'Session terminated successfully' });
    });
});

const RUNTIME_PORT = process.env.PORT || 5000;
app.listen(RUNTIME_PORT, () => {
    console.log(`Secure Authentication Engine actively processing on port ${RUNTIME_PORT}`);
});